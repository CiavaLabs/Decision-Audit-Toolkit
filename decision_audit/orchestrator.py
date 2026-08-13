from typing import Any

from . import ed25519
from ._version import __version__
from .aggregate import AggregatePolicy, aggregate_policy_for
from .chain import HashChain, detect_chain_scheme
from .config import Config
from .constraints import ConstraintChecker, get_policy_profile, load_constraints_from_json
from .crypto import make_signer
from .drift import MeanShiftDriftDetector
from .driftstore import load_drift_state, save_drift_state
from .portfolio import PortfolioAccumulator
from .privacy import ContextRedactor

RECORD_SCHEMA = 1


class AuditOrchestrator:
    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        chain_path = self.config.resolved_chain_path()
        scheme = detect_chain_scheme(chain_path) or self.config.signature_scheme
        self.signer = make_signer(
            scheme,
            key_path=self.config.resolved_key_path(scheme),
            public_key_path=self.config.resolved_public_key_path(scheme))
        self.chain = HashChain(self.signer, storage_path=chain_path,
                               clock=self.config.clock)
        self.constraints = self._init_constraints()
        self.redactor = ContextRedactor(self.config.banded_fields, self.config.clear_fields)
        self.drift_detector = MeanShiftDriftDetector(self.config)
        self._drift_state_path = (self.config.resolved_drift_state_path()
                                  if self.config.persist_drift_state else None)

    def audit_decision(self, decision: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(decision, dict):
            raise ValueError("decision must be an object")
        if not isinstance(context, dict):
            raise ValueError("context must be an object")

        violations = self.constraints.check(context)
        input_errors: list[str] = []

        model_decision = decision.get("decision", "UNKNOWN")
        model_score = decision.get("score")
        if model_score is None:
            model_score = decision.get("confidence")
        policy_blocked = len(violations) > 0
        final_outcome = model_decision
        if policy_blocked and model_decision == "APPROVE":
            final_outcome = "BLOCKED_BY_POLICY"

        redacted_context, dropped_fields, redaction_errors = self.redactor.redact(context)
        input_errors.extend(redaction_errors)
        redacted_decision, dropped_decision = self.redactor.select(
            decision, self.config.decision_fields)

        base: dict[str, Any] = {
            "schema": RECORD_SCHEMA,
            "model_decision": model_decision,
            "model_score": model_score,
            "decision": redacted_decision,
            "violations": len(violations),
            "violation_ids": [v["id"] for v in violations],
            "final_outcome": final_outcome,
            "policy_blocked": policy_blocked,
            "context": redacted_context
        }
        period = context.get("period")
        segment = context.get("segment")
        if period is not None and period != "":
            base["period"] = period
        if segment is not None and segment != "":
            base["segment"] = segment
        if dropped_fields:
            base["redacted_fields"] = dropped_fields
        if dropped_decision:
            base["redacted_decision_fields"] = dropped_decision

        outcome: dict[str, Any] = {}

        def build(index: int) -> dict[str, Any]:
            errors = list(input_errors)
            drift_result = None
            if "features" in context:
                reload_error = self._reload_drift_state()
                if reload_error:
                    errors.append(reload_error)
                outcome["drift_before"] = self.drift_detector.snapshot()
                try:
                    drift_result = self.drift_detector.update(context["features"])
                except ValueError as exc:
                    errors.append(f"drift not evaluated: {exc}")

            outcome["drift"] = drift_result
            outcome["audit_id"] = f"audit_{index:06d}"
            outcome["input_errors"] = errors

            record = dict(base)
            record["audit_id"] = outcome["audit_id"]
            record["anomaly"] = drift_result.get("drift", False) if drift_result else False
            record["status"] = "degraded" if errors else "ok"
            if errors:
                record["input_errors"] = errors
            if drift_result and "threshold" in drift_result:
                record["drift_score"] = drift_result["score"]
            return record

        def on_commit() -> None:
            if "drift_before" in outcome:
                self._save_drift_state()

        try:
            block_hash = self.chain.add_record(build, on_commit=on_commit)
        except Exception:
            if "drift_before" in outcome:
                self.drift_detector.restore(outcome["drift_before"])
            raise

        return {
            "audit_id": outcome["audit_id"],
            "block_hash": block_hash,
            "decision": decision,
            "final_outcome": final_outcome,
            "status": "degraded" if outcome["input_errors"] else "ok",
            "input_errors": outcome["input_errors"],
            "constraints": {"passed": len(violations) == 0, "violations": violations},
            "drift": outcome["drift"]
        }

    def _reload_drift_state(self) -> str | None:
        if not self._drift_state_path:
            return None
        stored = load_drift_state(self._drift_state_path)
        if stored is None:
            return None
        return self.drift_detector.load_state(stored)

    def _save_drift_state(self) -> None:
        if not self._drift_state_path:
            return
        save_drift_state(self._drift_state_path, self.drift_detector.snapshot())

    def verify_integrity(self, *, full: bool = False) -> dict[str, Any]:
        chain_valid, chain_errors = self.chain.verify_integrity(full=full)
        report = {
            "valid": chain_valid,
            "errors": chain_errors,
            "warnings": self.chain.warnings,
            "signature_check": "every-block" if full else "head-only",
            "blocks": len(self.chain.chain),
            "anomalies": sum(1 for node in self.chain.chain if node.data.get("anomaly")),
            "degraded_records": sum(1 for node in self.chain.chain
                                    if node.data.get("status") == "degraded"),
            "root_hash": None if self.chain.unreadable else self.chain.tree_head()[1],
            "version": __version__,
            "scheme": self.signer.scheme,
            "policy": self.config.policy_config_path or self.config.policy_profile
        }
        if self.signer.scheme == "ed25519":
            report["ed25519_backend"] = ed25519.active_backend()
        if self.chain.clock_regressions:
            report["clock_regressions"] = self.chain.clock_regressions
        return report

    def _init_constraints(self) -> ConstraintChecker:
        if self.config.policy_config_path:
            return load_constraints_from_json(self.config.policy_config_path)
        return get_policy_profile(self.config.policy_profile)

    def get_portfolio_summary(self) -> dict[str, Any]:
        accumulator = PortfolioAccumulator(
            min_group_size=self.config.fairness_min_group_size)
        return accumulator.extend(node.data for node in self.chain.chain).result()

    def check_aggregate_policy(self, summary: dict[str, Any] | None = None, *,
                               chain_valid: bool | None = None) -> dict[str, Any]:
        policy = self._init_aggregate_policy()
        result = policy.evaluate(summary if summary is not None
                                 else self.get_portfolio_summary())
        if chain_valid is None:
            chain_valid, chain_errors = self.chain.verify_integrity()
        else:
            chain_errors = [] if chain_valid else self.chain.verify_integrity()[1]
        result["chain_valid"] = chain_valid
        if not chain_valid:
            result["passed"] = False
            result["chain_errors"] = chain_errors
        return result

    def _init_aggregate_policy(self) -> AggregatePolicy:
        return aggregate_policy_for(self.config.aggregate_profile,
                                    self.config.aggregate_config_path)
