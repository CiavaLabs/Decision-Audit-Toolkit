from collections.abc import Iterable
from typing import Any

from .fairness import DEFAULT_MIN_GROUP_SIZE, FairnessAccumulator

MAX_ANOMALY_ROWS = 1000


class PortfolioAccumulator:
    def __init__(self, *, min_group_size: int = DEFAULT_MIN_GROUP_SIZE,
                 max_anomaly_rows: int = MAX_ANOMALY_ROWS):
        self.min_group_size = min_group_size
        self.max_anomaly_rows = max_anomaly_rows
        self.reset()

    def reset(self) -> None:
        self._fairness = FairnessAccumulator(min_group_size=self.min_group_size)
        self.audits = 0
        self.with_violations = 0
        self.with_anomaly = 0
        self.degraded = 0
        self._decisions: dict[str, int] = {}
        self._model_decisions: dict[str, int] = {}
        self._final_outcomes: dict[str, int] = {}
        self._policy_overrides: dict[str, int] = {}
        self._violations_by_id: dict[str, int] = {}
        self._audits_by_period: dict[str, int] = {}
        self._anomaly_audits: list[dict[str, Any]] = []

    @staticmethod
    def _bump(counter: dict[str, int], key: Any) -> None:
        label = key if isinstance(key, str) else str(key)
        counter[label] = counter.get(label, 0) + 1

    def add(self, data: Any) -> None:
        if not isinstance(data, dict):
            data = {}
        self.audits += 1

        period = data.get("period")
        if period:
            self._bump(self._audits_by_period, period)
        if data.get("violations", 0):
            self.with_violations += 1
            recorded = data.get("violation_ids")
            for v_id in (recorded if isinstance(recorded, list) and recorded
                         else ["_unspecified"]):
                self._bump(self._violations_by_id, v_id)
        if data.get("status") == "degraded":
            self.degraded += 1
        if data.get("anomaly"):
            self.with_anomaly += 1
            if len(self._anomaly_audits) < self.max_anomaly_rows:
                self._anomaly_audits.append({
                    "audit_id": data.get("audit_id"),
                    "period": period,
                    "drift_score": data.get("drift_score"),
                })

        recorded_decision = data.get("decision")
        decision_label = (recorded_decision.get("decision", "UNKNOWN")
                          if isinstance(recorded_decision, dict) else "UNKNOWN")
        self._bump(self._decisions, decision_label)
        model_label = data.get("model_decision", decision_label)
        self._bump(self._model_decisions, model_label)
        self._bump(self._final_outcomes, data.get("final_outcome", model_label))
        if data.get("policy_blocked") and model_label == "APPROVE":
            self._bump(self._policy_overrides, "model_approve_blocked")

        self._fairness.add(data)

    def extend(self, records: Iterable[Any]) -> "PortfolioAccumulator":
        for data in records:
            self.add(data)
        return self

    def result(self) -> dict[str, Any]:
        violation_rate = self.with_violations / self.audits if self.audits else 0.0
        summary: dict[str, Any] = {
            "audits": self.audits,
            "with_violations": self.with_violations,
            "violation_rate": round(violation_rate, 4),
            "with_anomaly": self.with_anomaly,
            "degraded": self.degraded,
            "decisions_by_outcome": dict(self._decisions),
            "model_decisions": dict(self._model_decisions),
            "final_outcomes": dict(self._final_outcomes),
            "policy_overrides": dict(self._policy_overrides),
            "violations_by_id": dict(self._violations_by_id),
            "audits_by_period": dict(self._audits_by_period),
            "anomaly_audits": list(self._anomaly_audits),
            "fairness": self._fairness.result(),
            "chain_length": self.audits,
        }
        if self.with_anomaly > len(self._anomaly_audits):
            summary["anomaly_audits_truncated"] = (
                self.with_anomaly - len(self._anomaly_audits))
        return summary
