import tempfile
import unittest
from pathlib import Path

from decision_audit.chain import ChainIntegrityError
from decision_audit.config import Config
from decision_audit.orchestrator import RECORD_SCHEMA, AuditOrchestrator

CLEAN_CONTEXT = {
    "loan_amount": 150000,
    "property_value": 200000,
    "monthly_debt": 1000,
    "monthly_income": 6000,
    "marginal_var": 0.5,
    "var_limit": 1.0,
    "segment": "prime",
    "period": "T1",
}


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _config(self):
        return Config(state_dir=self._tmp.name)

    def test_clean_decision_passes_and_is_logged_redacted(self):
        orch = AuditOrchestrator(self._config())
        context = dict(CLEAN_CONTEXT, customer_id="C42", loan_amount=154999)
        result = orch.audit_decision({"decision": "APPROVE", "score": 0.4}, context)

        self.assertTrue(result["constraints"]["passed"])
        self.assertEqual(result["final_outcome"], "APPROVE")

        stored = orch.chain.chain[-1].data
        self.assertEqual(stored["context"]["loan_amount"], 150000)
        self.assertNotIn("customer_id", stored["context"])
        self.assertIn("customer_id", stored["redacted_fields"])

    def test_decision_payload_is_allowlisted_before_it_reaches_the_log(self):
        orch = AuditOrchestrator(self._config())
        orch.audit_decision(
            {"decision": "APPROVE", "score": 0.4, "reasons": ["LTV <= 70%"],
             "customer_ssn": "123-45-6789", "internal_ref": "X9"},
            dict(CLEAN_CONTEXT))

        stored = orch.chain.chain[-1].data
        self.assertEqual(stored["decision"],
                         {"decision": "APPROVE", "score": 0.4, "reasons": ["LTV <= 70%"]})
        self.assertEqual(stored["redacted_decision_fields"], ["customer_ssn", "internal_ref"])
        raw = Path(orch.config.resolved_chain_path()).read_text()
        self.assertNotIn("123-45-6789", raw)

    def test_unprocessable_input_is_logged_as_degraded_not_dropped(self):
        orch = AuditOrchestrator(self._config())
        result = orch.audit_decision(
            {"decision": "APPROVE"}, dict(CLEAN_CONTEXT, features=["a", "b"]))

        self.assertEqual(result["status"], "degraded")
        self.assertEqual(len(orch.chain.chain), 1)
        stored = orch.chain.chain[-1].data
        self.assertEqual(stored["status"], "degraded")
        self.assertTrue(any("features must be" in e for e in stored["input_errors"]))
        self.assertEqual(orch.verify_integrity()["degraded_records"], 1)

    def test_drift_state_rolls_back_when_the_append_fails(self):
        orch = AuditOrchestrator(self._config())
        for i in range(3):
            orch.audit_decision({"decision": "APPROVE"},
                                dict(CLEAN_CONTEXT, features=[1.0 + i, 2.0]))
        before = orch.drift_detector.snapshot()

        orch.chain._append_allowed = False
        with self.assertRaises(ChainIntegrityError):
            orch.audit_decision({"decision": "APPROVE"},
                                dict(CLEAN_CONTEXT, features=[99.0, 99.0]))

        self.assertEqual(orch.drift_detector.snapshot(), before)

    def test_an_unreadable_chain_reports_no_root_hash(self):
        config = self._config()
        orch = AuditOrchestrator(config)
        orch.audit_decision({"decision": "APPROVE"}, dict(CLEAN_CONTEXT))
        Path(config.resolved_chain_path()).write_text("not a chain\n")

        report = AuditOrchestrator(config).verify_integrity()
        self.assertFalse(report["valid"])
        self.assertIsNone(report["root_hash"])

    def test_an_explicit_null_score_falls_back_to_confidence(self):
        orch = AuditOrchestrator(self._config())
        orch.audit_decision({"decision": "APPROVE", "score": None, "confidence": 0.4},
                            dict(CLEAN_CONTEXT))
        self.assertEqual(orch.chain.chain[-1].data["model_score"], 0.4)

    def test_records_carry_a_schema_version(self):
        orch = AuditOrchestrator(self._config())
        orch.audit_decision({"decision": "APPROVE"}, dict(CLEAN_CONTEXT))
        self.assertEqual(orch.chain.chain[-1].data["schema"], RECORD_SCHEMA)

    def test_policy_blocks_model_approval(self):
        orch = AuditOrchestrator(self._config())
        context = dict(CLEAN_CONTEXT, marginal_var=1.5)
        result = orch.audit_decision({"decision": "APPROVE", "score": 0.5}, context)
        self.assertFalse(result["constraints"]["passed"])
        self.assertEqual(result["final_outcome"], "BLOCKED_BY_POLICY")

    def test_model_rejection_is_not_relabelled(self):
        orch = AuditOrchestrator(self._config())
        context = dict(CLEAN_CONTEXT, marginal_var=1.5)
        result = orch.audit_decision({"decision": "REJECT", "score": 1.1}, context)
        self.assertEqual(result["final_outcome"], "REJECT")

    def test_audit_ids_unique_across_sessions(self):
        config = self._config()
        first = AuditOrchestrator(config)
        ids = [first.audit_decision({"decision": "APPROVE"}, dict(CLEAN_CONTEXT))["audit_id"]
               for _ in range(2)]
        second = AuditOrchestrator(config)
        ids.append(second.audit_decision({"decision": "APPROVE"}, dict(CLEAN_CONTEXT))["audit_id"])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(second.get_portfolio_summary()["audits"], 3)

    def test_verify_integrity_reports_chain_derived_counts(self):
        config = self._config()
        orch = AuditOrchestrator(config)
        orch.audit_decision({"decision": "APPROVE"}, dict(CLEAN_CONTEXT))

        fresh = AuditOrchestrator(config)
        report = fresh.verify_integrity()
        self.assertTrue(report["valid"])
        self.assertEqual(report["blocks"], 1)

    def test_summary_aggregates(self):
        orch = AuditOrchestrator(self._config())
        orch.audit_decision({"decision": "APPROVE", "score": 0.4}, dict(CLEAN_CONTEXT))
        orch.audit_decision({"decision": "APPROVE", "score": 0.5},
                            dict(CLEAN_CONTEXT, marginal_var=1.5, segment="near_prime"))
        summary = orch.get_portfolio_summary()
        self.assertEqual(summary["audits"], 2)
        self.assertEqual(summary["with_violations"], 1)
        self.assertEqual(summary["violations_by_id"], {"var_limit": 1})
        self.assertEqual(summary["policy_overrides"], {"model_approve_blocked": 1})
        self.assertEqual(summary["final_outcomes"],
                         {"APPROVE": 1, "BLOCKED_BY_POLICY": 1})
        self.assertEqual(set(summary["fairness"]["groups"]), {"prime", "near_prime"})

    def test_injectable_clock_makes_runs_reproducible(self):
        def run(state_dir):
            config = Config(state_dir=state_dir, clock=lambda: 1_000_000.0)
            orch = AuditOrchestrator(config)
            return [orch.audit_decision({"decision": "APPROVE", "score": 0.4},
                                        dict(CLEAN_CONTEXT))["block_hash"]
                    for _ in range(3)]

        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            self.assertEqual(run(a), run(b))


if __name__ == "__main__":
    unittest.main()
