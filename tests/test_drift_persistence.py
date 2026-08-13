import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from decision_audit.chain import ChainIntegrityError
from decision_audit.config import Config
from decision_audit.driftstore import load_drift_state, save_drift_state
from decision_audit.orchestrator import AuditOrchestrator

REPO_ROOT = Path(__file__).resolve().parent.parent

BASE = {
    "loan_amount": 150000, "property_value": 900000, "monthly_debt": 1000,
    "monthly_income": 6000, "marginal_var": 0.5, "var_limit": 1.0,
    "segment": "prime",
}


def shifting_context(i: int) -> dict:
    amount = 100000 + i * 8000
    return dict(BASE, loan_amount=amount,
                features=[float(amount), 900000.0, 1000.0, 6000.0, 0.5])


class DriftPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = str(Path(self._tmp.name) / "state")

    def _config(self, **kwargs):
        return Config(state_dir=self.state, signature_scheme="hmac",
                      drift_window_size=20, drift_min_test_samples=5, **kwargs)

    def test_drift_is_detected_across_fresh_orchestrators(self):
        for i in range(60):
            orch = AuditOrchestrator(self._config())
            orch.audit_decision({"decision": "APPROVE"}, shifting_context(i))

        report = AuditOrchestrator(self._config()).verify_integrity()
        self.assertGreater(report["anomalies"], 0,
                           "a hard population shift went unnoticed")

    def test_windows_survive_a_real_process_boundary(self):
        writer = textwrap.dedent("""
            import sys
            from decision_audit.config import Config
            from decision_audit.orchestrator import AuditOrchestrator
            sys.path.insert(0, ".")
            from tests.test_drift_persistence import shifting_context

            state, start, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
            orch = AuditOrchestrator(Config(state_dir=state, signature_scheme="hmac",
                                            drift_window_size=20,
                                            drift_min_test_samples=5))
            for i in range(start, start + count):
                orch.audit_decision({"decision": "APPROVE"}, shifting_context(i))
        """)
        for start in (0, 20, 40):
            proc = subprocess.run([sys.executable, "-c", writer, self.state,
                                   str(start), "20"],
                                  cwd=REPO_ROOT, capture_output=True, text=True,
                                  timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)

        report = AuditOrchestrator(self._config()).verify_integrity()
        self.assertEqual(report["blocks"], 60)
        self.assertGreater(report["anomalies"], 0)

    def test_state_is_ignored_when_the_window_settings_changed(self):
        for i in range(30):
            AuditOrchestrator(self._config()).audit_decision(
                {"decision": "APPROVE"}, shifting_context(i))

        resized = AuditOrchestrator(Config(
            state_dir=self.state, signature_scheme="hmac",
            drift_window_size=50, drift_min_test_samples=5))
        result = resized.audit_decision({"decision": "APPROVE"}, shifting_context(30))
        self.assertEqual(result["status"], "degraded")
        self.assertTrue(any("window_size" in e for e in result["input_errors"]),
                        result["input_errors"])
        self.assertEqual(len(resized.drift_detector.reference_window), 1)

    def test_a_refused_append_does_not_advance_the_stored_windows(self):
        orch = AuditOrchestrator(self._config())
        for i in range(5):
            orch.audit_decision({"decision": "APPROVE"}, shifting_context(i))
        before = load_drift_state(Path(self.state) / "drift_state.json")

        orch.chain._append_allowed = False
        with self.assertRaises(ChainIntegrityError):
            orch.audit_decision({"decision": "APPROVE"}, shifting_context(99))

        after = load_drift_state(Path(self.state) / "drift_state.json")
        self.assertEqual(before, after)

    def test_decisions_without_features_leave_the_state_alone(self):
        orch = AuditOrchestrator(self._config())
        for i in range(5):
            orch.audit_decision({"decision": "APPROVE"}, shifting_context(i))
        before = load_drift_state(Path(self.state) / "drift_state.json")

        orch.audit_decision({"decision": "APPROVE"}, dict(BASE))
        after = load_drift_state(Path(self.state) / "drift_state.json")
        self.assertEqual(before, after)

    def test_reset_removes_the_stored_windows(self):
        AuditOrchestrator(self._config()).audit_decision(
            {"decision": "APPROVE"}, shifting_context(0))
        state_file = Path(self.state) / "drift_state.json"
        self.assertTrue(state_file.exists())

        proc = subprocess.run(
            [sys.executable, "-m", "decision_audit", "--state-dir", self.state, "reset"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(state_file.exists())

    def test_persistence_can_be_turned_off(self):
        orch = AuditOrchestrator(self._config(persist_drift_state=False))
        orch.audit_decision({"decision": "APPROVE"}, shifting_context(0))
        self.assertFalse((Path(self.state) / "drift_state.json").exists())


class DriftStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "drift_state.json"

    def test_round_trip(self):
        state = {"reference": [[1.0, 2.0]], "test": [], "n_features": 2,
                 "window_size": 10, "min_test_samples": 5}
        save_drift_state(self.path, state)
        loaded = load_drift_state(self.path)
        self.assertEqual({k: loaded[k] for k in state}, state)

    def test_missing_file_reads_as_no_state(self):
        self.assertIsNone(load_drift_state(self.path))

    def test_corrupt_file_reads_as_no_state_rather_than_raising(self):
        self.path.write_text("{ not json")
        self.assertIsNone(load_drift_state(self.path))

    def test_state_from_a_future_schema_is_not_guessed_at(self):
        self.path.write_text(json.dumps({"schema": 99, "reference": []}))
        self.assertIsNone(load_drift_state(self.path))

    def test_write_leaves_no_partial_file_behind(self):
        save_drift_state(self.path, {"reference": [], "test": [], "n_features": None,
                                     "window_size": 10, "min_test_samples": 5})
        self.assertFalse(self.path.with_name(self.path.name + ".tmp").exists())


if __name__ == "__main__":
    unittest.main()
