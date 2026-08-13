import json
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

WRITER = textwrap.dedent("""
    import sys, time
    from decision_audit.config import Config
    from decision_audit.orchestrator import AuditOrchestrator

    state_dir, start_at, count = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
    orch = AuditOrchestrator(Config(state_dir=state_dir, signature_scheme="hmac"))
    while time.time() < start_at:   # both processes load, then write together
        time.sleep(0.005)
    context = {"loan_amount": 100000, "property_value": 200000,
               "monthly_income": 6000, "monthly_debt": 1000,
               "marginal_var": 0.5, "var_limit": 1.0}
    for _ in range(count):
        print(orch.audit_decision({"decision": "APPROVE"}, context)["audit_id"])
""")


class ConcurrentAppendTests(unittest.TestCase):
    def test_two_processes_produce_one_valid_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            per_writer = 4

            start_at = time.time() + 1.5
            procs = [
                subprocess.Popen(
                    [sys.executable, "-c", WRITER,
                     str(state), str(start_at), str(per_writer)],
                    cwd=REPO_ROOT, stdout=subprocess.PIPE, text=True)
                for _ in range(2)
            ]
            reported = []
            for proc in procs:
                out, _ = proc.communicate(timeout=120)
                self.assertEqual(proc.returncode, 0)
                reported.extend(out.split())

            lines = [json.loads(line)
                     for line in (state / "chain.jsonl").read_text().splitlines()
                     if line.strip()]
            blocks = lines[1:]
            self.assertEqual(len(blocks), 2 * per_writer)
            self.assertEqual([b["index"] for b in blocks], list(range(2 * per_writer)))

            stored_ids = [b["data"]["audit_id"] for b in blocks]
            self.assertEqual(len(set(stored_ids)), len(stored_ids))
            self.assertEqual(sorted(reported), sorted(stored_ids))

            verify = subprocess.run(
                [sys.executable, "-m", "decision_audit", "--state-dir", str(state),
                 "--scheme", "hmac", "verify"],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(verify.returncode, 0, verify.stdout)


if __name__ == "__main__":
    unittest.main()
