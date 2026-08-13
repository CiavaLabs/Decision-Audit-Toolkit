import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args, state_dir):
    return subprocess.run(
        [sys.executable, "-m", "decision_audit", "--state-dir", str(state_dir), *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "state"

    def test_happy_path_demo_verify_summary_report(self):
        demo = run_cli("demo", state_dir=self.state)
        self.assertEqual(demo.returncode, 0, demo.stderr)
        self.assertIn("BLOCKED_BY_POLICY", demo.stdout)
        self.assertIn("Drift detected", demo.stdout)

        verify = run_cli("verify", "--json", state_dir=self.state)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertTrue(json.loads(verify.stdout)["valid"])

        summary = run_cli("summary", state_dir=self.state)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertGreater(json.loads(summary.stdout)["audits"], 0)

        out_file = Path(self._tmp.name) / "report.html"
        report = run_cli("report", "--out", str(out_file), state_dir=self.state)
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertIn("Decision Audit Report", out_file.read_text())

    def test_tampered_chain_fails_verify_and_blocks_appends(self):
        self.assertEqual(run_cli("batch", state_dir=self.state).returncode, 0)

        chain_file = self.state / "chain.jsonl"
        lines = chain_file.read_text().splitlines()
        block = json.loads(lines[1])
        block["data"]["model_decision"] = "TAMPERED"
        lines[1] = json.dumps(block)
        chain_file.write_text("\n".join(lines) + "\n")

        verify = run_cli("verify", state_dir=self.state)
        self.assertEqual(verify.returncode, 1)
        self.assertIn("INVALID", verify.stdout)

        demo = run_cli("demo", state_dir=self.state)
        self.assertEqual(demo.returncode, 1)
        self.assertIn("refusing to append", demo.stderr)

        reset = run_cli("reset", state_dir=self.state)
        self.assertEqual(reset.returncode, 0)
        self.assertEqual(run_cli("verify", state_dir=self.state).returncode, 0)

    def _tamper(self):
        chain_file = self.state / "chain.jsonl"
        lines = chain_file.read_text().splitlines()
        block = json.loads(lines[1])
        block["data"]["model_decision"] = "TAMPERED"
        lines[1] = json.dumps(block)
        chain_file.write_text("\n".join(lines) + "\n")

    def _seed_one_segment(self, count=3):
        payload = [{"decision": {"decision": "APPROVE", "score": 0.4},
                    "context": {"loan_amount": 100000, "property_value": 200000,
                                "monthly_debt": 1000, "monthly_income": 6000,
                                "marginal_var": 0.5, "var_limit": 1.0,
                                "segment": "only", "period": "T1"}}
                   for _ in range(count)]
        source = Path(self._tmp.name) / "decisions.json"
        source.write_text(json.dumps(payload))
        result = run_cli("audit", "--input", str(source), state_dir=self.state)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_read_command_reports_cleanly_on_a_tampered_chain(self):
        self.assertEqual(run_cli("batch", state_dir=self.state).returncode, 0)
        self._tamper()

        check = run_cli("check", state_dir=self.state)
        self.assertEqual(check.returncode, 1, check.stdout)
        self.assertIn("does not verify", check.stdout)

        summary = run_cli("summary", state_dir=self.state)
        self.assertEqual(summary.returncode, 1)
        self.assertFalse(json.loads(summary.stdout)["integrity"]["valid"])

        proof_file = Path(self._tmp.name) / "p.json"
        prove = run_cli("prove", "--index", "1", "--out", str(proof_file),
                        state_dir=self.state)
        self.assertEqual(prove.returncode, 1)
        self.assertIn("Refusing to build a proof", prove.stderr)
        self.assertFalse(proof_file.exists())

        checkpoint = run_cli("checkpoint", state_dir=self.state)
        self.assertEqual(checkpoint.returncode, 1)
        self.assertIn("Refusing to checkpoint", checkpoint.stderr)

    def test_a_misconfigured_threshold_is_refused_rather_than_skipped(self):
        self.assertEqual(run_cli("batch", state_dir=self.state).returncode, 0)
        policy = Path(self._tmp.name) / "rules.json"
        policy.write_text(json.dumps({"aggregate_rules": [
            {"id": "four_fifths", "type": "min_approval_ratio", "minimum": 0.8}]}))

        check = run_cli("--aggregate-config", str(policy), "check", state_dir=self.state)
        self.assertEqual(check.returncode, 2, check.stdout)
        self.assertIn("needs a 'min' threshold", check.stderr)

    def test_strict_check_refuses_to_pass_on_a_partial_answer(self):
        self._seed_one_segment()
        lenient = run_cli("check", "--json", state_dir=self.state)
        self.assertEqual(lenient.returncode, 0, lenient.stdout)
        result = json.loads(lenient.stdout)
        self.assertTrue(result["passed"])
        self.assertFalse(result["complete"])
        self.assertTrue(result["not_evaluated"])

        strict = run_cli("check", "--strict", state_dir=self.state)
        self.assertEqual(strict.returncode, 4, strict.stdout)

    def test_summary_and_check_stream_match_the_loaded_path(self):
        self.assertEqual(run_cli("batch", state_dir=self.state).returncode, 0)
        for command in (("summary",), ("check", "--json")):
            with self.subTest(command=command):
                loaded = run_cli(*command, state_dir=self.state)
                streamed = run_cli(*command, "--stream", state_dir=self.state)
                self.assertEqual(loaded.returncode, streamed.returncode)
                self.assertEqual(json.loads(loaded.stdout), json.loads(streamed.stdout))

    def test_stream_and_loaded_agree_on_a_chain_that_breaks_partway(self):
        self.assertEqual(run_cli("batch", state_dir=self.state).returncode, 0)
        chain_file = self.state / "chain.jsonl"
        lines = chain_file.read_text().splitlines()
        lines[40] = "{ not a record }"
        chain_file.write_text("\n".join(lines) + "\n")

        for command in (("summary",), ("check", "--json")):
            with self.subTest(command=command):
                loaded = run_cli(*command, state_dir=self.state)
                streamed = run_cli(*command, "--stream", state_dir=self.state)
                self.assertEqual(loaded.returncode, streamed.returncode)
                self.assertEqual(loaded.stdout, streamed.stdout)

    def test_verify_json_is_byte_for_byte_the_same_either_way(self):
        self.assertEqual(run_cli("batch", state_dir=self.state).returncode, 0)
        loaded = run_cli("verify", "--json", state_dir=self.state).stdout
        streamed = run_cli("verify", "--json", "--stream", state_dir=self.state).stdout
        self.assertEqual(loaded, streamed)
        self.assertTrue(json.loads(loaded)["valid"])

    def test_an_unusable_ed25519_backend_is_an_error_not_a_traceback(self):
        env = dict(os.environ, DECISION_AUDIT_ED25519_BACKEND="nope")
        proc = subprocess.run(
            [sys.executable, "-m", "decision_audit", "--state-dir", str(self.state),
             "demo"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("unknown Ed25519 backend", proc.stderr)

    def test_verify_without_state_is_clean(self):
        verify = run_cli("verify", state_dir=self.state)
        self.assertEqual(verify.returncode, 0)
        self.assertIn("nothing to verify", verify.stdout)
        self.assertFalse(self.state.exists())

    def test_audit_command_from_stdin(self):
        payload = json.dumps({
            "decision": {"decision": "APPROVE", "score": 0.4},
            "context": {
                "loan_amount": 150000, "property_value": 200000,
                "monthly_debt": 1000, "monthly_income": 6000,
                "marginal_var": 1.5, "var_limit": 1.0, "segment": "prime",
            },
        })
        proc = subprocess.run(
            [sys.executable, "-m", "decision_audit", "--state-dir", str(self.state), "audit"],
            cwd=REPO_ROOT, input=payload, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["final_outcome"], "BLOCKED_BY_POLICY")

        summary = run_cli("summary", state_dir=self.state)
        self.assertEqual(json.loads(summary.stdout)["audits"], 1)

    def test_audit_command_rejects_malformed_input(self):
        proc = subprocess.run(
            [sys.executable, "-m", "decision_audit", "--state-dir", str(self.state), "audit"],
            cwd=REPO_ROOT, input="not json", capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid JSON", proc.stderr)

    def test_missing_dataset_is_a_usage_error(self):
        batch = run_cli("batch", "--data-path", "does_not_exist.csv", state_dir=self.state)
        self.assertEqual(batch.returncode, 2)
        self.assertIn("not found", batch.stderr)

    def test_audit_command_rejects_a_non_object_context(self):
        payload = Path(self._tmp.name) / "bad.json"
        payload.write_text(json.dumps({"decision": "APPROVE", "context": []}))
        proc = run_cli("audit", "--input", str(payload), state_dir=self.state)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("context must be an object", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_a_third_party_verifies_one_record_holding_only_the_public_key(self):
        self._seed_hmac_state(scheme="ed25519", count=8)

        proof_file = Path(self._tmp.name) / "record3.json"
        prove = run_cli("prove", "--index", "3", "--out", str(proof_file),
                        state_dir=self.state)
        self.assertEqual(prove.returncode, 0, prove.stderr)

        third_party = Path(self._tmp.name) / "third_party"
        third_party.mkdir()
        pub = third_party / "ed25519_key.pub"
        pub.write_bytes((Path(self.state) / "ed25519_key.pub").read_bytes())

        check = run_cli("--public-key", str(pub), "verify-proof", str(proof_file),
                        state_dir=third_party)
        self.assertEqual(check.returncode, 0, check.stderr + check.stdout)
        self.assertIn("Proof OK", check.stdout)
        self.assertFalse((third_party / "chain.jsonl").exists())
        self.assertFalse((third_party / "ed25519_key.bin").exists())

    def test_an_edited_record_fails_third_party_verification(self):
        self._seed_hmac_state(scheme="ed25519", count=8)
        proof_file = Path(self._tmp.name) / "record3.json"
        run_cli("prove", "--index", "3", "--out", str(proof_file), state_dir=self.state)

        proof = json.loads(proof_file.read_text())
        proof["block"]["data"]["final_outcome"] = "APPROVE_FORGED"
        proof_file.write_text(json.dumps(proof))

        check = run_cli("verify-proof", str(proof_file), state_dir=self.state)
        self.assertEqual(check.returncode, 1)
        self.assertIn("FAILED", check.stdout)

    def test_consistency_proof_shows_the_log_only_grew(self):
        self._seed_hmac_state(scheme="ed25519", count=5)
        head_file = Path(self._tmp.name) / "head.json"
        self.assertEqual(
            run_cli("prove", "--head", "--out", str(head_file),
                    state_dir=self.state).returncode, 0)

        self._seed_hmac_state(scheme="ed25519", count=4)

        proof_file = Path(self._tmp.name) / "consistency.json"
        made = run_cli("prove", "--since", str(head_file), "--out", str(proof_file),
                       state_dir=self.state)
        self.assertEqual(made.returncode, 0, made.stderr)

        check = run_cli("verify-proof", str(proof_file), state_dir=self.state)
        self.assertEqual(check.returncode, 0, check.stderr + check.stdout)
        self.assertIn("5 to 9", check.stdout)

    def test_checkpoint_now_pins_the_whole_prefix_not_just_its_last_block(self):
        self._seed_hmac_state(scheme="ed25519", count=6)
        cp_file = Path(self._tmp.name) / "cp.json"
        cp = run_cli("checkpoint", state_dir=self.state)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        statement = json.loads(cp.stdout)
        self.assertIn("root_hash", statement)
        cp_file.write_text(cp.stdout)

        self.assertEqual(run_cli("checkpoint", "--check", str(cp_file),
                                 state_dir=self.state).returncode, 0)

        chain_path = Path(self.state) / "chain.jsonl"
        lines = chain_path.read_text().splitlines()
        block = json.loads(lines[2])
        block["data"]["final_outcome"] = "REWRITTEN"
        lines[2] = json.dumps(block, sort_keys=True, separators=(",", ":"))
        chain_path.write_text("\n".join(lines) + "\n")

        recheck = run_cli("checkpoint", "--check", str(cp_file), state_dir=self.state)
        self.assertEqual(recheck.returncode, 1)

    def test_global_options_are_honoured_by_commands_that_create_a_chain(self):
        for command in ("demo", "batch"):
            with self.subTest(command=command, option="--scheme"):
                state = Path(self._tmp.name) / f"state_{command}"
                proc = run_cli("--scheme", "hmac", command, state_dir=state)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                header = json.loads((state / "chain.jsonl").read_text().splitlines()[0])
                self.assertEqual(header["scheme"], "hmac")
                self.assertTrue((state / "hmac_key.bin").exists())

            with self.subTest(command=command, option="--key-path"):
                keys = Path(self._tmp.name) / f"keys_{command}"
                keys.mkdir()
                state = Path(self._tmp.name) / f"keyed_{command}"
                proc = run_cli("--key-path", str(keys / "seed.bin"),
                               "--public-key", str(keys / "auditor.pub"),
                               command, state_dir=state)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertTrue((keys / "seed.bin").exists())
                self.assertTrue((keys / "auditor.pub").exists())
                self.assertFalse((state / "ed25519_key.bin").exists())
                self.assertFalse((state / "ed25519_key.pub").exists())

    def test_a_checkpoint_can_stand_in_for_a_tree_head(self):
        self._seed_hmac_state(count=4)
        cp = run_cli("checkpoint", state_dir=self.state)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        cp_file = Path(self._tmp.name) / "cp.json"
        cp_file.write_text(cp.stdout)

        self._seed_hmac_state(count=3)
        proof_file = Path(self._tmp.name) / "grew.json"
        made = run_cli("prove", "--since", str(cp_file), "--out", str(proof_file),
                       state_dir=self.state)
        self.assertEqual(made.returncode, 0, made.stderr)

        check = run_cli("verify-proof", str(proof_file), state_dir=self.state)
        self.assertEqual(check.returncode, 0, check.stderr + check.stdout)

    def test_verify_proof_finds_the_scheme_without_being_told(self):
        self._seed_hmac_state(count=4)
        proof_file = Path(self._tmp.name) / "p.json"
        run_cli("prove", "--index", "1", "--out", str(proof_file), state_dir=self.state)

        check = run_cli("verify-proof", str(proof_file), state_dir=self.state)
        self.assertEqual(check.returncode, 0, check.stderr + check.stdout)

    def test_a_malformed_item_commits_nothing_from_the_batch(self):
        good = {"decision": "APPROVE",
                "context": {"loan_amount": 100000, "property_value": 200000,
                            "monthly_income": 6000, "monthly_debt": 1000,
                            "marginal_var": 0.5, "var_limit": 1.0}}
        payload = Path(self._tmp.name) / "partial.json"
        payload.write_text(json.dumps([good, good, {"decision": "APPROVE",
                                                    "context": "not an object"}]))

        proc = run_cli("audit", "--input", str(payload), state_dir=self.state)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("item 2", proc.stderr)
        self.assertFalse((Path(self.state) / "chain.jsonl").exists(),
                         "nothing should have been written")

    def test_unprocessable_features_degrade_the_record_but_still_log_it(self):
        payload = Path(self._tmp.name) / "features.json"
        payload.write_text(json.dumps(
            {"decision": "APPROVE", "context": {"loan_amount": 1, "features": "abc"}}))
        proc = run_cli("audit", "--input", str(payload), state_dir=self.state)
        self.assertEqual(proc.returncode, 3)
        self.assertNotIn("Traceback", proc.stderr)

        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "degraded")
        self.assertTrue(any("features must be" in e for e in result["input_errors"]),
                        result["input_errors"])

        verify = run_cli("verify", "--json", state_dir=self.state)
        self.assertEqual(verify.returncode, 0)
        self.assertEqual(json.loads(verify.stdout)["degraded_records"], 1)

    def test_unbandable_value_is_dropped_not_logged_raw(self):
        payload = Path(self._tmp.name) / "bad_amount.json"
        payload.write_text(json.dumps(
            {"decision": "APPROVE", "context": {"loan_amount": "not-a-number"}}))
        proc = run_cli("audit", "--input", str(payload), state_dir=self.state)
        self.assertEqual(proc.returncode, 3)

        chain = (Path(self.state) / "chain.jsonl").read_text()
        self.assertNotIn("not-a-number", chain)
        self.assertIn("degraded", chain)

    def _seed_hmac_state(self, scheme: str = "hmac", count: int = 1):
        payload = Path(self._tmp.name) / "seed.json"
        payload.write_text(json.dumps([
            {"decision": "APPROVE",
             "context": {"loan_amount": 100000 + i * 1000, "property_value": 200000,
                         "monthly_income": 6000, "monthly_debt": 1000,
                         "marginal_var": 0.5, "var_limit": 1.0}}
            for i in range(count)
        ]))
        proc = run_cli("--scheme", scheme, "audit", "--input", str(payload),
                       state_dir=self.state)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_key_path_puts_the_signing_key_where_it_is_asked_to(self):
        keystore = Path(self._tmp.name) / "keystore"
        keystore.mkdir()
        key = keystore / "signing.bin"

        seed = run_cli("--scheme", "hmac", "--key-path", str(key), "audit",
                       "--input", self._one_decision(), state_dir=self.state)
        self.assertEqual(seed.returncode, 0, seed.stderr)
        self.assertTrue(key.exists())
        self.assertFalse((self.state / "hmac_key.bin").exists())

        verify = run_cli("--key-path", str(key), "verify", state_dir=self.state)
        self.assertEqual(verify.returncode, 0, verify.stdout)

        reset = run_cli("--key-path", str(key), "reset", state_dir=self.state)
        self.assertEqual(reset.returncode, 0, reset.stderr)
        self.assertFalse((self.state / "chain.jsonl").exists())
        self.assertTrue(key.exists(), "a key named on the command line is not ours")

    def _one_decision(self) -> str:
        payload = Path(self._tmp.name) / "one.json"
        payload.write_text(json.dumps(
            {"decision": "APPROVE",
             "context": {"loan_amount": 100000, "property_value": 200000,
                         "monthly_income": 6000, "monthly_debt": 1000,
                         "marginal_var": 0.5, "var_limit": 1.0}}))
        return str(payload)

    def test_reset_leaves_a_public_key_given_on_the_command_line(self):
        keystore = Path(self._tmp.name) / "keystore"
        keystore.mkdir()
        auditor_key = keystore / "auditor.pub"
        auditor_key.write_bytes(b"x" * 32)

        proc = run_cli("--public-key", str(auditor_key), "reset", state_dir=self.state)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(auditor_key.exists())

    def test_reset_removes_its_own_state(self):
        self._seed_hmac_state()
        self.assertTrue((self.state / "chain.jsonl").exists())
        proc = run_cli("reset", state_dir=self.state)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse((self.state / "chain.jsonl").exists())
        self.assertFalse((self.state / "hmac_key.bin").exists())
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
