import json
import tempfile
import unittest
from pathlib import Path

from decision_audit.chain import compute_block_hash
from decision_audit.config import Config
from decision_audit.crypto import Ed25519Signer
from decision_audit.orchestrator import AuditOrchestrator
from decision_audit.proofs import (
    build_consistency_proof,
    build_inclusion_proof,
    build_tree_head,
    verify_proof,
)

CONTEXT = {
    "loan_amount": 150000, "property_value": 200000, "monthly_debt": 1000,
    "monthly_income": 6000, "marginal_var": 0.5, "var_limit": 1.0,
    "segment": "prime",
}


class ProofTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "state"
        self.orch = AuditOrchestrator(Config(state_dir=str(self.state)))
        for i in range(12):
            self.orch.audit_decision({"decision": "APPROVE", "score": i / 100},
                                     dict(CONTEXT, loan_amount=100000 + i * 1000))

    def _third_party_signer(self):
        return Ed25519Signer(
            key_path=str(Path(self._tmp.name) / "absent_seed.bin"),
            public_key_path=str(self.state / "ed25519_key.pub"))

    def _proof_for(self, index=5):
        return build_inclusion_proof(self.orch.chain, self.orch.signer, index)


class InclusionProofTests(ProofTestBase):
    def test_inclusion_proof_verifies_with_only_the_public_key(self):
        proof = self._proof_for(5)
        valid, errors = verify_proof(self._third_party_signer(), proof)
        self.assertTrue(valid, errors)

    def test_inclusion_proof_discloses_only_its_own_record(self):
        proof = self._proof_for(5)
        rendered = json.dumps(proof)
        self.assertIn("audit_000005", rendered)
        for other in range(12):
            if other != 5:
                self.assertNotIn(f"audit_{other:06d}", rendered)

    def test_inclusion_proof_is_far_smaller_than_the_log(self):
        proof = len(json.dumps(self._proof_for(5)))
        log = len(Path(self.orch.config.resolved_chain_path()).read_text())
        self.assertLess(proof, log)

    def test_edited_record_is_rejected(self):
        proof = self._proof_for(5)
        proof["block"]["data"]["final_outcome"] = "SOMETHING_ELSE"
        valid, errors = verify_proof(self._third_party_signer(), proof)
        self.assertFalse(valid)
        self.assertTrue(any("does not hash" in e for e in errors), errors)

    def test_edited_record_with_a_repaired_block_hash_is_rejected(self):
        proof = self._proof_for(5)
        block = proof["block"]
        block["data"]["final_outcome"] = "SOMETHING_ELSE"
        proof["block_hash"] = compute_block_hash(
            block["index"], block["timestamp"], block["data"], block["prev_hash"])
        valid, errors = verify_proof(self._third_party_signer(), proof)
        self.assertFalse(valid)
        self.assertTrue(any("not in the signed tree" in e for e in errors), errors)

    def test_record_claimed_at_another_position_is_rejected(self):
        proof = self._proof_for(5)
        proof["leaf_index"] = 6
        valid, _ = verify_proof(self._third_party_signer(), proof)
        self.assertFalse(valid)

    def test_forged_tree_head_is_rejected(self):
        proof = self._proof_for(5)
        proof["tree_head"]["root_hash"] = "ab" * 32
        valid, errors = verify_proof(self._third_party_signer(), proof)
        self.assertFalse(valid)
        self.assertTrue(any("signature invalid" in e for e in errors), errors)

    def test_tampered_path_is_rejected(self):
        proof = self._proof_for(5)
        proof["path"][0] = "cd" * 32
        valid, _ = verify_proof(self._third_party_signer(), proof)
        self.assertFalse(valid)

    def test_tree_binds_record_content_not_the_stored_hash_field(self):
        before = self.orch.chain.tree_head()[1]
        node = self.orch.chain.chain[5]
        node.data["final_outcome"] = "REWRITTEN"
        self.orch.chain._tree_key = None

        self.assertNotEqual(self.orch.chain.tree_head()[1], before)

    def test_proof_for_a_missing_index_is_refused(self):
        with self.assertRaises(ValueError):
            build_inclusion_proof(self.orch.chain, self.orch.signer, 99)

    def test_every_record_can_be_proved(self):
        signer = self._third_party_signer()
        for i in range(12):
            with self.subTest(record=i):
                valid, errors = verify_proof(signer, self._proof_for(i))
                self.assertTrue(valid, errors)


class ConsistencyProofTests(ProofTestBase):
    def test_growth_keeps_the_earlier_log_intact(self):
        earlier = build_tree_head(self.orch.chain, self.orch.signer)
        for _ in range(5):
            self.orch.audit_decision({"decision": "REJECT"}, dict(CONTEXT))

        proof = build_consistency_proof(self.orch.chain, self.orch.signer, earlier)
        valid, errors = verify_proof(self._third_party_signer(), proof)
        self.assertTrue(valid, errors)
        self.assertEqual(proof["old_tree_head"]["tree_size"], 12)
        self.assertEqual(proof["new_tree_head"]["tree_size"], 17)

    def test_rewritten_history_cannot_be_proved_consistent(self):
        earlier = build_tree_head(self.orch.chain, self.orch.signer)

        other_state = Path(self._tmp.name) / "rewritten"
        rewritten = AuditOrchestrator(Config(
            state_dir=str(other_state),
            key_path=str(self.state / "ed25519_key.bin"),
            public_key_path=str(self.state / "ed25519_key.pub")))
        for i in range(12):
            amount = 100000 + i * 1000 + (500 if i == 5 else 0)
            rewritten.audit_decision({"decision": "APPROVE", "score": i / 100},
                                     dict(CONTEXT, loan_amount=amount))

        proof = build_consistency_proof(rewritten.chain, rewritten.signer, earlier)
        valid, errors = verify_proof(self._third_party_signer(), proof)
        self.assertFalse(valid)
        self.assertTrue(any("does not extend" in e for e in errors), errors)

    def test_truncation_below_the_checkpoint_leaves_no_proof_to_make(self):
        earlier = build_tree_head(self.orch.chain, self.orch.signer)
        self.orch.chain.chain = self.orch.chain.chain[:6]
        with self.assertRaises(ValueError) as caught:
            build_consistency_proof(self.orch.chain, self.orch.signer, earlier)
        self.assertIn("truncated", str(caught.exception))

    def test_a_head_signed_by_another_key_is_rejected(self):
        other_state = Path(self._tmp.name) / "other"
        other = AuditOrchestrator(Config(state_dir=str(other_state)))
        other.audit_decision({"decision": "APPROVE"}, dict(CONTEXT))
        foreign_head = build_tree_head(other.chain, other.signer)

        proof = build_inclusion_proof(self.orch.chain, self.orch.signer, 3)
        proof["tree_head"] = foreign_head
        valid, _ = verify_proof(self._third_party_signer(), proof)
        self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()
