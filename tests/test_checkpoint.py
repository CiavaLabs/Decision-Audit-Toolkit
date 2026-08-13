import tempfile
import unittest
from pathlib import Path

from decision_audit.chain import HashChain
from decision_audit.checkpoint import build_checkpoint, verify_checkpoint
from decision_audit.crypto import Ed25519Signer


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name)
        self.signer = Ed25519Signer(str(self.state / "key.bin"), str(self.state / "key.pub"))
        self.chain = HashChain(self.signer, storage_path=str(self.state / "chain.jsonl"))

    def test_checkpoint_of_empty_chain_raises(self):
        with self.assertRaises(ValueError):
            build_checkpoint(self.chain, self.signer)

    def test_checkpoint_verifies_and_survives_appends(self):
        for i in range(3):
            self.chain.add_record({"n": i})
        checkpoint = build_checkpoint(self.chain, self.signer)

        valid, errors, _ = verify_checkpoint(self.chain, self.signer, checkpoint)
        self.assertTrue(valid, errors)

        self.chain.add_record({"n": 3})
        valid, errors, _ = verify_checkpoint(self.chain, self.signer, checkpoint)
        self.assertTrue(valid, errors)

    def test_tampered_checkpoint_fails_signature(self):
        self.chain.add_record({"n": 0})
        checkpoint = build_checkpoint(self.chain, self.signer)
        checkpoint["blocks"] = 999
        valid, errors, _ = verify_checkpoint(self.chain, self.signer, checkpoint)
        self.assertFalse(valid)
        self.assertTrue(any("signature invalid" in e for e in errors), errors)

    def test_truncated_history_is_detected(self):
        for i in range(3):
            self.chain.add_record({"n": i})
        checkpoint = build_checkpoint(self.chain, self.signer)

        shorter = HashChain(self.signer)
        shorter.add_record({"n": 0})
        valid, errors, _ = verify_checkpoint(shorter, self.signer, checkpoint)
        self.assertFalse(valid)
        self.assertTrue(any("truncated" in e for e in errors), errors)

    def test_rewritten_history_is_detected(self):
        for i in range(3):
            self.chain.add_record({"n": i})
        checkpoint = build_checkpoint(self.chain, self.signer)

        rewritten = HashChain(self.signer)
        for i in range(3):
            rewritten.add_record({"n": i + 100})
        valid, errors, _ = verify_checkpoint(rewritten, self.signer, checkpoint)
        self.assertFalse(valid)
        self.assertTrue(any("history rewritten" in e for e in errors), errors)

    def test_a_checkpoint_without_a_merkle_root_warns_but_passes(self):
        from decision_audit.utils import canonical_json

        for i in range(3):
            self.chain.add_record({"n": i})
        current = build_checkpoint(self.chain, self.signer)
        rootless = {k: v for k, v in current.items()
                    if k not in ("root_hash", "tree_size", "signature")}
        rootless["signature"] = self.signer.sign(canonical_json(rootless).encode()).hex()

        valid, errors, warnings = verify_checkpoint(self.chain, self.signer, rootless)
        self.assertTrue(valid, errors)
        self.assertEqual(errors, [])
        self.assertTrue(any("carries no Merkle root" in w for w in warnings), warnings)

    def test_a_rewritten_history_still_fails_a_checkpoint_without_a_root(self):
        from decision_audit.utils import canonical_json

        for i in range(3):
            self.chain.add_record({"n": i})
        current = build_checkpoint(self.chain, self.signer)
        rootless = {k: v for k, v in current.items()
                    if k not in ("root_hash", "tree_size", "signature")}
        rootless["signature"] = self.signer.sign(canonical_json(rootless).encode()).hex()

        rewritten = HashChain(self.signer)
        for i in range(3):
            rewritten.add_record({"n": i + 100})
        valid, errors, _ = verify_checkpoint(rewritten, self.signer, rootless)
        self.assertFalse(valid)
        self.assertTrue(any("history rewritten" in e for e in errors), errors)

    def test_malformed_checkpoint_reported(self):
        self.chain.add_record({"n": 0})
        valid, errors, _ = verify_checkpoint(self.chain, self.signer, {"signature": "zz"})
        self.assertFalse(valid)
        self.assertTrue(any("malformed" in e for e in errors), errors)

    def test_a_nonsensical_tree_size_is_reported_not_raised(self):
        for i in range(3):
            self.chain.add_record({"n": i})
        checkpoint = dict(build_checkpoint(self.chain, self.signer), tree_size=-1)

        valid, errors, _ = verify_checkpoint(self.chain, self.signer, checkpoint)
        self.assertFalse(valid)
        self.assertTrue(any("negative" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
