import tempfile
import unittest
from pathlib import Path

from decision_audit.chain import HashChain
from decision_audit.crypto import Ed25519Signer, HmacSigner, make_signer


class Ed25519SignerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name)
        self.seed_path = self.state / "ed25519_key.bin"
        self.pub_path = self.state / "ed25519_key.pub"

    def _signer(self) -> Ed25519Signer:
        return Ed25519Signer(str(self.seed_path), str(self.pub_path))

    def test_sign_creates_keypair_and_roundtrips(self):
        signer = self._signer()
        signature = signer.sign(b"message")
        self.assertTrue(self.seed_path.exists())
        self.assertTrue(self.pub_path.exists())
        self.assertTrue(signer.verify(b"message", signature))
        self.assertFalse(signer.verify(b"other", signature))

    def test_verification_needs_only_the_public_key(self):
        signature = self._signer().sign(b"message")
        self.seed_path.unlink()

        verifier = self._signer()
        self.assertTrue(verifier.can_verify())
        self.assertTrue(verifier.verify(b"message", signature))

    def test_cannot_sign_with_only_the_public_key(self):
        self._signer().sign(b"message")
        self.seed_path.unlink()

        crippled = self._signer()
        with self.assertRaises(ValueError) as caught:
            crippled.sign(b"message")
        self.assertIn("private seed missing", str(caught.exception))
        self.assertFalse(self.seed_path.exists())

    def test_read_only_construction_creates_no_state(self):
        signer = self._signer()
        self.assertFalse(signer.can_verify())
        self.assertFalse(self.seed_path.exists())
        self.assertFalse(self.pub_path.exists())

    def test_in_memory_signer(self):
        signer = Ed25519Signer()
        self.assertTrue(signer.verify(b"m", signer.sign(b"m")))


class SignerFactoryTests(unittest.TestCase):
    def test_make_signer(self):
        self.assertIsInstance(make_signer("hmac"), HmacSigner)
        self.assertIsInstance(make_signer("ed25519"), Ed25519Signer)
        with self.assertRaises(ValueError):
            make_signer("rot13")


class SchemeMismatchTests(unittest.TestCase):
    def test_chain_reports_scheme_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            chain_path = state / "chain.jsonl"
            ed = Ed25519Signer(str(state / "ed25519_key.bin"), str(state / "ed25519_key.pub"))
            HashChain(ed, storage_path=str(chain_path)).add_record({"n": 0})

            hmac_chain = HashChain(HmacSigner(str(state / "hmac_key.bin")),
                                   storage_path=str(chain_path))
            valid, errors = hmac_chain.verify_integrity()
            self.assertFalse(valid)
            self.assertTrue(any("signed with 'ed25519'" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
