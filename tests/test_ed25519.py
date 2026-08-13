import secrets
import unittest

from decision_audit import ed25519

RFC_VECTORS = [
    {
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": "e5564300c360ac729086e2cc806e828a"
                     "84877f1eb8e5d974d873e06522490155"
                     "5fb8821590a33bacc61e39701cf9b46b"
                     "d25bf5f0595bbe24655141438e7a100b",
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": "92a009a9f0d4cab8720e820b5f642540"
                     "a2b27b5416503f8fb3762223ebdb69da"
                     "085ac1e43e15996e458f3613d0f11d8c"
                     "387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": "6291d657deec24024827e69c3abe01a3"
                     "0ce548a284743a445e3680d7db5ac3ac"
                     "18ff9b538d16f290ae67f760984dc659"
                     "4a7c15e9716ed28dc027beceea1ec40a",
    },
]


def available_backends():
    found = []
    for name in ("python", "cryptography", "pynacl"):
        try:
            found.append(ed25519.select_backend(name))
        except ImportError:
            continue
    return found


class Ed25519RfcVectorTests(unittest.TestCase):
    def test_public_key_derivation_matches_rfc(self):
        for backend in available_backends():
            for vec in RFC_VECTORS:
                with self.subTest(backend=backend.name, seed=vec["seed"][:8]):
                    self.assertEqual(
                        backend.secret_to_public(bytes.fromhex(vec["seed"])).hex(),
                        vec["public"])

    def test_signatures_match_rfc(self):
        for backend in available_backends():
            for vec in RFC_VECTORS:
                with self.subTest(backend=backend.name, seed=vec["seed"][:8]):
                    sig = backend.sign(bytes.fromhex(vec["seed"]),
                                       bytes.fromhex(vec["message"]))
                    self.assertEqual(sig.hex(), vec["signature"])

    def test_rfc_signatures_verify(self):
        for backend in available_backends():
            for vec in RFC_VECTORS:
                with self.subTest(backend=backend.name, seed=vec["seed"][:8]):
                    self.assertTrue(backend.verify(
                        bytes.fromhex(vec["public"]),
                        bytes.fromhex(vec["message"]),
                        bytes.fromhex(vec["signature"])))


class BaseMultiplicationTests(unittest.TestCase):
    def test_the_precomputed_table_matches_plain_double_and_add(self):
        scalars = [0, 1, 2, 3, 8, ed25519._q - 1, 1 << 254, (1 << 255) - 1]
        scalars += [secrets.randbelow(1 << 255) for _ in range(40)]
        for scalar in scalars:
            with self.subTest(scalar=scalar):
                self.assertTrue(ed25519._point_equal(
                    ed25519._base_mult(scalar),
                    ed25519._point_mult(scalar, ed25519._G)))

    def test_a_scalar_wider_than_the_table_still_multiplies(self):
        wide = (1 << 300) + 7
        self.assertTrue(ed25519._point_equal(
            ed25519._base_mult(wide), ed25519._point_mult(wide, ed25519._G)))

    def test_the_cached_public_key_does_not_change_the_signature(self):
        seed, message = bytes(range(32)), b"decision-audit block hash"
        ed25519.pure_secret_to_public.cache_clear()
        cold = ed25519.pure_sign(seed, message)
        self.assertEqual(ed25519.pure_sign(seed, message), cold)
        ed25519.pure_secret_to_public.cache_clear()
        self.assertEqual(ed25519.pure_sign(seed, message), cold)

    def test_the_cache_does_not_confuse_two_seeds(self):
        first, second = bytes(range(32)), bytes(range(1, 33))
        message = b"m"
        publics = [ed25519.pure_secret_to_public(s) for s in (first, second)]
        self.assertNotEqual(*publics)
        for seed, public in zip((first, second), publics, strict=True):
            with self.subTest(seed=seed[:4].hex()):
                self.assertTrue(ed25519.pure_verify(
                    public, message, ed25519.pure_sign(seed, message)))


class BackendSelectionTests(unittest.TestCase):
    def tearDown(self):
        ed25519.use_backend(None)

    def test_pure_backend_is_always_available(self):
        self.assertEqual(ed25519.select_backend("python").name, "python")

    def test_unknown_backend_is_an_error_not_a_silent_downgrade(self):
        with self.assertRaises(ValueError):
            ed25519.select_backend("openssl-maybe")

    def test_use_backend_switches_the_module_level_functions(self):
        ed25519.use_backend("python")
        self.assertEqual(ed25519.active_backend(), "python")

    def test_every_backend_produces_identical_bytes(self):
        backends = available_backends()
        if len(backends) < 2:
            self.skipTest("only the pure backend is installed")
        seed = bytes(range(32))
        message = b"decision-audit block hash"
        signatures = {b.name: b.sign(seed, message) for b in backends}
        publics = {b.name: b.secret_to_public(seed) for b in backends}
        self.assertEqual(len(set(signatures.values())), 1, signatures)
        self.assertEqual(len(set(publics.values())), 1, publics)

    def test_each_backend_verifies_every_other_backends_signature(self):
        backends = available_backends()
        if len(backends) < 2:
            self.skipTest("only the pure backend is installed")
        seed = bytes(range(1, 33))
        message = b"cross-backend"
        for signer in backends:
            signature = signer.sign(seed, message)
            public = signer.secret_to_public(seed)
            for verifier in backends:
                with self.subTest(signed_by=signer.name, verified_by=verifier.name):
                    self.assertTrue(verifier.verify(public, message, signature))

    def test_all_backends_reject_the_same_tampered_inputs(self):
        backends = available_backends()
        seed = bytes(range(2, 34))
        message = b"original"
        public = ed25519.pure_secret_to_public(seed)
        signature = ed25519.pure_sign(seed, message)
        tampered = [
            (public, b"edited", signature),
            (public, message, signature[:32] + bytes(32)),
            (bytes(32), message, signature),
            (public, message, bytes(64)),
            (public, message, signature[:63] + bytes([signature[63] ^ 1])),
        ]
        for i, args in enumerate(tampered):
            verdicts = {b.name: b.verify(*args) for b in backends}
            with self.subTest(case=i):
                self.assertEqual(set(verdicts.values()), {False}, verdicts)


class Ed25519BehaviourTests(unittest.TestCase):
    def test_tampered_message_fails(self):
        vec = RFC_VECTORS[2]
        self.assertFalse(ed25519.verify(
            bytes.fromhex(vec["public"]), b"tampered", bytes.fromhex(vec["signature"])))

    def test_wrong_public_key_fails(self):
        vec, other = RFC_VECTORS[1], RFC_VECTORS[2]
        self.assertFalse(ed25519.verify(
            bytes.fromhex(other["public"]),
            bytes.fromhex(vec["message"]),
            bytes.fromhex(vec["signature"])))

    def test_malformed_inputs_fail_closed(self):
        vec = RFC_VECTORS[0]
        public = bytes.fromhex(vec["public"])
        signature = bytes.fromhex(vec["signature"])
        self.assertFalse(ed25519.verify(public[:31], b"", signature))
        self.assertFalse(ed25519.verify(public, b"", signature[:63]))
        self.assertFalse(ed25519.verify(public, b"", b"\xff" * 64))

    def test_bad_seed_length_raises(self):
        with self.assertRaises(ValueError):
            ed25519.sign(b"short", b"msg")


if __name__ == "__main__":
    unittest.main()
