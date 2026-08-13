import hashlib
import math
import unittest

from decision_audit.merkle import (
    MerkleTree,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)

MAX_N = 40


def rfc6962_mth(data: list[bytes]) -> bytes:
    if not data:
        return hashlib.sha256(b"").digest()
    if len(data) == 1:
        return hashlib.sha256(b"\x00" + data[0]).digest()
    k = 1
    while k * 2 < len(data):
        k *= 2
    return hashlib.sha256(b"\x01" + rfc6962_mth(data[:k]) + rfc6962_mth(data[k:])).digest()


def block_hashes(n: int) -> list[str]:
    return [f"{i:064x}" for i in range(n)]


def tree_of(n: int) -> MerkleTree:
    return MerkleTree([leaf_hash(h) for h in block_hashes(n)])


class MerkleRootTests(unittest.TestCase):
    def test_root_matches_an_independent_rfc6962_implementation(self):
        for n in range(0, MAX_N + 1):
            with self.subTest(n=n):
                expected = rfc6962_mth([bytes.fromhex(h) for h in block_hashes(n)])
                self.assertEqual(tree_of(n).root(), expected)

    def test_empty_tree_is_the_hash_of_nothing(self):
        self.assertEqual(MerkleTree([]).root(), hashlib.sha256(b"").digest())

    def test_leaf_and_node_hashes_are_domain_separated(self):
        left = right = bytes(32)
        self.assertNotEqual(leaf_hash("00" * 32), node_hash(left, right))

    def test_appending_changes_the_root(self):
        self.assertNotEqual(tree_of(7).root(), tree_of(8).root())


class InclusionProofTests(unittest.TestCase):
    def test_every_proof_verifies(self):
        for n in range(1, MAX_N + 1):
            tree = tree_of(n)
            root = tree.root()
            for i in range(n):
                with self.subTest(n=n, leaf=i):
                    self.assertTrue(verify_inclusion(
                        i, n, tree.leaves[i], tree.inclusion_proof(i), root))

    def test_proofs_are_rejected_when_anything_is_off(self):
        for n in range(2, 25):
            tree = tree_of(n)
            root = tree.root()
            for i in range(n):
                proof = tree.inclusion_proof(i)
                cases = {
                    "wrong root": (i, n, tree.leaves[i], proof, bytes(32)),
                    "wrong index": ((i + 1) % n, n, tree.leaves[i], proof, root),
                    "wrong leaf": (i, n, leaf_hash("ff" * 32), proof, root),
                    "truncated path": (i, n, tree.leaves[i], proof[:-1], root),
                    "extra step": (i, n, tree.leaves[i], [*proof, bytes(32)], root),
                }
                for label, args in cases.items():
                    with self.subTest(n=n, leaf=i, case=label):
                        self.assertFalse(verify_inclusion(*args))

    def test_index_outside_the_tree_is_refused(self):
        tree = tree_of(4)
        with self.assertRaises(ValueError):
            tree.inclusion_proof(4)
        with self.assertRaises(ValueError):
            tree.inclusion_proof(-1)

    def test_proof_size_is_logarithmic(self):
        for n in (1, 2, 16, 17, 1000, 1024):
            tree = tree_of(n)
            for i in (0, n // 2, n - 1):
                with self.subTest(n=n, leaf=i):
                    self.assertLessEqual(len(tree.inclusion_proof(i)),
                                         max(1, math.ceil(math.log2(n)) + 1))


class ConsistencyProofTests(unittest.TestCase):
    def test_every_proof_verifies(self):
        for n in range(1, MAX_N + 1):
            tree = tree_of(n)
            new_root = tree.root()
            for m in range(1, n + 1):
                with self.subTest(old=m, new=n):
                    self.assertTrue(verify_consistency(
                        m, n, tree_of(m).root(), new_root, tree.consistency_proof(m)))

    def test_rewritten_history_is_rejected(self):
        for n in range(2, 25):
            tree = tree_of(n)
            new_root = tree.root()
            for m in range(1, n):
                forged = MerkleTree(
                    [leaf_hash(h) for h in block_hashes(m - 1)]
                    + [leaf_hash("ab" * 32)])
                with self.subTest(old=m, new=n):
                    self.assertFalse(verify_consistency(
                        m, n, forged.root(), new_root, tree.consistency_proof(m)))

    def test_a_shrinking_log_has_no_consistency_proof(self):
        self.assertFalse(verify_consistency(
            10, 5, tree_of(10).root(), tree_of(5).root(), []))
        with self.assertRaises(ValueError):
            tree_of(5).consistency_proof(10)

    def test_same_size_needs_the_same_root_and_no_proof(self):
        root = tree_of(6).root()
        self.assertTrue(verify_consistency(6, 6, root, root, []))
        self.assertFalse(verify_consistency(6, 6, bytes(32), root, []))

    def test_every_tree_extends_the_empty_one(self):
        self.assertEqual(tree_of(5).consistency_proof(0), [])
        self.assertTrue(verify_consistency(0, 5, MerkleTree([]).root(),
                                           tree_of(5).root(), []))


if __name__ == "__main__":
    unittest.main()
