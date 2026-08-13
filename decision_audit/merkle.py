import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(block_hash_hex: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(block_hash_hex)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        self.leaves = list(leaves)
        self._cache: dict[tuple[int, int], bytes] = {}

    def root(self) -> bytes:
        if not self.leaves:
            return hashlib.sha256(b"").digest()
        return self.subtree(0, len(self.leaves))

    def root_hex(self) -> str:
        return self.root().hex()

    def subtree(self, start: int, end: int) -> bytes:
        key = (start, end)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        n = end - start
        if n == 1:
            value = self.leaves[start]
        else:
            k = _split(n)
            value = node_hash(self.subtree(start, start + k),
                              self.subtree(start + k, end))
        self._cache[key] = value
        return value

    def inclusion_proof(self, index: int) -> list[bytes]:
        n = len(self.leaves)
        if not 0 <= index < n:
            raise ValueError(f"leaf {index} is outside a tree of {n} leaves")
        return self._path(index, 0, n)

    def _path(self, index: int, start: int, end: int) -> list[bytes]:
        n = end - start
        if n == 1:
            return []
        k = _split(n)
        if index < k:
            return [*self._path(index, start, start + k), self.subtree(start + k, end)]
        return [*self._path(index - k, start + k, end), self.subtree(start, start + k)]

    def consistency_proof(self, old_size: int) -> list[bytes]:
        n = len(self.leaves)
        if not 0 <= old_size <= n:
            raise ValueError(f"cannot prove consistency with {old_size} leaves of {n}")
        if old_size == 0 or old_size == n:
            return []
        return self._subproof(old_size, 0, n, True)

    def _subproof(self, m: int, start: int, end: int, on_the_old_path: bool) -> list[bytes]:
        n = end - start
        if m == n:
            return [] if on_the_old_path else [self.subtree(start, end)]
        k = _split(n)
        if m <= k:
            return [*self._subproof(m, start, start + k, on_the_old_path),
                    self.subtree(start + k, end)]
        return [*self._subproof(m - k, start + k, end, False),
                self.subtree(start, start + k)]


def verify_inclusion(leaf_index: int, tree_size: int, leaf: bytes,
                     proof: list[bytes], root: bytes) -> bool:
    if tree_size <= 0 or not 0 <= leaf_index < tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    computed = leaf
    for sibling in proof:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            computed = node_hash(sibling, computed)
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            computed = node_hash(computed, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and computed == root


def verify_consistency(old_size: int, new_size: int, old_root: bytes,
                       new_root: bytes, proof: list[bytes]) -> bool:
    if old_size > new_size or old_size < 0:
        return False
    if old_size == 0:
        return True
    if old_size == new_size:
        return not proof and old_root == new_root

    path = list(proof)
    if old_size & (old_size - 1) == 0:
        path = [old_root, *path]
    if not path:
        return False

    fn, sn = old_size - 1, new_size - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1

    old_computed = new_computed = path[0]
    for sibling in path[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            old_computed = node_hash(sibling, old_computed)
            new_computed = node_hash(sibling, new_computed)
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            new_computed = node_hash(new_computed, sibling)
        fn >>= 1
        sn >>= 1

    return sn == 0 and old_computed == old_root and new_computed == new_root
