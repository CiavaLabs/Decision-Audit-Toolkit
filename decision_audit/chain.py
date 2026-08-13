import math
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .crypto import sha256_hex
from .locking import file_lock
from .merkle import MerkleTree, leaf_hash
from .utils import canonical_json, loads_strict

GENESIS_HASH = "0" * 64
CHAIN_SCHEMA = 1

SECOND_HEADER = "a second header line"

class ChainIntegrityError(RuntimeError):
    pass

def is_header(payload: Any) -> bool:
    return isinstance(payload, dict) and payload.get("type") == "header"

def compute_block_hash(index: int, timestamp: float, data: dict,
                       prev_hash: str) -> str:
    block_content = {"index": index, "timestamp": timestamp,
                     "data": data, "prev_hash": prev_hash}
    return sha256_hex(canonical_json(block_content).encode())

@dataclass
class ChainNode:
    index: int
    timestamp: float
    data: dict[str, Any]
    prev_hash: str
    hash: str
    signature: bytes

def node_from_dict(payload: Any) -> ChainNode:
    if not isinstance(payload, dict):
        raise TypeError("block must be a JSON object")
    index, timestamp = payload["index"], payload["timestamp"]
    data, prev_hash, block_hash = payload["data"], payload["prev_hash"], payload["hash"]
    if isinstance(index, bool) or not isinstance(index, int):
        raise TypeError("block 'index' must be an integer")
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        raise TypeError("block 'timestamp' must be a number")
    if not math.isfinite(timestamp):
        raise ValueError("block 'timestamp' must be finite")
    if not isinstance(data, dict):
        raise TypeError("block 'data' must be a JSON object")
    if not isinstance(prev_hash, str) or not isinstance(block_hash, str):
        raise TypeError("block 'prev_hash' and 'hash' must be strings")
    return ChainNode(
        index=index,
        timestamp=timestamp,
        data=data,
        prev_hash=prev_hash,
        hash=block_hash,
        signature=bytes.fromhex(payload["signature"]),
    )

class HashChain:
    def __init__(self, signer, storage_path: str | None = None,
                 clock: Callable[[], float] = time.time):
        self.signer = signer
        self.storage_path = Path(storage_path) if storage_path else None
        self.clock = clock
        self.chain: list[ChainNode] = []
        self._lock = threading.RLock()
        self._file_errors: list[str] = []
        self._unreadable = False
        self._warnings: list[str] = []
        self._append_allowed: bool | None = None
        self._read_offset = 0
        self._clock_regressions = 0
        self._tree: MerkleTree | None = None
        self._tree_key: tuple[int, str] | None = None
        self._load_existing_chain()

    @property
    def warnings(self) -> list[str]:
        return list(self._warnings)

    @property
    def clock_regressions(self) -> int:
        return self._clock_regressions

    @property
    def unreadable(self) -> bool:
        return self._unreadable

    def _load_existing_chain(self) -> None:
        if not self.storage_path or not self.storage_path.exists():
            return
        try:
            data = self.storage_path.read_bytes()
        except OSError as exc:
            self._fail_load(f"unreadable chain file: {exc}")
            return

        complete, _, torn = data.rpartition(b"\n")
        if data and not torn:
            complete = data
        elif torn:
            complete = complete + b"\n" if complete else b""
            self._warnings.append(
                f"discarded {len(torn)} trailing bytes: a record whose write was "
                "cut short (crash or full disk during append)")

        try:
            raw = complete.decode("utf-8")
        except UnicodeDecodeError as exc:
            self._fail_load(f"unreadable chain file: {exc}")
            return

        self._load_jsonl(raw)
        if not self._file_errors:
            self._read_offset = len(complete)

    def _load_jsonl(self, raw: str) -> None:
        entries: list[tuple[int, Any]] = []
        for lineno, line in enumerate(raw.split("\n"), start=1):
            if not line.strip():
                continue
            try:
                entries.append((lineno, loads_strict(line)))
            except ValueError:
                self._fail_load(f"unreadable chain file: invalid JSON at line {lineno}")
                return
        if not entries:
            return
        header = entries[0][1]
        if not is_header(header):
            self._fail_load("unreadable chain file: missing header line")
            return
        chain: list[ChainNode] = []
        for lineno, payload in entries[1:]:
            if is_header(payload):
                self._fail_load(f"unreadable chain file: {SECOND_HEADER} at line {lineno}")
                return
            try:
                chain.append(self._dict_to_node(payload))
            except (KeyError, TypeError, ValueError) as exc:
                self._fail_load(
                    f"unreadable chain file: unreadable record at line {lineno}: {exc}")
                return
        self.chain = chain
        self._check_scheme(header.get("scheme"))

    def _fail_load(self, error: str) -> None:
        self.chain = []
        self._file_errors = [error]
        self._unreadable = True
        self._append_allowed = False
        self._read_offset = 0

    def _check_scheme(self, stored_scheme) -> None:
        if stored_scheme and stored_scheme != self.signer.scheme:
            self._file_errors.append(
                f"chain was signed with '{stored_scheme}' but the configured scheme is "
                f"'{self.signer.scheme}'")
            self._append_allowed = False

    _compute_hash = staticmethod(compute_block_hash)

    def add_record(self, data: dict[str, Any] | Callable[[int], dict[str, Any]],
                   on_commit: Callable[[], None] | None = None) -> str:
        with self._lock, file_lock(self.storage_path):
            self._sync_from_disk_locked()
            if not self._may_append_locked():
                raise ChainIntegrityError(
                    "stored chain failed verification; refusing to append "
                    "(reset the audit state to start over)")
            prev_hash = self.chain[-1].hash if self.chain else GENESIS_HASH
            index = len(self.chain)
            if callable(data):
                data = data(index)
            timestamp = self.clock()
            if self.chain and timestamp < self.chain[-1].timestamp:
                timestamp = self.chain[-1].timestamp
                self._clock_regressions += 1
            block_hash = self._compute_hash(index, timestamp, data, prev_hash)
            signature = self.signer.sign(block_hash.encode())
            node = ChainNode(index, timestamp, data, prev_hash, block_hash, signature)
            self.chain.append(node)
            self._persist_append_locked(node)
            if on_commit is not None:
                on_commit()
            return block_hash

    def _may_append_locked(self) -> bool:
        if self._append_allowed is None:
            self._append_allowed = self.verify_integrity()[0]
        return self._append_allowed

    def _sync_from_disk_locked(self) -> None:
        if self._file_errors or not self.storage_path:
            return
        try:
            size = self.storage_path.stat().st_size
        except OSError:
            return
        if size == self._read_offset:
            return
        if size < self._read_offset:
            self._reload_locked()
            return
        parsed = self._read_appended_locked()
        if parsed is None:
            return
        appended, consumed = parsed

        can_verify = self.signer.can_verify()
        for node in appended:
            expected_prev = self.chain[-1].hash if self.chain else GENESIS_HASH
            expected_hash = self._compute_hash(node.index, node.timestamp, node.data, node.prev_hash)
            if (node.prev_hash != expected_prev or node.index != len(self.chain)
                    or node.hash != expected_hash):
                self._file_errors.append(
                    f"block {node.index}: appended by another writer but does not "
                    "extend this chain")
                self._append_allowed = False
                return
            if can_verify and not self.signer.verify(node.hash.encode(), node.signature):
                self._file_errors.append(
                    f"block {node.index}: appended by another writer with an "
                    "invalid signature")
                self._append_allowed = False
                return
            self.chain.append(node)
        self._read_offset += consumed

    def _read_appended_locked(self) -> tuple[list[ChainNode], int] | None:
        if self.storage_path is None:
            return [], 0
        try:
            with open(self.storage_path, "rb") as fh:
                fh.seek(self._read_offset)
                tail = fh.read()
        except OSError as exc:
            self._fail_load(f"unreadable chain file: {exc}")
            return None

        nodes: list[ChainNode] = []
        consumed = 0
        expect_header = self._read_offset == 0
        for raw_line in tail.split(b"\n")[:-1]:
            consumed += len(raw_line) + 1
            if not raw_line.strip():
                continue
            try:
                payload = loads_strict(raw_line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._fail_load("unreadable chain file: invalid JSON in appended records")
                return None
            if expect_header:
                expect_header = False
                if is_header(payload):
                    continue
                self._fail_load("unreadable chain file: missing header line")
                return None
            if is_header(payload):
                self._fail_load(
                    f"unreadable chain file: {SECOND_HEADER} in appended records")
                return None
            try:
                nodes.append(self._dict_to_node(payload))
            except (KeyError, TypeError, ValueError) as exc:
                self._fail_load(f"unreadable chain file: {exc}")
                return None
        return nodes, consumed

    def _reload_locked(self) -> None:
        self.chain = []
        self._file_errors = []
        self._unreadable = False
        self._warnings = []
        self._append_allowed = None
        self._read_offset = 0
        self._load_existing_chain()

    def verify_integrity(self, *, full: bool = False) -> tuple[bool, list[str]]:
        with self._lock:
            errors = list(self._file_errors)
            check_signatures = self.signer.can_verify()
            if self.chain and not check_signatures:
                errors.append("verification key not found: signatures cannot be verified")
            head_index = len(self.chain) - 1
            for i, node in enumerate(self.chain):
                expected_hash = self._compute_hash(node.index, node.timestamp, node.data, node.prev_hash)
                if node.hash != expected_hash:
                    errors.append(f"block {i}: hash mismatch")
                if (check_signatures and (full or i == head_index)
                        and not self.signer.verify(node.hash.encode(), node.signature)):
                    errors.append(f"block {i}: invalid signature")
                if node.index != i:
                    errors.append(f"block {i}: index recorded as {node.index}")
                if i == 0:
                    if node.prev_hash != GENESIS_HASH:
                        errors.append("block 0: prev_hash is not the genesis sentinel")
                else:
                    if node.prev_hash != self.chain[i - 1].hash:
                        errors.append(f"block {i}: broken link to previous block")
                    if node.timestamp < self.chain[i - 1].timestamp:
                        errors.append(
                            f"block {i}: timestamp {node.timestamp} precedes "
                            f"block {i - 1}'s {self.chain[i - 1].timestamp}")
        return len(errors) == 0, errors

    def merkle_tree(self) -> MerkleTree:
        with self._lock:
            head = self.chain[-1].hash if self.chain else GENESIS_HASH
            key = (len(self.chain), head)
            if self._tree is None or self._tree_key != key:
                self._tree = MerkleTree([leaf_hash(h) for h in self._content_hashes()])
                self._tree_key = key
            return self._tree

    def _content_hashes(self) -> list[str]:
        return [compute_block_hash(n.index, n.timestamp, n.data, n.prev_hash)
                for n in self.chain]

    def tree_head(self) -> tuple[int, str]:
        tree = self.merkle_tree()
        return len(self.chain), tree.root_hex()

    def _header(self) -> dict[str, Any]:
        return {"type": "header", "schema": CHAIN_SCHEMA, "scheme": self.signer.scheme}

    def _drop_torn_tail_locked(self) -> None:
        if not self.storage_path or not self.storage_path.exists():
            return
        try:
            if self.storage_path.stat().st_size <= self._read_offset:
                return
            with open(self.storage_path, "r+b") as fh:
                fh.truncate(self._read_offset)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            return

    def _persist_append_locked(self, node: ChainNode) -> None:
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._drop_torn_tail_locked()
        is_new = not self.storage_path.exists() or self.storage_path.stat().st_size == 0
        with open(self.storage_path, "a", encoding="utf-8", newline="\n") as fh:
            if is_new:
                fh.write(canonical_json(self._header()) + "\n")
                for existing in self.chain[:-1]:
                    fh.write(canonical_json(self._node_to_dict(existing)) + "\n")
            fh.write(canonical_json(self._node_to_dict(node)) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            self._read_offset = fh.tell()

    @staticmethod
    def _node_to_dict(node: ChainNode) -> dict[str, Any]:
        return {
            "index": node.index,
            "timestamp": node.timestamp,
            "data": node.data,
            "prev_hash": node.prev_hash,
            "hash": node.hash,
            "signature": node.signature.hex()
        }

    _dict_to_node = staticmethod(node_from_dict)

def detect_chain_scheme(storage_path) -> str | None:
    path = Path(storage_path)
    try:
        with open(path, encoding="utf-8") as fh:
            first_line = next((line for line in fh if line.strip()), "")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        head = loads_strict(first_line)
    except ValueError:
        return None
    if isinstance(head, dict) and isinstance(head.get("scheme"), str):
        return head["scheme"]
    return None
