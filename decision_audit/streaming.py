import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .chain import (
    GENESIS_HASH,
    SECOND_HEADER,
    ChainNode,
    compute_block_hash,
    is_header,
    node_from_dict,
)
from .merkle import leaf_hash, node_hash
from .portfolio import PortfolioAccumulator
from .utils import loads_strict


class StreamingMerkleRoot:
    def __init__(self) -> None:
        self._stack: list[tuple[bytes, int]] = []

    def add(self, leaf: bytes) -> None:
        self._stack.append((leaf, 1))
        while len(self._stack) >= 2 and self._stack[-1][1] == self._stack[-2][1]:
            (right, size), (left, _) = self._stack.pop(), self._stack.pop()
            self._stack.append((node_hash(left, right), size * 2))

    def root(self) -> bytes:
        if not self._stack:
            return hashlib.sha256(b"").digest()
        value = self._stack[-1][0]
        for left, _ in reversed(self._stack[:-1]):
            value = node_hash(left, value)
        return value


@dataclass
class FileState:
    scheme: str | None = None
    warnings: list[str] = field(default_factory=list)


def stream_blocks(path: str | Path,
                  state: FileState | None = None) -> Iterator[tuple[int, ChainNode]]:
    chain_path = Path(path)
    seen_header = False
    with open(chain_path, "rb") as handle:
        for lineno, raw in enumerate(handle, start=1):
            if not raw.endswith(b"\n"):
                if state is not None:
                    state.warnings.append(
                        f"discarded {len(raw)} trailing bytes: a record whose write "
                        "was cut short (crash or full disk during append)")
                return
            text = raw.strip()
            if not text:
                continue
            try:
                payload = loads_strict(text.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"invalid JSON at line {lineno}") from exc
            if is_header(payload):
                if seen_header:
                    raise ValueError(f"{SECOND_HEADER} at line {lineno}")
                seen_header = True
                if state is not None and isinstance(payload.get("scheme"), str):
                    state.scheme = payload["scheme"]
                continue
            if not seen_header:
                raise ValueError("missing header line")
            try:
                yield lineno, node_from_dict(payload)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"unreadable record at line {lineno}: {exc}") from exc


def verify_stream(path: str | Path, signer, *, full: bool = False,
                  summary: PortfolioAccumulator | None = None) -> dict[str, Any]:
    errors: list[str] = []
    can_verify = signer.can_verify()
    tree = StreamingMerkleRoot()
    state = FileState()

    blocks = 0
    anomalies = 0
    degraded = 0
    previous: ChainNode | None = None
    head: ChainNode | None = None
    head_signature_slot = 0

    try:
        for _, node in stream_blocks(path, state):
            i = blocks
            expected = compute_block_hash(node.index, node.timestamp,
                                          node.data, node.prev_hash)
            if node.hash != expected:
                errors.append(f"block {i}: hash mismatch")
            head_signature_slot = len(errors)
            if full and can_verify and not signer.verify(node.hash.encode(), node.signature):
                errors.append(f"block {i}: invalid signature")
            if node.index != i:
                errors.append(f"block {i}: index recorded as {node.index}")
            if previous is None:
                if node.prev_hash != GENESIS_HASH:
                    errors.append("block 0: prev_hash is not the genesis sentinel")
            else:
                if node.prev_hash != previous.hash:
                    errors.append(f"block {i}: broken link to previous block")
                if node.timestamp < previous.timestamp:
                    errors.append(
                        f"block {i}: timestamp {node.timestamp} precedes "
                        f"block {i - 1}'s {previous.timestamp}")

            tree.add(leaf_hash(expected))
            if node.data.get("anomaly"):
                anomalies += 1
            if node.data.get("status") == "degraded":
                degraded += 1
            if summary is not None:
                summary.add(node.data)
            blocks += 1
            previous = node
            head = node
    except (OSError, ValueError) as exc:
        if summary is not None:
            summary.reset()
        return {
            "valid": False, "errors": [f"unreadable chain file: {exc}"],
            "warnings": state.warnings,
            "signature_check": "every-block" if full else "head-only",
            "blocks": 0, "anomalies": 0, "degraded_records": 0,
            "root_hash": None,
        }

    prelude: list[str] = []
    if state.scheme and state.scheme != signer.scheme:
        prelude.append(
            f"chain was signed with '{state.scheme}' but the configured scheme is "
            f"'{signer.scheme}'")
    if blocks and not can_verify:
        prelude.append("verification key not found: signatures cannot be verified")
    elif head is not None and not full and can_verify and \
            not signer.verify(head.hash.encode(), head.signature):
        errors.insert(head_signature_slot, f"block {blocks - 1}: invalid signature")
    errors = prelude + errors

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": state.warnings,
        "signature_check": "every-block" if full else "head-only",
        "blocks": blocks,
        "anomalies": anomalies,
        "degraded_records": degraded,
        "root_hash": tree.root().hex(),
    }
