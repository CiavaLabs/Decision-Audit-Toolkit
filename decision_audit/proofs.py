import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ._version import __version__
from .chain import HashChain, compute_block_hash
from .merkle import (
    MerkleTree,
    leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from .utils import canonical_json, loads_strict

PROOF_SCHEMA = 1


def build_tree_head(chain: HashChain, signer,
                    clock: Callable[[], float] = time.time) -> dict[str, Any]:
    tree_size, root_hash = chain.tree_head()
    statement = {
        "type": "signed_tree_head",
        "schema": PROOF_SCHEMA,
        "tree_size": tree_size,
        "root_hash": root_hash,
        "scheme": signer.scheme,
        "timestamp": clock(),
    }
    signature = signer.sign(canonical_json(statement).encode())
    return dict(statement, signature=signature.hex())


TREE_HEAD_TYPES = ("signed_tree_head", "checkpoint")


def verify_tree_head(signer, head: dict[str, Any]) -> tuple[bool, list[str]]:
    if not isinstance(head, dict) or head.get("type") not in TREE_HEAD_TYPES:
        return False, ["not a signed tree head"]
    if not isinstance(head.get("tree_size"), int) or isinstance(head.get("tree_size"), bool):
        return False, ["signed tree head: tree_size missing or invalid"]
    if not isinstance(head.get("root_hash"), str):
        return False, [
            "signed tree head: root_hash missing or invalid"
            + (" (a checkpoint without a Merkle root cannot stand in for one)"
               if head.get("type") == "checkpoint" else "")]
    if not signer.can_verify():
        return False, ["verification key not found: tree head signature cannot be checked"]
    statement = {k: v for k, v in head.items() if k != "signature"}
    try:
        signature = bytes.fromhex(str(head.get("signature", "")))
    except ValueError:
        return False, ["signed tree head: signature is not hex"]
    if not signature or not signer.verify(canonical_json(statement).encode(), signature):
        return False, ["signed tree head: signature invalid"]
    return True, []


def build_inclusion_proof(chain: HashChain, signer, index: int,
                          clock: Callable[[], float] = time.time) -> dict[str, Any]:
    size = len(chain.chain)
    if not 0 <= index < size:
        raise ValueError(f"no block at index {index}: the chain has {size}")
    node = chain.chain[index]
    tree = chain.merkle_tree()
    return {
        "type": "inclusion_proof",
        "schema": PROOF_SCHEMA,
        "version": __version__,
        "leaf_index": index,
        "block": {
            "index": node.index,
            "timestamp": node.timestamp,
            "data": node.data,
            "prev_hash": node.prev_hash,
        },
        "block_hash": node.hash,
        "path": [h.hex() for h in tree.inclusion_proof(index)],
        "tree_head": build_tree_head(chain, signer, clock=clock),
    }


def build_consistency_proof(chain: HashChain, signer, old_head: dict[str, Any],
                            clock: Callable[[], float] = time.time) -> dict[str, Any]:
    old_size = old_head.get("tree_size")
    if not isinstance(old_size, int) or isinstance(old_size, bool) or old_size < 0:
        raise ValueError("the earlier tree head has no usable tree_size")
    size = len(chain.chain)
    if old_size > size:
        raise ValueError(
            f"the earlier tree head covers {old_size} records but the log now "
            f"has {size}: history was truncated, no proof exists")
    tree = chain.merkle_tree()
    return {
        "type": "consistency_proof",
        "schema": PROOF_SCHEMA,
        "version": __version__,
        "old_tree_head": old_head,
        "new_tree_head": build_tree_head(chain, signer, clock=clock),
        "path": [h.hex() for h in tree.consistency_proof(old_size)],
    }


def verify_proof(signer, proof: dict[str, Any]) -> tuple[bool, list[str]]:
    if not isinstance(proof, dict):
        return False, ["proof file must contain a JSON object"]
    kind = proof.get("type")
    if kind == "inclusion_proof":
        return _verify_inclusion_bundle(signer, proof)
    if kind == "consistency_proof":
        return _verify_consistency_bundle(signer, proof)
    if kind == "signed_tree_head":
        return verify_tree_head(signer, proof)
    return False, [f"unknown proof type {kind!r}"]


def _decode_path(proof: dict[str, Any]) -> list[bytes] | None:
    raw = proof.get("path")
    if not isinstance(raw, list):
        return None
    try:
        path = [bytes.fromhex(str(h)) for h in raw]
    except ValueError:
        return None
    return path if all(len(h) == 32 for h in path) else None


def _verify_inclusion_bundle(signer, proof: dict[str, Any]) -> tuple[bool, list[str]]:
    head = proof.get("tree_head")
    if not isinstance(head, dict):
        return False, ["inclusion proof: no signed tree head"]
    head_ok, errors = verify_tree_head(signer, head)
    if not head_ok:
        return False, errors

    block = proof.get("block")
    index = proof.get("leaf_index")
    if not isinstance(block, dict) or not isinstance(index, int) or isinstance(index, bool):
        return False, ["inclusion proof: block or leaf_index missing"]

    try:
        recomputed = compute_block_hash(
            block["index"], block["timestamp"], block["data"], block["prev_hash"])
    except (KeyError, TypeError, ValueError) as exc:
        return False, [f"inclusion proof: block is not hashable ({exc})"]
    if recomputed != proof.get("block_hash"):
        return False, ["inclusion proof: block does not hash to the stated block_hash"]

    path = _decode_path(proof)
    if path is None:
        return False, ["inclusion proof: path is not a list of 32-byte hashes"]
    try:
        root = bytes.fromhex(str(head["root_hash"]))
    except ValueError:
        return False, ["inclusion proof: root_hash is not hex"]

    if not verify_inclusion(index, head["tree_size"], leaf_hash(recomputed), path, root):
        return False, ["inclusion proof: the record is not in the signed tree"]
    return True, []


def _verify_consistency_bundle(signer, proof: dict[str, Any]) -> tuple[bool, list[str]]:
    old = proof.get("old_tree_head")
    new = proof.get("new_tree_head")
    if not isinstance(old, dict) or not isinstance(new, dict):
        return False, ["consistency proof: needs both tree heads"]

    errors: list[str] = []
    for label, head in (("earlier", old), ("current", new)):
        ok, head_errors = verify_tree_head(signer, head)
        if not ok:
            errors.extend(f"{label} {e}" for e in head_errors)
    if errors:
        return False, errors

    path = _decode_path(proof)
    if path is None:
        return False, ["consistency proof: path is not a list of 32-byte hashes"]
    try:
        old_root = bytes.fromhex(str(old["root_hash"]))
        new_root = bytes.fromhex(str(new["root_hash"]))
    except ValueError:
        return False, ["consistency proof: a root_hash is not hex"]

    if old["tree_size"] > new["tree_size"]:
        return False, [
            f"consistency proof: the earlier head covers {old['tree_size']} records "
            f"but the current one covers {new['tree_size']}: history truncated"]
    if not verify_consistency(old["tree_size"], new["tree_size"],
                              old_root, new_root, path):
        return False, ["consistency proof: the current log does not extend the earlier one"]
    return True, []


def scheme_of(proof: dict[str, Any]) -> str | None:
    if not isinstance(proof, dict):
        return None
    for candidate in (proof, proof.get("tree_head"), proof.get("new_tree_head"),
                      proof.get("old_tree_head")):
        if isinstance(candidate, dict) and isinstance(candidate.get("scheme"), str):
            return candidate["scheme"]
    return None


def load_proof(path: str) -> dict[str, Any]:
    payload = loads_strict(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("proof file must contain a JSON object")
    return payload


def prefix_root(chain: HashChain, size: int) -> str:
    if not 0 <= size <= len(chain.chain):
        raise ValueError(f"cannot take a prefix of {size} from {len(chain.chain)} records")
    leaves = [leaf_hash(compute_block_hash(n.index, n.timestamp, n.data, n.prev_hash))
              for n in chain.chain[:size]]
    return MerkleTree(leaves).root_hex()
