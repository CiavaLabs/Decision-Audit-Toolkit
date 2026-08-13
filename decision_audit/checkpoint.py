import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .chain import HashChain
from .proofs import prefix_root
from .utils import canonical_json, loads_strict


def build_checkpoint(chain: HashChain, signer,
                     clock: Callable[[], float] = time.time) -> dict[str, Any]:
    if not chain.chain:
        raise ValueError("cannot checkpoint an empty chain")
    head = chain.chain[-1]
    tree_size, root_hash = chain.tree_head()
    statement = {
        "type": "checkpoint",
        "head_index": head.index,
        "head_hash": head.hash,
        "blocks": len(chain.chain),
        "tree_size": tree_size,
        "root_hash": root_hash,
        "scheme": signer.scheme,
        "timestamp": clock()
    }
    signature = signer.sign(canonical_json(statement).encode())
    return dict(statement, signature=signature.hex())

def verify_checkpoint(chain: HashChain, signer,
                      checkpoint: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    chain_valid, chain_errors = chain.verify_integrity()
    if not chain_valid:
        errors.append("the stored chain does not verify, so a checkpoint "
                      f"comparison cannot mean anything: {chain_errors[0]}")

    statement = {k: v for k, v in checkpoint.items() if k != "signature"}
    try:
        signature = bytes.fromhex(str(checkpoint.get("signature", "")))
    except ValueError:
        signature = b""
    if not signer.can_verify():
        errors.append("verification key not found: checkpoint signature cannot be verified")
    elif not signature or not signer.verify(canonical_json(statement).encode(), signature):
        errors.append("checkpoint signature invalid")

    head_index = checkpoint.get("head_index")
    head_hash = checkpoint.get("head_hash")
    if (not isinstance(head_index, int) or isinstance(head_index, bool)
            or head_index < 0 or not isinstance(head_hash, str)):
        errors.append("malformed checkpoint: head_index/head_hash missing or invalid")
        return False, errors, warnings

    blocks = checkpoint.get("blocks")
    if isinstance(blocks, int) and not isinstance(blocks, bool) and len(chain.chain) < blocks:
        errors.append(
            f"chain has {len(chain.chain)} blocks but the checkpoint recorded "
            f"{blocks}: history truncated")
    elif head_index >= len(chain.chain):
        errors.append(
            f"chain has {len(chain.chain)} blocks but the checkpoint references "
            f"index {head_index}: history truncated or diverged")
    elif chain.chain[head_index].hash != head_hash:
        errors.append(
            f"block {head_index} hash differs from the checkpoint: history rewritten")

    checkpointed_root = checkpoint.get("root_hash")
    tree_size = checkpoint.get("tree_size")
    if isinstance(checkpointed_root, str) and isinstance(tree_size, int) \
            and not isinstance(tree_size, bool):
        if tree_size < 0:
            errors.append(f"malformed checkpoint: tree_size {tree_size} is negative")
        elif tree_size > len(chain.chain):
            errors.append(
                f"checkpoint covers {tree_size} records but the log has "
                f"{len(chain.chain)}: history truncated")
        elif prefix_root(chain, tree_size) != checkpointed_root:
            errors.append(
                f"the first {tree_size} records no longer match the checkpointed "
                "Merkle root: history rewritten")
    else:
        warnings.append(
            "checkpoint carries no Merkle root: only its head block was checked, "
            "not the history behind it (re-issue it to get the stronger check)")

    return len(errors) == 0, errors, warnings

def load_checkpoint(path: str) -> dict[str, Any]:
    payload = loads_strict(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("checkpoint file must contain a JSON object")
    return payload
