import json
import os
from pathlib import Path
from typing import Any

STATE_SCHEMA = 1


def load_drift_state(path: str | Path) -> dict[str, Any] | None:
    state_path = Path(path)
    if not state_path.exists():
        return None
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != STATE_SCHEMA:
        return None
    return payload


def save_drift_state(path: str | Path, state: dict[str, Any]) -> None:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(state, schema=STATE_SCHEMA)
    tmp = state_path.with_name(state_path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, separators=(",", ":"), sort_keys=True, allow_nan=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, state_path)
