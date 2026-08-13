import json


def canonical_json(obj) -> str:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
    except ValueError as exc:
        raise ValueError(f"value cannot be represented in JSON: {exc}") from exc


def _reject_constant(name: str):
    raise ValueError(f"{name} is not valid JSON (RFC 8259)")


def loads_strict(text: str | bytes):
    return json.loads(text, parse_constant=_reject_constant)
