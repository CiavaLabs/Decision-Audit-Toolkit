import math
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from typing import Any


class ContextRedactor:
    def __init__(self, banded_fields: Mapping[str, float], clear_fields: Sequence[str]):
        self.banded_fields = dict(banded_fields)
        self.clear_fields = set(clear_fields)

    def redact(self, context: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
        kept: dict[str, Any] = {}
        dropped: list[str] = []
        errors: list[str] = []
        for key, value in context.items():
            if key in self.banded_fields:
                try:
                    kept[key] = self.band_value(float(value), self.banded_fields[key])
                except (TypeError, ValueError):
                    dropped.append(key)
                    errors.append(
                        f"{key}: not a bandable number "
                        f"(got {type(value).__name__})")
            elif key in self.clear_fields:
                kept[key] = value
            else:
                dropped.append(key)
        return kept, sorted(dropped), errors

    @staticmethod
    def select(payload: Mapping[str, Any],
               allowed: Sequence[str]) -> tuple[dict[str, Any], list[str]]:
        allowed_set = set(allowed)
        kept = {k: v for k, v in payload.items() if k in allowed_set}
        dropped = sorted(k for k in payload if k not in allowed_set)
        return kept, dropped

    @staticmethod
    def band_value(value: float, band: float) -> float:
        if band <= 0:
            return value
        if not math.isfinite(value):
            raise ValueError("cannot band a non-finite value")
        try:
            quotient = Decimal(str(value)) / Decimal(str(band))
            return float(math.floor(quotient) * Decimal(str(band)))
        except (InvalidOperation, OverflowError):
            return math.floor(value / band) * band
