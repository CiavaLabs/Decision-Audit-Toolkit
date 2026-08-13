import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path


def _default_banded_fields() -> dict[str, float]:
    return {
        "loan_amount": 10_000.0,
        "property_value": 10_000.0,
        "monthly_income": 500.0,
        "monthly_debt": 500.0,
    }

@dataclass
class Config:
    drift_window_size: int = 50
    drift_threshold: float = 3.0
    drift_min_test_samples: int = 10

    banded_fields: dict[str, float] = field(default_factory=_default_banded_fields)
    clear_fields: Sequence[str] = ("period", "segment", "marginal_var", "var_limit")

    decision_fields: Sequence[str] = ("decision", "score", "confidence", "reasons")

    signature_scheme: str = "ed25519"

    state_dir: str = "audit_state"
    key_path: str | None = None
    public_key_path: str | None = None
    chain_path: str | None = None
    drift_state_path: str | None = None
    persist_drift_state: bool = True

    policy_profile: str = "financial_basic"
    policy_config_path: str | None = None

    aggregate_profile: str = "financial_basic"
    aggregate_config_path: str | None = None

    fairness_min_group_size: int = 30

    clock: Callable[[], float] = time.time

    def resolved_key_path(self, scheme: str | None = None) -> str:
        scheme = scheme or self.signature_scheme
        name = "hmac_key.bin" if scheme == "hmac" else "ed25519_key.bin"
        return self.key_path or str(Path(self.state_dir) / name)

    def resolved_public_key_path(self, scheme: str | None = None) -> str | None:
        scheme = scheme or self.signature_scheme
        if scheme == "hmac":
            return None
        return self.public_key_path or str(Path(self.state_dir) / "ed25519_key.pub")

    def resolved_chain_path(self) -> str:
        return self.chain_path or str(Path(self.state_dir) / "chain.jsonl")

    def resolved_drift_state_path(self) -> str:
        return self.drift_state_path or str(Path(self.state_dir) / "drift_state.json")
