import math
from collections import deque
from collections.abc import Sequence
from typing import Any

from .config import Config

_ZERO_VARIANCE_SCORE = 1e6

def _as_vector(observation) -> list[float]:
    if isinstance(observation, (str, bytes)) or not isinstance(observation, Sequence):
        raise ValueError("features must be a list of numbers")
    values = []
    for item in observation:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError(f"features must be numbers, got {type(item).__name__}")
        value = float(item)
        if not math.isfinite(value):
            raise ValueError("features must be finite numbers")
        values.append(value)
    if not values:
        raise ValueError("features must not be empty")
    return values

class MeanShiftDriftDetector:
    def __init__(self, config: Config):
        self.window_size = config.drift_window_size
        self.threshold = config.drift_threshold
        self.min_test_samples = max(2, config.drift_min_test_samples)
        if self.window_size < self.min_test_samples:
            raise ValueError(
                f"drift_window_size ({self.window_size}) is below the minimum test "
                f"sample count ({self.min_test_samples}): the test window could "
                "never fill, so drift would never be evaluated")
        self.reference_window: deque[list[float]] = deque(maxlen=self.window_size)
        self.test_window: deque[list[float]] = deque(maxlen=self.window_size)
        self.n_features: int | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "reference": [list(row) for row in self.reference_window],
            "test": [list(row) for row in self.test_window],
            "n_features": self.n_features,
            "window_size": self.window_size,
            "min_test_samples": self.min_test_samples,
        }

    def restore(self, state: dict[str, Any]) -> None:
        self.reference_window = deque(state["reference"], maxlen=self.window_size)
        self.test_window = deque(state["test"], maxlen=self.window_size)
        self.n_features = state["n_features"]

    def load_state(self, state: dict[str, Any]) -> str | None:
        if not isinstance(state, dict):
            return "drift state file is not an object"
        for key in ("reference", "test"):
            rows = state.get(key)
            if not isinstance(rows, list) or not all(isinstance(r, list) for r in rows):
                return f"drift state has no usable '{key}' window"
        if state.get("window_size") != self.window_size:
            return (f"drift state was recorded with window_size "
                    f"{state.get('window_size')}, now {self.window_size}")
        if state.get("min_test_samples") != self.min_test_samples:
            return (f"drift state was recorded with min_test_samples "
                    f"{state.get('min_test_samples')}, now {self.min_test_samples}")
        try:
            reference = [[float(v) for v in row] for row in state["reference"]]
            test = [[float(v) for v in row] for row in state["test"]]
        except (TypeError, ValueError):
            return "drift state windows are not numeric"

        widths = {len(row) for row in reference + test}
        if len(widths) > 1:
            return "drift state windows have inconsistent feature counts"
        if widths == {0}:
            return "drift state windows have no features"
        self.reference_window = deque(reference, maxlen=self.window_size)
        self.test_window = deque(test, maxlen=self.window_size)
        self.n_features = widths.pop() if widths else None
        return None

    def update(self, observation: Sequence[float]) -> dict[str, Any]:
        observation = _as_vector(observation)
        if self.n_features is None:
            self.n_features = len(observation)
        elif len(observation) != self.n_features:
            raise ValueError(f"Expected {self.n_features} features, got {len(observation)}")

        if len(self.reference_window) < self.window_size:
            self.reference_window.append(list(observation))
            return {"drift": False, "score": 0.0, "filling_reference": True}

        self.test_window.append(list(observation))
        if len(self.test_window) < self.min_test_samples:
            return {"drift": False, "score": 0.0, "filling_test": True}

        score = self._score(list(self.reference_window), list(self.test_window),
                            self.n_features)
        is_drift = score > self.threshold

        if is_drift and len(self.test_window) >= self.window_size:
            self.reference_window = deque(self.test_window, maxlen=self.window_size)
            self.test_window.clear()

        return {
            "drift": is_drift, "score": round(score, 3), "threshold": self.threshold,
            "n_obs_ref": len(self.reference_window), "n_obs_test": len(self.test_window)
        }

    def _score(self, ref: list[list[float]], test: list[list[float]],
               n_features: int) -> float:
        n, m = len(ref), len(test)
        total = 0.0
        for i in range(n_features):
            ref_vals = [row[i] for row in ref]
            test_vals = [row[i] for row in test]
            mean_ref = sum(ref_vals) / n
            mean_test = sum(test_vals) / m
            ss_ref = sum((v - mean_ref) ** 2 for v in ref_vals)
            ss_test = sum((v - mean_test) ** 2 for v in test_vals)
            var_pooled = (ss_ref + ss_test) / (n + m - 2)
            delta = mean_test - mean_ref
            if var_pooled > 0:
                z = delta / math.sqrt(var_pooled * (1 / n + 1 / m))
            else:
                z = 0.0 if delta == 0 else _ZERO_VARIANCE_SCORE
            total += z * z
        return math.sqrt(total / max(n_features, 1))
