import math
from collections import defaultdict
from typing import Any

Z_95 = 1.959963984540054

DEFAULT_MIN_GROUP_SIZE = 30


def wilson_interval(successes: int, total: int, z: float = Z_95) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 1.0
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = (z / denominator) * math.sqrt(p * (1 - p) / total
                                           + z * z / (4 * total * total))
    return max(0.0, centre - margin), min(1.0, centre + margin)


class FairnessAccumulator:
    def __init__(self, attribute: str = "segment",
                 min_group_size: int = DEFAULT_MIN_GROUP_SIZE):
        self.attribute = attribute
        self.min_group_size = min_group_size
        self._members: dict[str, int] = defaultdict(int)
        self._model_approvals: dict[str, int] = defaultdict(int)
        self._final_approvals: dict[str, int] = defaultdict(int)
        self._policy_overrides: dict[str, int] = defaultdict(int)
        self._violations: dict[str, int] = defaultdict(int)
        self._scores_sum: dict[str, float] = defaultdict(float)
        self._scores_count: dict[str, int] = defaultdict(int)

    def _group_of(self, data: dict[str, Any]) -> str | None:
        for source in (data, data.get("context")):
            if not isinstance(source, dict):
                continue
            label = source.get(self.attribute)
            if label is not None and label != "":
                return label if isinstance(label, str) else str(label)
        return None

    def add(self, data: dict[str, Any]) -> None:
        group = self._group_of(data)
        if group is None:
            return
        self._members[group] += 1
        model_decision = data.get("model_decision")
        if model_decision == "APPROVE":
            self._model_approvals[group] += 1
        if data.get("final_outcome") == "APPROVE":
            self._final_approvals[group] += 1
        if data.get("policy_blocked"):
            self._violations[group] += 1
            if model_decision == "APPROVE":
                self._policy_overrides[group] += 1
        score = data.get("model_score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            self._scores_sum[group] += float(score)
            self._scores_count[group] += 1

    def result(self) -> dict[str, Any]:
        metrics: dict[str, Any] = {}
        for group, count in self._members.items():
            approvals = self._model_approvals.get(group, 0)
            final = self._final_approvals.get(group, 0)
            scored = self._scores_count.get(group, 0)
            low, high = wilson_interval(final, count)
            metrics[group] = {
                "count": count,
                "model_approval_rate": round(approvals / count, 4),
                "final_approval_rate": round(final / count, 4),
                "final_approval_ci95": [round(low, 4), round(high, 4)],
                "violation_rate": round(self._violations.get(group, 0) / count, 4),
                "policy_override_rate": (
                    round(self._policy_overrides.get(group, 0) / approvals, 4)
                    if approvals else 0.0),
                "avg_model_score": (round(self._scores_sum.get(group, 0.0) / scored, 4)
                                    if scored else None),
                "sufficient_data": count >= self.min_group_size,
            }

        compared = {g: m for g, m in metrics.items() if m["sufficient_data"]}
        excluded = sorted(g for g in metrics if g not in compared)
        approval_span: float | None = None
        approval_ratio: float | None = None
        if len(compared) >= 2:
            rates = [m["final_approval_rate"] for m in compared.values()]
            approval_span = round(max(rates) - min(rates), 4)
            if max(rates) > 0:
                approval_ratio = round(min(rates) / max(rates), 4)

        return {
            "attribute": self.attribute,
            "groups": metrics,
            "approval_span": approval_span,
            "approval_ratio": approval_ratio,
            "min_group_size": self.min_group_size,
            "compared_groups": sorted(compared),
            "excluded_groups": excluded,
        }
