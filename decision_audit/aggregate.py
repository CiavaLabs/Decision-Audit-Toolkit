from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, NamedTuple

from .utils import loads_strict

NOT_EVALUATED = "not_evaluated"

Summary = dict[str, Any]
Spec = dict[str, Any]
Finding = dict[str, Any]


def _finding(spec: dict[str, Any], observed: Any, threshold: Any,
             detail: str) -> Finding:
    return {
        "id": spec["id"],
        "severity": spec.get("severity", "info"),
        "description": spec.get("description", ""),
        "observed": observed,
        "threshold": threshold,
        "detail": detail,
    }


def _not_evaluated(spec: dict[str, Any], why: str) -> Finding:
    return {
        "id": spec["id"],
        "severity": NOT_EVALUATED,
        "description": spec.get("description", ""),
        "observed": None,
        "threshold": None,
        "detail": why,
    }


def _rate(numerator: Any, denominator: Any) -> float | None:
    if not isinstance(numerator, (int, float)) or not isinstance(denominator, (int, float)):
        return None
    if not denominator:
        return None
    return numerator / denominator


def _fairness_basis(summary: Summary, spec: Spec) -> dict[str, Any]:
    fairness = summary.get("fairness")
    groups = fairness.get("groups") if isinstance(fairness, dict) else None
    if not isinstance(groups, dict):
        return {}
    members = {g: m for g, m in groups.items() if isinstance(m, dict)}
    minimum = spec.get("min_group_size")
    if minimum is None:
        return {g: m for g, m in members.items() if m.get("sufficient_data")}
    return {g: m for g, m in members.items()
            if isinstance(m.get("count"), int) and m["count"] >= minimum}


def _check_max_approval_span(spec: Spec, summary: Summary) -> Finding | None:
    eligible = _fairness_basis(summary, spec)
    if len(eligible) < 2:
        return _not_evaluated(spec, f"needs two comparable groups, found {len(eligible)}")
    rates = [m["final_approval_rate"] for m in eligible.values()]
    span = round(max(rates) - min(rates), 4)
    limit = float(spec["max"])
    if span > limit:
        return _finding(spec, span, limit,
                        f"approval rates across {len(eligible)} groups span {span:.1%}, "
                        f"above the {limit:.1%} limit")
    return None


def _check_min_approval_ratio(spec: Spec, summary: Summary) -> Finding | None:
    eligible = _fairness_basis(summary, spec)
    if len(eligible) < 2:
        return _not_evaluated(spec, f"needs two comparable groups, found {len(eligible)}")
    rates = [m["final_approval_rate"] for m in eligible.values()]
    if max(rates) <= 0:
        return _not_evaluated(spec, "no group approved anything, so there is no ratio")
    ratio = round(min(rates) / max(rates), 4)
    floor = float(spec["min"])
    if ratio < floor:
        return _finding(spec, ratio, floor,
                        f"the least-approved group runs at {ratio:.1%} of the "
                        f"most-approved, below the {floor:.1%} floor")
    return None


def _check_max_override_rate_gap(spec: Spec, summary: Summary) -> Finding | None:
    eligible = _fairness_basis(summary, spec)
    if len(eligible) < 2:
        return _not_evaluated(spec, f"needs two comparable groups, found {len(eligible)}")
    rates = [m["policy_override_rate"] for m in eligible.values()]
    gap = round(max(rates) - min(rates), 4)
    limit = float(spec["max"])
    if gap > limit:
        return _finding(spec, gap, limit,
                        f"policy reverses approvals at rates {gap:.1%} apart across "
                        f"groups, above the {limit:.1%} limit")
    return None


def _ratio_rule(field: str, label: str) -> Callable[[Spec, Summary], Finding | None]:
    def check(spec: Spec, summary: Summary) -> Finding | None:
        rate = _rate(summary.get(field), summary.get("audits"))
        if rate is None:
            return _not_evaluated(spec, f"no '{field}' count over a non-zero audit count")
        rate = round(rate, 4)
        limit = float(spec["max"])
        if rate > limit:
            return _finding(spec, rate, limit,
                            f"{label} on {rate:.1%} of decisions, above the "
                            f"{limit:.1%} limit")
        return None
    return check


class RuleType(NamedTuple):
    check: Callable[[Spec, Summary], Finding | None]
    thresholds: tuple[str, ...] = ()


_RULE_TYPES: dict[str, RuleType] = {
    "max_approval_span": RuleType(_check_max_approval_span, ("max",)),
    "min_approval_ratio": RuleType(_check_min_approval_ratio, ("min",)),
    "max_override_rate_gap": RuleType(_check_max_override_rate_gap, ("max",)),
    "max_violation_rate": RuleType(
        _ratio_rule("with_violations", "policy violations"), ("max",)),
    "max_anomaly_rate": RuleType(
        _ratio_rule("with_anomaly", "drift alerts"), ("max",)),
    "max_degraded_rate": RuleType(
        _ratio_rule("degraded", "records the toolkit could not fully evaluate"),
        ("max",)),
}


def register_aggregate_rule(name: str, check: Callable[[Spec, Summary], Finding | None],
                            thresholds: Sequence[str] = ()) -> None:
    _RULE_TYPES[name] = RuleType(check, tuple(thresholds))


def available_rule_types() -> list[str]:
    return sorted(_RULE_TYPES)


class AggregatePolicy:
    def __init__(self, specs: Sequence[dict[str, Any]]):
        self.specs: list[dict[str, Any]] = []
        for spec in specs:
            if not isinstance(spec, dict):
                raise ValueError("every aggregate rule must be an object")
            if "id" not in spec:
                raise ValueError("every aggregate rule needs an 'id'")
            declared = spec.get("type")
            rule_type = _RULE_TYPES.get(declared) if isinstance(declared, str) else None
            if rule_type is None:
                raise ValueError(
                    f"rule '{spec['id']}': unsupported type {spec.get('type')!r}; "
                    f"expected one of {', '.join(available_rule_types())}")
            for key in rule_type.thresholds:
                if key not in spec:
                    raise ValueError(
                        f"rule '{spec['id']}' of type '{spec['type']}' needs a "
                        f"'{key}' threshold")
                value = spec[key]
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(
                        f"rule '{spec['id']}': '{key}' must be a number, got "
                        f"{type(value).__name__}")
            minimum = spec.get("min_group_size")
            if minimum is not None and (isinstance(minimum, bool)
                                        or not isinstance(minimum, int)):
                raise ValueError(
                    f"rule '{spec['id']}': 'min_group_size' must be an integer")
            self.specs.append(dict(spec))

    def check(self, summary: Summary) -> list[Finding]:
        findings: list[Finding] = []
        for spec in self.specs:
            try:
                result = _RULE_TYPES[spec["type"]].check(spec, summary)
            except (KeyError, TypeError, ValueError) as exc:
                result = _not_evaluated(spec, f"rule could not be applied: {exc}")
            if result is not None:
                findings.append(result)
        return findings

    def evaluate(self, summary: dict[str, Any]) -> dict[str, Any]:
        findings = self.check(summary)
        breaches = [f for f in findings if f["severity"] != NOT_EVALUATED]
        not_evaluated = [f for f in findings if f["severity"] == NOT_EVALUATED]
        return {
            "rules": len(self.specs),
            "passed": not breaches,
            "complete": not not_evaluated,
            "breaches": breaches,
            "not_evaluated": not_evaluated,
        }


DEFAULT_AGGREGATE_RULES: list[dict[str, Any]] = [
    {
        "id": "approval_span",
        "type": "max_approval_span",
        "max": 0.2,
        "severity": "high",
        "description": "Final approval rates must not differ by more than 20 points across segments",
    },
    {
        "id": "four_fifths",
        "type": "min_approval_ratio",
        "min": 0.8,
        "severity": "critical",
        "description": "The least-approved segment must reach 80% of the most-approved rate",
    },
    {
        "id": "drift_rate",
        "type": "max_anomaly_rate",
        "max": 0.05,
        "severity": "medium",
        "description": "No more than 5% of decisions may carry a drift alert",
    },
    {
        "id": "unevaluated_rate",
        "type": "max_degraded_rate",
        "max": 0.01,
        "severity": "high",
        "description": "No more than 1% of decisions may be logged as degraded",
    },
]

AGGREGATE_REGISTRY: dict[str, Callable[[], AggregatePolicy]] = {
    "financial_basic": lambda: AggregatePolicy(DEFAULT_AGGREGATE_RULES),
}


def register_aggregate_profile(name: str, builder: Callable[[], AggregatePolicy]) -> None:
    AGGREGATE_REGISTRY[name] = builder


def get_aggregate_profile(name: str) -> AggregatePolicy:
    if name not in AGGREGATE_REGISTRY:
        raise ValueError(
            f"Unknown aggregate policy profile '{name}'; expected one of "
            f"{', '.join(sorted(AGGREGATE_REGISTRY))}")
    return AGGREGATE_REGISTRY[name]()


def load_aggregate_policy_from_json(path: str) -> AggregatePolicy:
    payload = loads_strict(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        specs = payload.get("aggregate_rules", [])
    else:
        specs = payload
    if not isinstance(specs, list):
        raise ValueError(
            "Aggregate policy must be a list or wrap an 'aggregate_rules' key")
    return AggregatePolicy(specs)


def aggregate_policy_for(profile: str, config_path: str | None) -> AggregatePolicy:
    if config_path:
        return load_aggregate_policy_from_json(config_path)
    return get_aggregate_profile(profile)
