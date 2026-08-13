from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .utils import loads_strict


class MissingField(KeyError):
    pass

def _required(ctx: dict[str, Any], field: str) -> float:
    if field not in ctx:
        raise MissingField(f"context field '{field}' is missing")
    return float(ctx[field])

def _optional(ctx: dict[str, Any], field: str, default: float) -> float:
    return float(ctx[field]) if field in ctx else default

class ConstraintChecker:
    @dataclass
    class Constraint:
        id: str
        check_fn: Callable[[dict[str, Any]], bool]
        severity: str
        description: str

    def __init__(self) -> None:
        self.constraints: dict[str, ConstraintChecker.Constraint] = {}

    def add_constraint(self, constraint: 'ConstraintChecker.Constraint') -> None:
        self.constraints[constraint.id] = constraint

    def check(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(context, dict):
            raise ValueError("context must be an object")
        violations: list[dict[str, Any]] = []
        for c in self.constraints.values():
            try:
                if not c.check_fn(context):
                    violations.append({"id": c.id, "severity": c.severity, "description": c.description})
            except MissingField as e:
                violations.append({"id": c.id, "severity": "error",
                                   "description": f"Not evaluated: {e.args[0]}"})
            except (KeyError, TypeError, ValueError, ZeroDivisionError) as e:
                violations.append({"id": c.id, "severity": "error", "description": f"Check failed: {e}"})
        return violations

def _spec_error(exc: Exception) -> str:
    if isinstance(exc, KeyError) and exc.args:
        return f"missing {exc.args[0]!r}"
    return str(exc)

def build_constraints_from_specs(specs: Sequence[dict[str, Any]]) -> ConstraintChecker:
    checker = ConstraintChecker()
    for spec in specs:
        if not isinstance(spec, dict):
            raise ValueError(
                f"every constraint rule must be an object, got {type(spec).__name__}")
        if "id" not in spec:
            raise ValueError("every constraint needs an 'id'")
        try:
            check_fn = _constraint_fn_from_spec(spec)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"constraint '{spec['id']}': {_spec_error(exc)}") from exc
        checker.add_constraint(ConstraintChecker.Constraint(
            id=spec["id"],
            severity=spec.get("severity", "info"),
            description=spec.get("description", ""),
            check_fn=check_fn
        ))
    return checker

CheckFn = Callable[[dict[str, Any]], bool]
Builder = Callable[[dict[str, Any]], CheckFn]


def _build_ratio_max(spec: dict[str, Any]) -> CheckFn:
    numerator = spec["numerator"]
    denominator = spec["denominator"]
    limit = float(spec["max"])
    min_denominator = float(spec.get("min_denominator", 1.0))
    def check_fn(ctx: dict[str, Any]) -> bool:
        denom = max(_required(ctx, denominator), min_denominator)
        num = _required(ctx, numerator)
        return (num / denom) <= limit
    return check_fn


def _build_ratio_min(spec: dict[str, Any]) -> CheckFn:
    numerator = spec["numerator"]
    denominator = spec["denominator"]
    floor = float(spec["min"])
    min_denominator = float(spec.get("min_denominator", 1.0))
    def check_fn(ctx: dict[str, Any]) -> bool:
        denom = max(_required(ctx, denominator), min_denominator)
        return (_required(ctx, numerator) / denom) >= floor
    return check_fn


def _build_lte_field(spec: dict[str, Any]) -> CheckFn:
    field = spec["field"]
    other = spec["other_field"]
    fallback = float(spec.get("other_default", float("inf")))
    def check_fn(ctx: dict[str, Any]) -> bool:
        return _required(ctx, field) <= _optional(ctx, other, fallback)
    return check_fn


def _build_positive(spec: dict[str, Any]) -> CheckFn:
    fields = list(spec["fields"])
    if not fields:
        raise ValueError("'positive' needs a non-empty 'fields' list")
    def check_fn(ctx: dict[str, Any]) -> bool:
        return all(_required(ctx, f) > 0 for f in fields)
    return check_fn


def _build_value_max(spec: dict[str, Any]) -> CheckFn:
    field = spec["field"]
    limit = float(spec["max"])
    def check_fn(ctx: dict[str, Any]) -> bool:
        return _required(ctx, field) <= limit
    return check_fn


def _build_value_min(spec: dict[str, Any]) -> CheckFn:
    field = spec["field"]
    floor = float(spec["min"])
    def check_fn(ctx: dict[str, Any]) -> bool:
        return _required(ctx, field) >= floor
    return check_fn


def _build_in_set(spec: dict[str, Any]) -> CheckFn:
    field = spec["field"]
    allowed = set(spec["values"])
    def check_fn(ctx: dict[str, Any]) -> bool:
        if field not in ctx:
            raise MissingField(f"context field '{field}' is missing")
        return ctx[field] in allowed
    return check_fn


def _subrules(spec: dict[str, Any]) -> list[CheckFn]:
    rules = spec.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError(f"'{spec.get('type')}' needs a non-empty 'rules' list")
    return [_constraint_fn_from_spec(rule) for rule in rules]


def _build_all_of(spec: dict[str, Any]) -> CheckFn:
    subs = _subrules(spec)
    def check_fn(ctx: dict[str, Any]) -> bool:
        unevaluated: list[MissingField] = []
        for sub in subs:
            try:
                if not sub(ctx):
                    return False
            except MissingField as exc:
                unevaluated.append(exc)
        if unevaluated:
            raise unevaluated[0]
        return True
    return check_fn


def _build_any_of(spec: dict[str, Any]) -> CheckFn:
    subs = _subrules(spec)
    def check_fn(ctx: dict[str, Any]) -> bool:
        unevaluated: list[MissingField] = []
        for sub in subs:
            try:
                if sub(ctx):
                    return True
            except MissingField as exc:
                unevaluated.append(exc)
        if unevaluated:
            raise unevaluated[0]
        return False
    return check_fn


def _build_not(spec: dict[str, Any]) -> CheckFn:
    rule = spec.get("rule")
    if not isinstance(rule, dict):
        raise ValueError("'not' needs a single 'rule' object")
    inner = _constraint_fn_from_spec(rule)
    def check_fn(ctx: dict[str, Any]) -> bool:
        return not inner(ctx)
    return check_fn


CONSTRAINT_TYPES: dict[str, Builder] = {
    "ratio_max": _build_ratio_max,
    "ratio_min": _build_ratio_min,
    "lte_field": _build_lte_field,
    "positive": _build_positive,
    "value_max": _build_value_max,
    "value_min": _build_value_min,
    "in_set": _build_in_set,
    "all_of": _build_all_of,
    "any_of": _build_any_of,
    "not": _build_not,
}


def register_constraint_type(name: str, builder: Builder) -> None:
    CONSTRAINT_TYPES[name] = builder


def available_constraint_types() -> list[str]:
    return sorted(CONSTRAINT_TYPES)


def _constraint_fn_from_spec(spec: dict[str, Any]) -> CheckFn:
    if not isinstance(spec, dict):
        raise ValueError(f"every constraint rule must be an object, got {type(spec).__name__}")
    ctype = spec.get("type")
    builder = CONSTRAINT_TYPES.get(ctype) if isinstance(ctype, str) else None
    if builder is None:
        raise ValueError(
            f"Unsupported constraint type: {ctype}; expected one of "
            f"{', '.join(available_constraint_types())}")
    return builder(spec)

def load_constraints_from_json(path: str) -> ConstraintChecker:
    payload = loads_strict(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        specs = payload.get("constraints", [])
    else:
        specs = payload
    if not isinstance(specs, list):
        raise ValueError("Constraint definition must be a list or wrap a 'constraints' key")
    return build_constraints_from_specs(specs)

DEFAULT_FINANCIAL_CONSTRAINTS: list[dict[str, Any]] = [
    {
        "id": "ltv_limit",
        "type": "ratio_max",
        "numerator": "loan_amount",
        "denominator": "property_value",
        "max": 0.8,
        "severity": "high",
        "description": "Loan-to-value ratio must be <= 80%"
    },
    {
        "id": "dsr_limit",
        "type": "ratio_max",
        "numerator": "monthly_debt",
        "denominator": "monthly_income",
        "max": 0.35,
        "severity": "high",
        "description": "Debt service ratio must be <= 35%"
    },
    {
        "id": "var_limit",
        "type": "lte_field",
        "field": "marginal_var",
        "other_field": "var_limit",
        "other_default": 1.0,
        "severity": "critical",
        "description": "VaR must be within limit"
    },
    {
        "id": "positive_amounts",
        "type": "positive",
        "fields": ["loan_amount","property_value","monthly_income"],
        "severity": "critical",
        "description": "All amounts must be positive"
    }
]

def setup_financial_constraints() -> ConstraintChecker:
    return build_constraints_from_specs(DEFAULT_FINANCIAL_CONSTRAINTS)

STRICT_FINANCIAL_CONSTRAINTS: list[dict[str, Any]] = [
    {
        "id": "ltv_limit_strict",
        "type": "ratio_max",
        "numerator": "loan_amount",
        "denominator": "property_value",
        "max": 0.7,
        "severity": "critical",
        "description": "Strict LTV: <= 70%"
    },
    {
        "id": "dsr_limit_strict",
        "type": "ratio_max",
        "numerator": "monthly_debt",
        "denominator": "monthly_income",
        "max": 0.3,
        "severity": "critical",
        "description": "Strict DSR: <= 30%"
    },
    {
        "id": "var_limit_strict",
        "type": "lte_field",
        "field": "marginal_var",
        "other_field": "var_limit",
        "other_default": 0.9,
        "severity": "critical",
        "description": "Strict VaR limit"
    },
    {
        "id": "min_income",
        "type": "value_min",
        "field": "monthly_income",
        "min": 2500,
        "severity": "high",
        "description": "Borrower must earn >= 2.5k per month"
    },
    {
        "id": "positive_amounts",
        "type": "positive",
        "fields": ["loan_amount","property_value","monthly_income"],
        "severity": "critical",
        "description": "All amounts must be positive"
    }
]

def setup_financial_strict_constraints() -> ConstraintChecker:
    return build_constraints_from_specs(STRICT_FINANCIAL_CONSTRAINTS)

POLICY_REGISTRY: dict[str, Callable[[], ConstraintChecker]] = {}

def register_policy_profile(name: str, builder: Callable[[], ConstraintChecker]) -> None:
    POLICY_REGISTRY[name] = builder

def get_policy_profile(name: str) -> ConstraintChecker:
    if name not in POLICY_REGISTRY:
        raise ValueError(f"Unknown policy profile '{name}'")
    return POLICY_REGISTRY[name]()

register_policy_profile("financial_basic", setup_financial_constraints)
register_policy_profile("financial_strict", setup_financial_strict_constraints)
