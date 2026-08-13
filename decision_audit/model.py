from dataclasses import dataclass


@dataclass
class ModelOutput:
    decision: str
    score: float
    reasons: list[str]

def _safe_ratio(numerator: float, denominator: float, default: float = 0.0) -> float:
    if denominator <= 0:
        return default
    return numerator / denominator

def mortgage_risk_model(context: dict[str, float]) -> ModelOutput:
    loan_amount = float(context.get("loan_amount", 0.0))
    property_value = float(context.get("property_value", 1.0))
    monthly_debt = float(context.get("monthly_debt", 0.0))
    monthly_income = float(context.get("monthly_income", 1.0))
    marginal_var = float(context.get("marginal_var", 0.0))
    var_limit = float(context.get("var_limit", 1.0))

    ltv = min(_safe_ratio(loan_amount, property_value, 0.0), 2.0)
    dsr = min(_safe_ratio(monthly_debt, monthly_income, 0.0), 2.0)
    var_ratio = min(_safe_ratio(marginal_var, var_limit, 0.0), 2.0)

    buckets: list[tuple[str, float]] = []

    if ltv > 0.9:
        buckets.append(("LTV > 90%", 0.45))
    elif ltv > 0.8:
        buckets.append(("LTV 80-90%", 0.35))
    elif ltv > 0.7:
        buckets.append(("LTV 70-80%", 0.25))
    else:
        buckets.append(("LTV <= 70%", 0.15))

    if dsr > 0.4:
        buckets.append(("DSR > 40%", 0.35))
    elif dsr > 0.35:
        buckets.append(("DSR 35-40%", 0.3))
    elif dsr > 0.25:
        buckets.append(("DSR 25-35%", 0.2))
    else:
        buckets.append(("DSR <= 25%", 0.1))

    if var_ratio > 1.0:
        buckets.append(("VaR ratio > 1.0", 0.25))
    elif var_ratio > 0.8:
        buckets.append(("VaR ratio 0.8-1.0", 0.2))
    else:
        buckets.append(("VaR ratio <= 0.8", 0.1))

    if monthly_income < 2500:
        buckets.append(("Income < 2.5k", 0.15))
    elif monthly_income < 3500:
        buckets.append(("Income 2.5k-3.5k", 0.1))
    else:
        buckets.append(("Income >= 3.5k", 0.05))

    risk_score = sum(weight for _, weight in buckets)
    risk_score = round(min(max(risk_score, 0.0), 1.5), 3)

    if risk_score < 0.6:
        decision = "APPROVE"
    elif risk_score < 0.85:
        decision = "REVIEW"
    else:
        decision = "REJECT"

    reasons = [label for label, _ in buckets]
    return ModelOutput(decision=decision, score=risk_score, reasons=reasons)
