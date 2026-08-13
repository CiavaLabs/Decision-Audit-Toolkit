import csv
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import Config
from .model import mortgage_risk_model
from .orchestrator import AuditOrchestrator
from .utils import loads_strict

DEFAULT_FIELD_MAP: dict[str, str] = {
    "loan_amount": "loan_amount",
    "property_value": "property_value",
    "monthly_debt": "monthly_debt",
    "monthly_income": "monthly_income",
    "marginal_var": "marginal_var",
    "var_limit": "var_limit",
    "period": "period",
    "segment": "segment",
}

FEATURE_FIELDS = ["loan_amount", "property_value", "monthly_debt", "monthly_income", "marginal_var"]

def _decide(context: dict[str, Any]) -> dict[str, Any]:
    out = mortgage_risk_model(context)
    return {"decision": out.decision, "score": out.score, "reasons": out.reasons}

def main(config: Config | None = None) -> None:
    print("=" * 70)
    print("DECISION AUDIT TOOLKIT - MORTGAGE DEMO")
    print("=" * 70)

    config = replace(config or Config(), drift_window_size=20,
                     drift_min_test_samples=5)
    orchestrator = AuditOrchestrator(config)

    print("\n[1] CLEAN MORTGAGE REQUEST")
    print("-" * 40)
    context1 = {
        "loan_amount": 150000,
        "property_value": 200000,
        "monthly_debt": 1000,
        "monthly_income": 6000,
        "marginal_var": 0.5,
        "var_limit": 1.0,
        "customer_note": "repeat customer",
        "period": "demo_clean",
        "segment": "prime"
    }
    context1["features"] = [context1[f] for f in FEATURE_FIELDS]
    decision1 = _decide(context1)
    result1 = orchestrator.audit_decision(decision1, context1)
    print(f"Audit id: {result1['audit_id']}")
    print(f"Model decision: {decision1['decision']} (score {decision1['score']})")
    print(f"Policy checks passed: {result1['constraints']['passed']}")
    print(f"Final outcome: {result1['final_outcome']}")
    print(f"Block hash: {result1['block_hash'][:16]}...")
    stored = orchestrator.chain.chain[-1].data
    print(f"Logged context (banded): {json.dumps(stored['context'], sort_keys=True)}")
    print(f"Dropped from log: {stored.get('redacted_fields', [])}")

    print("\n[2] STRESSED BORROWER - MODEL ITSELF REJECTS")
    print("-" * 40)
    context2 = {
        "loan_amount": 200000,
        "property_value": 210000,
        "monthly_debt": 3000,
        "monthly_income": 5000,
        "marginal_var": 1.5,
        "var_limit": 1.0,
        "period": "demo_stress",
        "segment": "near_prime"
    }
    context2["features"] = [context2[f] for f in FEATURE_FIELDS]
    decision2 = _decide(context2)
    result2 = orchestrator.audit_decision(decision2, context2)
    print(f"Model decision: {decision2['decision']} (score {decision2['score']})")
    print(f"Violations found: {len(result2['constraints']['violations'])}")
    for v in result2["constraints"]["violations"]:
        print(f"  - {v['id']}: {v['description']}")

    print("\n[3] MODEL APPROVES, POLICY BLOCKS")
    print("-" * 40)
    context3 = {
        "loan_amount": 120000,
        "property_value": 200000,
        "monthly_debt": 1200,
        "monthly_income": 6000,
        "marginal_var": 1.05,
        "var_limit": 1.0,
        "period": "demo_override",
        "segment": "prime"
    }
    context3["features"] = [context3[f] for f in FEATURE_FIELDS]
    decision3 = _decide(context3)
    result3 = orchestrator.audit_decision(decision3, context3)
    print(f"Model decision: {decision3['decision']} (score {decision3['score']})")
    for v in result3["constraints"]["violations"]:
        print(f"  - violated {v['id']}: {v['description']}")
    print(f"Final outcome: {result3['final_outcome']}")

    print("\n[4] PORTFOLIO DRIFT CHECK")
    print("-" * 40)
    drift_notified = False
    for i in range(30):
        context = {
            "loan_amount": 150000 + (i % 7) * 2000,
            "property_value": 200000 + (i % 5) * 3000,
            "monthly_debt": 1000 + (i % 4) * 50,
            "monthly_income": 6000 + (i % 6) * 100,
            "marginal_var": 0.5,
            "var_limit": 1.0,
            "period": "demo_ref",
            "segment": "prime"
        }
        context["features"] = [context[f] for f in FEATURE_FIELDS]
        orchestrator.audit_decision(_decide(context), context)
    for i in range(30):
        context = {
            "loan_amount": 300000 + (i % 7) * 2000,
            "property_value": 350000 + (i % 5) * 3000,
            "monthly_debt": 4000 + (i % 4) * 50,
            "monthly_income": 8000 + (i % 6) * 100,
            "marginal_var": 0.9,
            "var_limit": 1.0,
            "period": "demo_shift",
            "segment": "near_prime"
        }
        context["features"] = [context[f] for f in FEATURE_FIELDS]
        result = orchestrator.audit_decision(_decide(context), context)
        if result["drift"] and result["drift"].get("drift") and not drift_notified:
            print(f"Drift detected after {i + 1} shifted decisions")
            print(f"  Score: {result['drift']['score']:.2f} sigma > threshold {result['drift']['threshold']}")
            drift_notified = True
    if not drift_notified:
        print("No drift detected within the stress window.")

    print("\n[5] INTEGRITY VERIFICATION")
    print("-" * 40)
    integrity = orchestrator.verify_integrity()
    print(f"Chain integrity: {'VALID' if integrity['valid'] else 'INVALID'}")
    print(f"Audit records: {integrity['blocks']}")
    print(f"Drift anomalies recorded: {integrity['anomalies']}")
    if integrity["errors"]:
        print("Chain errors found:")
        for err in integrity["errors"]:
            print(f"  - {err}")

    print("\n" + "=" * 70)
    print("DEMO COMPLETE")
    print(f"Audit log: {config.resolved_chain_path()}")
    print(f"Signature scheme: {orchestrator.signer.scheme}")
    if orchestrator.signer.scheme == "ed25519":
        print("Verification needs only the public key "
              f"({config.resolved_public_key_path('ed25519')})")
    print("=" * 70)

def load_field_map(path: str | None) -> dict[str, str]:
    if not path:
        return dict(DEFAULT_FIELD_MAP)
    payload = loads_strict(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("field map must be a JSON object: {context_field: csv_column}")
    field_map = dict(DEFAULT_FIELD_MAP)
    field_map.update({str(k): str(v) for k, v in payload.items()})
    return field_map

def run_batch_from_csv(
    data_path: str = "data/sample_mortgages.csv",
    *,
    config: Config | None = None,
    silent: bool = False,
    field_map: dict[str, str] | None = None
) -> dict[str, Any]:
    path = Path(data_path)
    if not path.exists():
        raise ValueError(f"dataset '{data_path}' not found")
    field_map = field_map or dict(DEFAULT_FIELD_MAP)

    config = replace(config or Config(), drift_window_size=15,
                     drift_min_test_samples=5)
    orchestrator = AuditOrchestrator(config)
    processed = 0
    skipped = 0
    violations = 0
    periods_seen = set()
    last_period = None
    drift_details: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                context = _row_to_context(row, field_map)
            except ValueError as exc:
                skipped += 1
                if not silent:
                    print(f"Skipping row {row.get('id', '?')}: {exc}")
                continue
            period = context.get("period", "A")
            periods_seen.add(period)
            if not silent and period != last_period:
                print(f"\n=== Period {period} ===")
                last_period = period
            result = orchestrator.audit_decision(_decide(context), context)
            processed += 1
            violations += len(result["constraints"]["violations"])
            drift_info = result.get("drift")
            if drift_info and drift_info.get("drift"):
                details = {
                    "audit_id": result["audit_id"],
                    "period": period,
                    "score": drift_info.get("score"),
                    "threshold": drift_info.get("threshold")
                }
                drift_details.append(details)
                if not silent:
                    print(
                        f"  Drift alert at {details['audit_id']} "
                        f"(period {period}): score {details['score']:.2f} > "
                        f"{details['threshold']}"
                    )

    if not silent:
        print(f"\nProcessed {processed} rows from {data_path} ({skipped} skipped)")
        print(f"Policy violations recorded: {violations}")
        print(f"Drift alerts detected: {len(drift_details)}")
        integrity = orchestrator.verify_integrity()
        print(f"Chain length now {integrity['blocks']} blocks (valid={integrity['valid']})")
    return {
        "processed": processed,
        "skipped": skipped,
        "violations": violations,
        "drift_alerts": len(drift_details),
        "periods": sorted(periods_seen),
        "drift_details": drift_details
    }

REQUIRED_FIELDS = ("loan_amount", "property_value", "monthly_debt", "monthly_income")
OPTIONAL_FIELDS = ("marginal_var", "var_limit")


def _row_to_context(row: dict[str, str], field_map: dict[str, str]) -> dict[str, Any]:
    def _read(field: str) -> float | None:
        raw = row.get(field_map.get(field, field), "")
        text = str(raw).strip() if raw is not None else ""
        return float(text) if text else None

    context: dict[str, Any] = {
        "period": (row.get(field_map.get("period", "period")) or "A").strip() or "A",
        "segment": (row.get(field_map.get("segment", "segment")) or "unknown").strip() or "unknown"
    }
    missing = []
    for field in REQUIRED_FIELDS:
        value = _read(field)
        if value is None:
            missing.append(field)
        else:
            context[field] = value
    if missing:
        raise ValueError(f"missing required value(s): {', '.join(missing)}")
    for field in OPTIONAL_FIELDS:
        value = _read(field)
        if value is not None:
            context[field] = value
    if all(field in context for field in FEATURE_FIELDS):
        context["features"] = [context[f] for f in FEATURE_FIELDS]
    return context

if __name__ == "__main__":
    main()
