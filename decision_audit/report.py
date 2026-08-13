import html
from datetime import datetime, timezone
from typing import Any

from ._version import __version__
from .orchestrator import AuditOrchestrator

_MAX_ANOMALY_ROWS = 25

def build_report(orchestrator: AuditOrchestrator) -> dict[str, Any]:
    generated_at = datetime.fromtimestamp(
        orchestrator.config.clock(), tz=timezone.utc
    ).isoformat(timespec="seconds")
    integrity = orchestrator.verify_integrity()
    summary = orchestrator.get_portfolio_summary()
    return {
        "title": "Decision Audit Report",
        "generated_at": generated_at,
        "version": __version__,
        "integrity": integrity,
        "summary": summary,
        "portfolio_policy": orchestrator.check_aggregate_policy(
            summary, chain_valid=integrity["valid"]),
    }

def render_html(report: dict[str, Any]) -> str:
    integrity = report["integrity"]
    summary = report["summary"]
    esc = html.escape

    status_ok = integrity["valid"]
    status_label = "VALID" if status_ok else "INVALID"
    status_class = "ok" if status_ok else "bad"

    parts: list[str] = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(report['title'])}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; color: #1a1a1a; }}
h1 {{ font-size: 1.5rem; }} h2 {{ font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .3rem; }}
table {{ border-collapse: collapse; margin: .8rem 0; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: .35rem .6rem; text-align: left; font-size: .9rem; }}
th {{ background: #f5f5f5; }}
.meta {{ color: #555; font-size: .85rem; }}
.badge {{ display: inline-block; padding: .15rem .6rem; border-radius: .3rem; font-weight: 600; }}
.badge.ok {{ background: #e6f4e6; color: #1a6b1a; }}
.badge.bad {{ background: #fbe4e4; color: #a11a1a; }}
.stats {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 1rem 0; }}
.stat {{ background: #f7f7f7; border-radius: .4rem; padding: .6rem 1rem; }}
.stat b {{ display: block; font-size: 1.3rem; }}
footer {{ margin-top: 2.5rem; color: #777; font-size: .8rem; }}
</style>
</head>
<body>
<h1>{esc(report['title'])}</h1>
<p class="meta">Generated {esc(report['generated_at'])} &middot; decision-audit {esc(report['version'])} &middot; policy: {esc(str(integrity.get('policy', '')))}</p>

<h2>Chain integrity</h2>
<p><span class="badge {status_class}">{status_label}</span>
{integrity['blocks']} audit records.</p>""")

    if integrity["errors"]:
        parts.append("<ul>")
        for err in integrity["errors"]:
            parts.append(f"<li>{esc(err)}</li>")
        parts.append("</ul>")

    parts.append(f"""
<h2>Portfolio overview</h2>
<div class="stats">
<div class="stat"><b>{summary['audits']}</b>decisions audited</div>
<div class="stat"><b>{summary['with_violations']}</b>with policy violations</div>
<div class="stat"><b>{summary['violation_rate']:.1%}</b>violation rate</div>
<div class="stat"><b>{summary['with_anomaly']}</b>drift anomalies</div>
</div>""")

    policy = report.get("portfolio_policy")
    if policy:
        policy_ok = policy["passed"]
        parts.append(
            f"""
<h2>Portfolio thresholds</h2>
<p><span class="badge {'ok' if policy_ok else 'bad'}">"""
            f"""{'PASS' if policy_ok else 'BREACHED'}</span>
{policy['rules']} rules evaluated.</p>""")
        if policy["breaches"]:
            parts.append("<table><tr><th>Rule</th><th>Severity</th>"
                         "<th>Observed</th><th>Threshold</th><th>Detail</th></tr>")
            for breach in policy["breaches"]:
                parts.append(
                    f"<tr><td>{esc(str(breach['id']))}</td>"
                    f"<td>{esc(str(breach['severity']))}</td>"
                    f"<td>{esc(str(breach['observed']))}</td>"
                    f"<td>{esc(str(breach['threshold']))}</td>"
                    f"<td>{esc(str(breach['detail']))}</td></tr>")
            parts.append("</table>")
        if not policy.get("chain_valid", True):
            parts.append("<p class=\"meta\">These thresholds were evaluated over a log "
                         "that does not verify: the numbers below describe the file as "
                         "it stands, not a history anyone can vouch for.</p>")
        if policy["not_evaluated"]:
            parts.append("<p class=\"meta\">Not evaluated: " + esc(", ".join(
                f"{r['id']} ({r['detail']})" for r in policy["not_evaluated"])) + "</p>")

    outcomes = sorted(set(summary["model_decisions"]) | set(summary["final_outcomes"]))
    if outcomes:
        parts.append("<h2>Decisions: model vs final</h2>\n<table><tr><th>Outcome</th><th>Model</th><th>Final</th></tr>")
        for outcome in outcomes:
            parts.append(
                f"<tr><td>{esc(outcome)}</td>"
                f"<td>{summary['model_decisions'].get(outcome, 0)}</td>"
                f"<td>{summary['final_outcomes'].get(outcome, 0)}</td></tr>")
        parts.append("</table>")
        overrides = summary["policy_overrides"].get("model_approve_blocked", 0)
        parts.append(f"<p class=\"meta\">Model approvals blocked by policy: {overrides}</p>")

    if summary["violations_by_id"]:
        parts.append("<h2>Violations by policy</h2>\n<table><tr><th>Policy id</th><th>Count</th></tr>")
        for policy_id, count in sorted(summary["violations_by_id"].items(), key=lambda kv: -kv[1]):
            parts.append(f"<tr><td>{esc(policy_id)}</td><td>{count}</td></tr>")
        parts.append("</table>")

    fairness = summary.get("fairness", {})
    groups = fairness.get("groups", {})
    if groups:
        parts.append(
            f"<h2>Fairness by {esc(str(fairness.get('attribute', 'group')))}</h2>\n"
            "<table><tr><th>Group</th><th>Count</th><th>Model approval</th>"
            "<th>Final approval</th><th>Violations</th><th>Approvals overridden</th>"
            "<th>Avg score</th></tr>")
        for group, m in sorted(groups.items()):
            avg = "n/a" if m["avg_model_score"] is None else f"{m['avg_model_score']:.3f}"
            parts.append(
                f"<tr><td>{esc(str(group))}</td><td>{m['count']}</td>"
                f"<td>{m['model_approval_rate']:.1%}</td><td>{m['final_approval_rate']:.1%}</td>"
                f"<td>{m['violation_rate']:.1%}</td>"
                f"<td>{m['policy_override_rate']:.1%}</td><td>{avg}</td></tr>")
        parts.append("</table>")
        span = fairness.get("approval_span")
        if span is None:
            parts.append(
                "<p class=\"meta\">Approval-rate span: not computed — fewer than two "
                f"groups reach the minimum of {esc(str(fairness.get('min_group_size')))} "
                "decisions.</p>")
        else:
            parts.append("<p class=\"meta\">Approval-rate span across "
                         f"{len(fairness.get('compared_groups', []))} comparable groups: "
                         f"{span:.1%}</p>")
        excluded = fairness.get("excluded_groups") or []
        if excluded:
            parts.append("<p class=\"meta\">Reported but too small to compare: "
                         + esc(", ".join(str(g) for g in excluded)) + "</p>")

    anomalies = summary.get("anomaly_audits", [])
    if anomalies:
        parts.append("<h2>Drift anomalies</h2>\n<table><tr><th>Audit id</th><th>Period</th><th>Score (sigma)</th></tr>")
        for entry in anomalies[:_MAX_ANOMALY_ROWS]:
            score = entry.get("drift_score")
            score_txt = "n/a" if isinstance(score, bool) or not isinstance(
                score, (int, float)) else f"{score:.2f}"
            parts.append(
                f"<tr><td>{esc(str(entry.get('audit_id')))}</td>"
                f"<td>{esc(str(entry.get('period') or ''))}</td><td>{score_txt}</td></tr>")
        parts.append("</table>")
        hidden = (summary.get("with_anomaly", len(anomalies))
                  - min(len(anomalies), _MAX_ANOMALY_ROWS))
        if hidden > 0:
            parts.append(f"<p class=\"meta\">…and {hidden} more.</p>")

    parts.append(f"""
<footer>decision-audit {esc(report['version'])} &middot; {_provenance_note(integrity.get('scheme'))}</footer>
</body>
</html>""")
    return "\n".join(parts)

def _provenance_note(scheme: Any) -> str:
    if scheme == "ed25519":
        return ("Ed25519-signed hash chain: verifiable with the public key alone, "
                "so signatures bind to the key holder.")
    if scheme == "hmac":
        return ("HMAC-signed hash chain provides integrity and authenticity, "
                "not non-repudiation.")
    return "Signed hash chain."
