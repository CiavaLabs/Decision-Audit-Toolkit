import tempfile
import unittest

from decision_audit.config import Config
from decision_audit.orchestrator import AuditOrchestrator
from decision_audit.report import build_report, render_html

CONTEXT = {
    "loan_amount": 150000,
    "property_value": 200000,
    "monthly_debt": 1000,
    "monthly_income": 6000,
    "marginal_var": 0.5,
    "var_limit": 1.0,
    "segment": "prime<script>",
    "period": "T1",
}


class ReportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.orch = AuditOrchestrator(Config(state_dir=self._tmp.name))

    def test_report_structure(self):
        self.orch.audit_decision({"decision": "APPROVE", "score": 0.4}, dict(CONTEXT))
        report = build_report(self.orch)
        self.assertEqual(
            set(report), {"title", "generated_at", "version", "integrity", "summary",
                          "portfolio_policy"})
        self.assertTrue(report["integrity"]["valid"])
        self.assertEqual(report["summary"]["audits"], 1)

    def test_report_carries_the_portfolio_thresholds(self):
        for _ in range(3):
            self.orch.audit_decision({"decision": "APPROVE", "score": 0.4}, dict(CONTEXT))
        report = build_report(self.orch)
        policy = report["portfolio_policy"]
        self.assertIn("passed", policy)
        self.assertIn("Portfolio thresholds", render_html(report))

    def test_html_renders_and_escapes(self):
        self.orch.audit_decision({"decision": "APPROVE", "score": 0.4}, dict(CONTEXT))
        html_out = render_html(build_report(self.orch))
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("VALID", html_out)
        self.assertIn("prime&lt;script&gt;", html_out)
        self.assertNotIn("prime<script>", html_out)

    def test_html_on_empty_chain(self):
        html_out = render_html(build_report(self.orch))
        self.assertIn("0 audit records", html_out)

    def test_footer_states_what_the_scheme_actually_proves(self):
        report = build_report(self.orch)

        report["integrity"]["scheme"] = "ed25519"
        ed_html = render_html(report)
        self.assertIn("Ed25519-signed", ed_html)
        self.assertNotIn("not non-repudiation", ed_html)

        report["integrity"]["scheme"] = "hmac"
        hmac_html = render_html(report)
        self.assertIn("not non-repudiation", hmac_html)


if __name__ == "__main__":
    unittest.main()
