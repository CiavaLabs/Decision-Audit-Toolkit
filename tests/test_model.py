import unittest

from decision_audit.model import mortgage_risk_model


class ModelTests(unittest.TestCase):
    def test_clean_application_approves(self):
        out = mortgage_risk_model({
            "loan_amount": 120000, "property_value": 200000,
            "monthly_debt": 800, "monthly_income": 5000,
            "marginal_var": 0.4, "var_limit": 1.0,
        })
        self.assertEqual(out.decision, "APPROVE")
        self.assertEqual(len(out.reasons), 4)

    def test_stressed_application_rejects(self):
        out = mortgage_risk_model({
            "loan_amount": 200000, "property_value": 210000,
            "monthly_debt": 3000, "monthly_income": 5000,
            "marginal_var": 1.5, "var_limit": 1.0,
        })
        self.assertEqual(out.decision, "REJECT")

    def test_score_is_bounded(self):
        out = mortgage_risk_model({
            "loan_amount": 1e9, "property_value": 1,
            "monthly_debt": 1e9, "monthly_income": 1,
            "marginal_var": 1e9, "var_limit": 1,
        })
        self.assertLessEqual(out.score, 1.5)
        self.assertGreaterEqual(out.score, 0.0)

    def test_zero_denominators_do_not_crash(self):
        out = mortgage_risk_model({
            "loan_amount": 100000, "property_value": 0,
            "monthly_debt": 500, "monthly_income": 0,
        })
        self.assertIn(out.decision, {"APPROVE", "REVIEW", "REJECT"})


if __name__ == "__main__":
    unittest.main()
