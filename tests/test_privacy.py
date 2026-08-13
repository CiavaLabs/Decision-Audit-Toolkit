import unittest

from decision_audit.privacy import ContextRedactor


class RedactorTests(unittest.TestCase):
    def setUp(self):
        self.redactor = ContextRedactor(
            banded_fields={"loan_amount": 10_000, "monthly_income": 500},
            clear_fields=("segment", "period"),
        )

    def test_banding_keeps_lower_bound(self):
        self.assertEqual(ContextRedactor.band_value(154_999, 10_000), 150_000)
        self.assertEqual(ContextRedactor.band_value(150_000, 10_000), 150_000)
        self.assertEqual(ContextRedactor.band_value(3_450, 500), 3_000)

    def test_negative_values_floor_towards_minus_infinity(self):
        self.assertEqual(ContextRedactor.band_value(-1_500, 1_000), -2_000)

    def test_value_on_a_band_edge_stays_in_its_band(self):
        self.assertEqual(ContextRedactor.band_value(0.3, 0.1), 0.3)
        self.assertEqual(ContextRedactor.band_value(0.7, 0.1), 0.7)
        self.assertEqual(ContextRedactor.band_value(0.15, 0.05), 0.15)
        self.assertEqual(ContextRedactor.band_value(0.29, 0.1), 0.2)

    def test_non_finite_values_are_refused(self):
        with self.assertRaises(ValueError):
            ContextRedactor.band_value(float("nan"), 100)
        with self.assertRaises(ValueError):
            ContextRedactor.band_value(float("inf"), 100)

    def test_band_zero_disables_banding(self):
        self.assertEqual(ContextRedactor.band_value(1234.5, 0), 1234.5)

    def test_unlisted_fields_are_dropped_and_reported(self):
        context = {
            "loan_amount": 154_999,
            "monthly_income": 3_450,
            "segment": "prime",
            "customer_id": "C123",
            "notes": "sensitive free text",
            "features": [1, 2, 3],
        }
        kept, dropped, errors = self.redactor.redact(context)
        self.assertEqual(kept, {
            "loan_amount": 150_000,
            "monthly_income": 3_000,
            "segment": "prime",
        })
        self.assertEqual(dropped, ["customer_id", "features", "notes"])
        self.assertEqual(errors, [])

    def test_raw_values_never_survive(self):
        kept, _, _ = self.redactor.redact({"loan_amount": 154_999})
        self.assertNotIn(154_999, kept.values())

    def test_unbandable_value_is_dropped_and_reported_not_raised(self):
        kept, dropped, errors = self.redactor.redact({"loan_amount": "n/a"})
        self.assertEqual(kept, {})
        self.assertEqual(dropped, ["loan_amount"])
        self.assertEqual(len(errors), 1)
        self.assertIn("loan_amount", errors[0])

    def test_select_keeps_only_the_allowlist(self):
        kept, dropped = ContextRedactor.select(
            {"decision": "APPROVE", "score": 0.4, "customer_ssn": "123-45-6789",
             "internal_ref": "X9"},
            ("decision", "score", "reasons"))
        self.assertEqual(kept, {"decision": "APPROVE", "score": 0.4})
        self.assertEqual(dropped, ["customer_ssn", "internal_ref"])


if __name__ == "__main__":
    unittest.main()
