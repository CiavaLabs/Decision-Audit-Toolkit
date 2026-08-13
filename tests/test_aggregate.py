import json
import tempfile
import unittest
from pathlib import Path

from decision_audit.aggregate import (
    _RULE_TYPES,
    NOT_EVALUATED,
    AggregatePolicy,
    get_aggregate_profile,
    load_aggregate_policy_from_json,
    register_aggregate_rule,
)
from decision_audit.config import Config
from decision_audit.fairness import wilson_interval
from decision_audit.orchestrator import AuditOrchestrator

BASE = {"property_value": 300000, "monthly_debt": 1000, "monthly_income": 6000,
        "marginal_var": 0.5, "var_limit": 1.0}


def summary_with(groups: dict[str, tuple[int, float]], **totals) -> dict:
    built = {}
    for name, (count, rate) in groups.items():
        low, high = wilson_interval(round(rate * count), count)
        built[name] = {
            "count": count,
            "model_approval_rate": rate,
            "final_approval_rate": rate,
            "final_approval_ci95": [round(low, 4), round(high, 4)],
            "violation_rate": 0.0,
            "policy_override_rate": 0.0,
            "avg_model_score": None,
            "sufficient_data": count >= 30,
        }
    return dict({"audits": sum(c for c, _ in groups.values()),
                 "with_violations": 0, "with_anomaly": 0, "degraded": 0,
                 "fairness": {"attribute": "segment", "groups": built}}, **totals)


class AggregateRuleTests(unittest.TestCase):
    def test_approval_span_breach_is_reported(self):
        policy = AggregatePolicy([
            {"id": "span", "type": "max_approval_span", "max": 0.2, "severity": "high"}])
        result = policy.evaluate(summary_with({"a": (50, 0.9), "b": (50, 0.4)}))
        self.assertFalse(result["passed"])
        self.assertEqual(result["breaches"][0]["id"], "span")
        self.assertEqual(result["breaches"][0]["observed"], 0.5)

    def test_approval_span_within_the_limit_passes(self):
        policy = AggregatePolicy([
            {"id": "span", "type": "max_approval_span", "max": 0.2}])
        self.assertTrue(policy.evaluate(
            summary_with({"a": (50, 0.9), "b": (50, 0.8)}))["passed"])

    def test_four_fifths_ratio(self):
        policy = AggregatePolicy([
            {"id": "ratio", "type": "min_approval_ratio", "min": 0.8}])
        self.assertFalse(policy.evaluate(
            summary_with({"a": (50, 1.0), "b": (50, 0.5)}))["passed"])
        self.assertTrue(policy.evaluate(
            summary_with({"a": (50, 1.0), "b": (50, 0.85)}))["passed"])

    def test_small_groups_do_not_drive_the_comparison(self):
        policy = AggregatePolicy([
            {"id": "span", "type": "max_approval_span", "max": 0.2}])
        result = policy.evaluate(
            summary_with({"a": (50, 0.9), "b": (50, 0.85), "tiny": (4, 0.0)}))
        self.assertTrue(result["passed"], result["breaches"])

    def test_a_rule_with_nothing_to_compare_says_so_rather_than_passing(self):
        policy = AggregatePolicy([
            {"id": "span", "type": "max_approval_span", "max": 0.2}])
        result = policy.evaluate(summary_with({"only": (50, 0.9)}))
        self.assertEqual(result["not_evaluated"][0]["id"], "span")
        self.assertEqual(result["not_evaluated"][0]["severity"], NOT_EVALUATED)
        self.assertTrue(result["passed"])
        self.assertEqual(result["breaches"], [])

    def test_per_rule_minimum_overrides_the_summary_default(self):
        policy = AggregatePolicy([
            {"id": "span", "type": "max_approval_span", "max": 0.2,
             "min_group_size": 3}])
        result = policy.evaluate(
            summary_with({"a": (50, 0.9), "tiny": (4, 0.0)}))
        self.assertFalse(result["passed"])

    def test_rate_rules(self):
        for rule_type, field in (("max_anomaly_rate", "with_anomaly"),
                                 ("max_violation_rate", "with_violations"),
                                 ("max_degraded_rate", "degraded")):
            with self.subTest(rule=rule_type):
                policy = AggregatePolicy([
                    {"id": rule_type, "type": rule_type, "max": 0.05}])
                summary = summary_with({"a": (100, 1.0)}, **{field: 20})
                self.assertFalse(policy.evaluate(summary)["passed"])
                summary = summary_with({"a": (100, 1.0)}, **{field: 1})
                self.assertTrue(policy.evaluate(summary)["passed"])

    def test_unknown_rule_type_is_refused_at_construction(self):
        with self.assertRaises(ValueError) as caught:
            AggregatePolicy([{"id": "x", "type": "vibes"}])
        self.assertIn("vibes", str(caught.exception))

    def test_rule_without_an_id_is_refused(self):
        with self.assertRaises(ValueError):
            AggregatePolicy([{"type": "max_approval_span", "max": 0.2}])

    def test_a_threshold_that_is_not_a_number_is_refused_at_construction(self):
        with self.assertRaises(ValueError) as caught:
            AggregatePolicy([
                {"id": "span", "type": "max_approval_span", "max": "not a number"}])
        self.assertIn("must be a number", str(caught.exception))

    def test_a_missing_threshold_is_refused_at_construction(self):
        with self.assertRaises(ValueError) as caught:
            AggregatePolicy([
                {"id": "four_fifths", "type": "min_approval_ratio", "minimum": 0.8}])
        self.assertIn("needs a 'min' threshold", str(caught.exception))

    def test_a_rule_the_data_cannot_support_is_reported_not_raised(self):
        policy = AggregatePolicy([
            {"id": "span", "type": "max_approval_span", "max": 0.2}])
        result = policy.evaluate({"audits": 0, "fairness": {"groups": {}}})
        self.assertEqual(result["not_evaluated"][0]["id"], "span")
        self.assertTrue(result["passed"])
        self.assertFalse(result["complete"])

    def test_a_summary_of_the_wrong_shape_is_reported_not_raised(self):
        policy = AggregatePolicy([
            {"id": "span", "type": "max_approval_span", "max": 0.2}])
        for summary in ({"fairness": "junk"}, {"fairness": {"groups": []}},
                        {"fairness": {"groups": {"a": "junk"}}}, {}):
            with self.subTest(summary=summary):
                result = policy.evaluate(summary)
                self.assertEqual(result["not_evaluated"][0]["id"], "span")

    def test_custom_rule_types_can_be_registered(self):
        register_aggregate_rule(
            "test_always_breaches",
            lambda spec, summary: {"id": spec["id"], "severity": "low",
                                   "description": "", "observed": 1,
                                   "threshold": 0, "detail": "by design"})
        self.addCleanup(_RULE_TYPES.pop, "test_always_breaches", None)
        policy = AggregatePolicy([{"id": "custom", "type": "test_always_breaches"}])
        self.assertFalse(policy.evaluate(summary_with({"a": (50, 1.0)}))["passed"])

    def test_profile_and_json_loading(self):
        self.assertGreater(len(get_aggregate_profile("financial_basic").specs), 0)
        with self.assertRaises(ValueError):
            get_aggregate_profile("nope")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps({"aggregate_rules": [
                {"id": "span", "type": "max_approval_span", "max": 0.1}]}))
            policy = load_aggregate_policy_from_json(str(path))
            self.assertEqual(len(policy.specs), 1)


class WilsonIntervalTests(unittest.TestCase):
    def test_interval_stays_inside_zero_and_one(self):
        for successes, total in ((0, 5), (5, 5), (0, 1), (1, 1), (3, 4)):
            low, high = wilson_interval(successes, total)
            with self.subTest(successes=successes, total=total):
                self.assertGreaterEqual(low, 0.0)
                self.assertLessEqual(high, 1.0)
                self.assertLessEqual(low, high)

    def test_interval_narrows_as_the_group_grows(self):
        small = wilson_interval(5, 10)
        large = wilson_interval(500, 1000)
        self.assertLess(large[1] - large[0], small[1] - small[0])

    def test_interval_brackets_the_observed_rate_for_interior_values(self):
        low, high = wilson_interval(30, 100)
        self.assertLess(low, 0.30)
        self.assertGreater(high, 0.30)

    def test_no_observations_gives_the_widest_interval(self):
        self.assertEqual(wilson_interval(0, 0), (0.0, 1.0))


class EndToEndAggregateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = str(Path(self._tmp.name) / "state")

    def test_a_real_disparity_is_caught_from_the_stored_log(self):
        orch = AuditOrchestrator(Config(state_dir=self.state, signature_scheme="hmac"))
        for _ in range(40):
            orch.audit_decision({"decision": "APPROVE", "score": 0.3},
                                dict(BASE, loan_amount=200000, segment="prime"))
        for _ in range(40):
            orch.audit_decision({"decision": "APPROVE", "score": 0.3},
                                dict(BASE, loan_amount=290000, segment="underserved"))

        result = orch.check_aggregate_policy()
        self.assertFalse(result["passed"])
        breached = {b["id"] for b in result["breaches"]}
        self.assertIn("approval_span", breached)
        self.assertIn("four_fifths", breached)

    def test_an_even_handed_portfolio_passes(self):
        orch = AuditOrchestrator(Config(state_dir=self.state, signature_scheme="hmac"))
        for segment in ("prime", "underserved"):
            for _ in range(40):
                orch.audit_decision({"decision": "APPROVE", "score": 0.3},
                                    dict(BASE, loan_amount=200000, segment=segment))
        result = orch.check_aggregate_policy()
        self.assertTrue(result["passed"], result["breaches"])


if __name__ == "__main__":
    unittest.main()
