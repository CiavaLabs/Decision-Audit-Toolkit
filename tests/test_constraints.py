import json
import tempfile
import unittest
from pathlib import Path

from decision_audit.constraints import (
    CONSTRAINT_TYPES,
    MissingField,
    available_constraint_types,
    build_constraints_from_specs,
    get_policy_profile,
    load_constraints_from_json,
    register_constraint_type,
)

VALID_CONTEXT = {
    "loan_amount": 100000,
    "property_value": 150000,
    "monthly_debt": 500,
    "monthly_income": 5000,
    "marginal_var": 0.5,
    "var_limit": 1.0,
}


class ConstraintTests(unittest.TestCase):
    def test_basic_profile_passes_clean_context(self):
        checker = get_policy_profile("financial_basic")
        self.assertEqual(checker.check(VALID_CONTEXT), [])

    def test_ratio_max_boundary_is_inclusive(self):
        checker = get_policy_profile("financial_basic")
        ctx = dict(VALID_CONTEXT, loan_amount=120000, property_value=150000)
        self.assertEqual(checker.check(ctx), [])
        ctx["loan_amount"] = 120001
        self.assertEqual([v["id"] for v in checker.check(ctx)], ["ltv_limit"])

    def test_positive_flags_zero_and_missing(self):
        checker = get_policy_profile("financial_basic")
        ctx = dict(VALID_CONTEXT, monthly_income=0)
        ids = [v["id"] for v in checker.check(ctx)]
        self.assertIn("positive_amounts", ids)
        ctx = dict(VALID_CONTEXT)
        del ctx["loan_amount"]
        ids = [v["id"] for v in checker.check(ctx)]
        self.assertIn("positive_amounts", ids)

    def test_lte_field_uses_default_when_other_missing(self):
        checker = build_constraints_from_specs([{
            "id": "var", "type": "lte_field",
            "field": "marginal_var", "other_field": "var_limit", "other_default": 1.0
        }])
        self.assertEqual(checker.check({"marginal_var": 0.9}), [])
        self.assertEqual(len(checker.check({"marginal_var": 1.1})), 1)

    def test_value_min_and_max(self):
        checker = build_constraints_from_specs([
            {"id": "min_income", "type": "value_min", "field": "monthly_income", "min": 2500},
            {"id": "max_loan", "type": "value_max", "field": "loan_amount", "max": 500000},
        ])
        self.assertEqual(checker.check({"monthly_income": 2500, "loan_amount": 500000}), [])
        ids = [v["id"] for v in checker.check({"monthly_income": 2000, "loan_amount": 600000})]
        self.assertEqual(sorted(ids), ["max_loan", "min_income"])

    def test_non_numeric_value_becomes_violation_not_crash(self):
        checker = get_policy_profile("financial_basic")
        ctx = dict(VALID_CONTEXT, loan_amount="not-a-number")
        violations = checker.check(ctx)
        self.assertTrue(violations)
        self.assertTrue(any(v["severity"] == "error" for v in violations), violations)

    def test_unknown_constraint_type_raises(self):
        with self.assertRaises(ValueError):
            build_constraints_from_specs([{"id": "x", "type": "nope"}])

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            get_policy_profile("does_not_exist")

    def test_load_from_json_wrapped_and_bare(self):
        specs = [{"id": "max_loan", "type": "value_max", "field": "loan_amount", "max": 100}]
        with tempfile.TemporaryDirectory() as tmp:
            wrapped = Path(tmp) / "wrapped.json"
            wrapped.write_text(json.dumps({"constraints": specs}))
            self.assertEqual(len(load_constraints_from_json(str(wrapped)).constraints), 1)

            bare = Path(tmp) / "bare.json"
            bare.write_text(json.dumps(specs))
            self.assertEqual(len(load_constraints_from_json(str(bare)).constraints), 1)

            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"constraints": "nope"}))
            with self.assertRaises(ValueError):
                load_constraints_from_json(str(bad))

    def test_missing_field_is_reported_not_treated_as_zero(self):
        checker = build_constraints_from_specs([
            {"id": "ltv", "type": "ratio_max", "numerator": "loan_amount",
             "denominator": "property_value", "max": 0.8},
            {"id": "cap", "type": "value_max", "field": "exposure", "max": 1000},
            {"id": "floor", "type": "value_min", "field": "income", "min": 100},
        ])
        violations = {v["id"]: v for v in checker.check({})}
        self.assertEqual(set(violations), {"ltv", "cap", "floor"})
        for violation in violations.values():
            self.assertEqual(violation["severity"], "error")
            self.assertIn("missing", violation["description"])

    def test_typo_in_a_field_name_does_not_pass_silently(self):
        checker = build_constraints_from_specs([
            {"id": "ltv", "type": "ratio_max", "numerator": "loan_amount",
             "denominator": "property_value", "max": 0.8},
        ])
        violations = checker.check({"loan_ammount": 190000, "property_value": 200000})
        self.assertEqual([v["id"] for v in violations], ["ltv"])

    def test_lte_field_keeps_its_declared_default(self):
        checker = build_constraints_from_specs([
            {"id": "var", "type": "lte_field", "field": "marginal_var",
             "other_field": "var_limit", "other_default": 1.0},
        ])
        self.assertEqual(checker.check({"marginal_var": 0.5}), [])
        self.assertEqual([v["id"] for v in checker.check({"marginal_var": 1.5})], ["var"])

    def test_non_dict_context_is_rejected(self):
        checker = build_constraints_from_specs([
            {"id": "cap", "type": "value_max", "field": "exposure", "max": 1000}])
        with self.assertRaises(ValueError):
            checker.check([])

    def test_bundled_policy_files_match_registry(self):
        for name in ("financial_basic", "financial_strict"):
            from_file = load_constraints_from_json(f"policies/{name}.json")
            from_registry = get_policy_profile(name)
            self.assertEqual(
                sorted(from_file.constraints), sorted(from_registry.constraints)
            )


class CompositionTests(unittest.TestCase):
    def _checker(self, spec):
        return build_constraints_from_specs([dict(spec, id="composed")])

    def test_all_of_needs_every_branch(self):
        checker = self._checker({
            "type": "all_of", "rules": [
                {"type": "value_min", "field": "income", "min": 2000},
                {"type": "value_max", "field": "debt", "max": 500},
            ]})
        self.assertEqual(checker.check({"income": 3000, "debt": 400}), [])
        self.assertEqual(len(checker.check({"income": 3000, "debt": 900})), 1)
        self.assertEqual(len(checker.check({"income": 1000, "debt": 400})), 1)

    def test_any_of_needs_one_branch(self):
        checker = self._checker({
            "type": "any_of", "rules": [
                {"type": "value_min", "field": "income", "min": 5000},
                {"type": "value_min", "field": "collateral", "min": 100000},
            ]})
        self.assertEqual(checker.check({"income": 6000, "collateral": 0}), [])
        self.assertEqual(checker.check({"income": 1000, "collateral": 200000}), [])
        self.assertEqual(len(checker.check({"income": 1000, "collateral": 0})), 1)

    def test_any_of_is_satisfied_even_if_another_branch_is_unevaluable(self):
        checker = self._checker({
            "type": "any_of", "rules": [
                {"type": "value_min", "field": "income", "min": 5000},
                {"type": "value_min", "field": "collateral", "min": 100000},
            ]})
        self.assertEqual(checker.check({"income": 6000}), [])

    def test_any_of_reports_unknown_rather_than_failing_on_a_missing_field(self):
        checker = self._checker({
            "type": "any_of", "rules": [
                {"type": "value_min", "field": "income", "min": 5000},
                {"type": "value_min", "field": "collateral", "min": 100000},
            ]})
        violations = checker.check({"income": 1000})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["severity"], "error")
        self.assertIn("collateral", violations[0]["description"])

    def test_all_of_does_not_depend_on_the_order_the_rules_are_written_in(self):
        failing = {"type": "value_max", "field": "debt", "max": 500}
        unevaluable = {"type": "value_min", "field": "income", "min": 2000}
        for order in ((failing, unevaluable), (unevaluable, failing)):
            with self.subTest(first=order[0]["field"]):
                checker = self._checker({"type": "all_of", "rules": list(order)})
                violations = checker.check({"debt": 900})
                self.assertEqual(len(violations), 1)
                self.assertEqual(violations[0]["severity"], "info")
                self.assertNotIn("Not evaluated", violations[0]["description"])

    def test_all_of_propagates_a_missing_field(self):
        checker = self._checker({
            "type": "all_of", "rules": [
                {"type": "value_min", "field": "income", "min": 2000},
                {"type": "value_max", "field": "debt", "max": 500},
            ]})
        violations = checker.check({"income": 3000})
        self.assertEqual(violations[0]["severity"], "error")
        self.assertIn("debt", violations[0]["description"])

    def test_not_inverts(self):
        checker = self._checker({
            "type": "not",
            "rule": {"type": "value_min", "field": "risk_flag", "min": 1}})
        self.assertEqual(checker.check({"risk_flag": 0}), [])
        self.assertEqual(len(checker.check({"risk_flag": 1})), 1)

    def test_nesting(self):
        checker = self._checker({
            "type": "all_of", "rules": [
                {"type": "value_min", "field": "income", "min": 2000},
                {"type": "any_of", "rules": [
                    {"type": "value_min", "field": "collateral", "min": 100000},
                    {"type": "value_min", "field": "guarantor_income", "min": 4000},
                ]},
            ]})
        self.assertEqual(checker.check(
            {"income": 3000, "collateral": 0, "guarantor_income": 5000}), [])
        self.assertEqual(len(checker.check(
            {"income": 3000, "collateral": 0, "guarantor_income": 1000})), 1)

    def test_composition_needs_rules(self):
        for spec in ({"id": "x", "type": "all_of"},
                     {"id": "x", "type": "any_of", "rules": []},
                     {"id": "x", "type": "not"}):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                build_constraints_from_specs([spec])

    def test_a_rule_that_is_not_an_object_is_refused_with_a_message(self):
        for spec in ([{"id": "x", "type": "all_of", "rules": ["nope"]}],
                     ["not an object"],
                     [{"type": "value_max", "field": "debt", "max": 1}]):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                build_constraints_from_specs(spec)

    def test_a_missing_setting_names_the_rule_that_lacks_it(self):
        for spec, missing in (
                ({"id": "ltv", "type": "ratio_max", "denominator": "v", "max": 0.8},
                 "'numerator'"),
                ({"id": "cap", "type": "value_max", "field": "debt"}, "'max'"),
                ({"id": "chan", "type": "in_set", "field": "channel"}, "'values'")):
            with self.subTest(spec=spec), self.assertRaises(ValueError) as caught:
                build_constraints_from_specs([spec])
            message = str(caught.exception)
            self.assertIn(spec["id"], message)
            self.assertIn(missing, message)

    def test_positive_without_fields_is_refused(self):
        for spec in ({"id": "amounts", "type": "positive"},
                     {"id": "amounts", "type": "positive", "fields": []}):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                build_constraints_from_specs([spec])


class RegistryTests(unittest.TestCase):
    def test_in_set(self):
        checker = build_constraints_from_specs([
            {"id": "channel", "type": "in_set", "field": "channel",
             "values": ["branch", "broker"]}])
        self.assertEqual(checker.check({"channel": "broker"}), [])
        self.assertEqual(len(checker.check({"channel": "web"})), 1)
        self.assertEqual(checker.check({})[0]["severity"], "error")

    def test_ratio_min(self):
        checker = build_constraints_from_specs([
            {"id": "coverage", "type": "ratio_min", "numerator": "property_value",
             "denominator": "loan_amount", "min": 1.25}])
        self.assertEqual(checker.check(
            {"property_value": 300000, "loan_amount": 200000}), [])
        self.assertEqual(len(checker.check(
            {"property_value": 210000, "loan_amount": 200000})), 1)

    def test_a_custom_type_can_be_registered(self):
        def build_even(spec):
            field = spec["field"]
            def check_fn(ctx):
                if field not in ctx:
                    raise MissingField(f"context field '{field}' is missing")
                return int(ctx[field]) % 2 == 0
            return check_fn

        register_constraint_type("test_even", build_even)
        self.addCleanup(CONSTRAINT_TYPES.pop, "test_even", None)
        self.assertIn("test_even", available_constraint_types())
        checker = build_constraints_from_specs([
            {"id": "even", "type": "test_even", "field": "n"}])
        self.assertEqual(checker.check({"n": 4}), [])
        self.assertEqual(len(checker.check({"n": 5})), 1)

    def test_unknown_type_lists_what_is_available(self):
        with self.assertRaises(ValueError) as caught:
            build_constraints_from_specs([{"id": "x", "type": "telepathy"}])
        self.assertIn("ratio_max", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
