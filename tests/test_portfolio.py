import unittest

from decision_audit.portfolio import PortfolioAccumulator


def _record(**overrides):
    data = {
        "decision": {"decision": "APPROVE"},
        "model_decision": "APPROVE",
        "final_outcome": "APPROVE",
        "segment": "a",
    }
    data.update(overrides)
    return data


class PortfolioAccumulatorTests(unittest.TestCase):
    def test_counts_outcomes_periods_and_violations(self):
        acc = PortfolioAccumulator(min_group_size=1)
        acc.add(_record(period="T1"))
        acc.add(_record(period="T1", violations=2, violation_ids=["ltv", "dsr"],
                        policy_blocked=True, final_outcome="BLOCKED_BY_POLICY"))
        acc.add(_record(period="T2", status="degraded"))
        result = acc.result()

        self.assertEqual(result["audits"], 3)
        self.assertEqual(result["with_violations"], 1)
        self.assertEqual(result["degraded"], 1)
        self.assertEqual(result["audits_by_period"], {"T1": 2, "T2": 1})
        self.assertEqual(result["violations_by_id"], {"ltv": 1, "dsr": 1})
        self.assertEqual(result["policy_overrides"], {"model_approve_blocked": 1})
        self.assertEqual(result["final_outcomes"],
                         {"APPROVE": 2, "BLOCKED_BY_POLICY": 1})

    def test_a_decision_that_is_not_an_object_does_not_raise(self):
        for broken in (None, "APPROVE", 7, ["APPROVE"]):
            with self.subTest(decision=broken):
                acc = PortfolioAccumulator(min_group_size=1)
                acc.add(_record(decision=broken))
                self.assertEqual(acc.result()["decisions_by_outcome"], {"UNKNOWN": 1})

    def test_a_record_that_is_not_an_object_is_counted_not_fatal(self):
        acc = PortfolioAccumulator(min_group_size=1)
        for broken in (None, [], "record", 3):
            acc.add(broken)
        self.assertEqual(acc.result()["audits"], 4)

    def test_unhashable_and_non_string_labels_survive(self):
        acc = PortfolioAccumulator(min_group_size=1)
        acc.add(_record(segment={"nested": "label"}, final_outcome=["odd"]))
        acc.add(_record(segment=7))
        result = acc.result()
        self.assertEqual(result["audits"], 2)
        self.assertIn("7", result["fairness"]["groups"])

    def test_violation_ids_absent_are_counted_under_a_placeholder(self):
        acc = PortfolioAccumulator(min_group_size=1)
        acc.add(_record(violations=1))
        self.assertEqual(acc.result()["violations_by_id"], {"_unspecified": 1})

    def test_the_anomaly_list_is_capped_but_the_total_is_not(self):
        acc = PortfolioAccumulator(min_group_size=1, max_anomaly_rows=5)
        for i in range(12):
            acc.add(_record(anomaly=True, audit_id=f"audit_{i}", drift_score=1.0))
        result = acc.result()
        self.assertEqual(result["with_anomaly"], 12)
        self.assertEqual(len(result["anomaly_audits"]), 5)
        self.assertEqual(result["anomaly_audits_truncated"], 7)

    def test_no_truncation_key_when_nothing_was_dropped(self):
        acc = PortfolioAccumulator(min_group_size=1, max_anomaly_rows=5)
        acc.add(_record(anomaly=True, audit_id="audit_0"))
        self.assertNotIn("anomaly_audits_truncated", acc.result())


if __name__ == "__main__":
    unittest.main()
