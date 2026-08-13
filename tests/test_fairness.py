import unittest

from decision_audit.fairness import DEFAULT_MIN_GROUP_SIZE, FairnessAccumulator


def _record(segment, model_decision, final_outcome, score=None, blocked=False):
    data = {
        "segment": segment,
        "model_decision": model_decision,
        "final_outcome": final_outcome,
        "policy_blocked": blocked,
    }
    if score is not None:
        data["model_score"] = score
    return data


def metrics_for(records, min_group_size=DEFAULT_MIN_GROUP_SIZE):
    accumulator = FairnessAccumulator(min_group_size=min_group_size)
    for record in records:
        accumulator.add(record)
    return accumulator.result()


class FairnessTests(unittest.TestCase):
    def test_rates_and_span(self):
        records = [
            _record("a", "APPROVE", "APPROVE", 0.4),
            _record("a", "APPROVE", "BLOCKED_BY_POLICY", 0.5, blocked=True),
            _record("b", "REJECT", "REJECT", 1.0),
            _record("b", "APPROVE", "APPROVE", 0.5),
        ]
        metrics = metrics_for(records)
        a, b = metrics["groups"]["a"], metrics["groups"]["b"]
        self.assertEqual(a["model_approval_rate"], 1.0)
        self.assertEqual(a["final_approval_rate"], 0.5)
        self.assertEqual(a["policy_override_rate"], 0.5)
        self.assertEqual(a["violation_rate"], 0.5)
        self.assertEqual(b["final_approval_rate"], 0.5)
        self.assertIsNone(metrics["approval_span"])
        self.assertEqual(metrics["compared_groups"], [])
        self.assertEqual(metrics["excluded_groups"], ["a", "b"])

    def test_span_is_taken_only_from_comparable_groups(self):
        records = ([_record("big_a", "APPROVE", "APPROVE") for _ in range(40)]
                   + [_record("big_b", "APPROVE", "REJECT") for _ in range(40)]
                   + [_record("tiny", "APPROVE", "APPROVE") for _ in range(2)])
        metrics = metrics_for(records, min_group_size=30)
        self.assertEqual(metrics["compared_groups"], ["big_a", "big_b"])
        self.assertEqual(metrics["excluded_groups"], ["tiny"])
        self.assertEqual(metrics["approval_span"], 1.0)
        self.assertEqual(metrics["approval_ratio"], 0.0)
        self.assertIn("tiny", metrics["groups"])

    def test_no_span_without_two_comparable_groups(self):
        records = ([_record("big", "APPROVE", "APPROVE") for _ in range(40)]
                   + [_record("tiny", "APPROVE", "REJECT") for _ in range(3)])
        metrics = metrics_for(records, min_group_size=30)
        self.assertIsNone(metrics["approval_span"])
        self.assertIsNone(metrics["approval_ratio"])
        self.assertEqual(metrics["compared_groups"], ["big"])

    def test_avg_score_only_over_scored_records(self):
        records = [
            _record("a", "APPROVE", "APPROVE", 0.4),
            _record("a", "APPROVE", "APPROVE"),
        ]
        self.assertEqual(metrics_for(records)["groups"]["a"]["avg_model_score"], 0.4)

    def test_avg_score_none_when_no_scores(self):
        metrics = metrics_for([_record("a", "APPROVE", "APPROVE")])
        self.assertIsNone(metrics["groups"]["a"]["avg_model_score"])

    def test_group_read_from_context_fallback(self):
        records = [{
            "context": {"segment": "c"},
            "model_decision": "APPROVE",
            "final_outcome": "APPROVE",
        }]
        self.assertIn("c", metrics_for(records)["groups"])

    def test_a_record_without_a_group_is_not_counted(self):
        records = [_record("", "APPROVE", "APPROVE"),
                   {"model_decision": "APPROVE", "final_outcome": "APPROVE"}]
        self.assertEqual(metrics_for(records)["groups"], {})

    def test_a_non_string_label_still_names_a_group(self):
        records = [_record(0, "APPROVE", "APPROVE"), _record(1, "REJECT", "REJECT")]
        self.assertEqual(sorted(metrics_for(records)["groups"]), ["0", "1"])

    def test_empty_input(self):
        metrics = metrics_for([])
        self.assertEqual(metrics["groups"], {})
        self.assertIsNone(metrics["approval_span"])
        self.assertIsNone(metrics["approval_ratio"])

    def test_override_rate_ignores_violations_on_rejected_decisions(self):
        records = [_record("a", "REJECT", "REJECT", blocked=True) for _ in range(4)]
        groups = metrics_for(records)["groups"]
        self.assertEqual(groups["a"]["violation_rate"], 1.0)
        self.assertEqual(groups["a"]["policy_override_rate"], 0.0)

    def test_boolean_score_is_not_averaged(self):
        records = [_record("a", "APPROVE", "APPROVE", score=True)]
        self.assertIsNone(metrics_for(records)["groups"]["a"]["avg_model_score"])

    def test_result_can_be_read_twice(self):
        accumulator = FairnessAccumulator(min_group_size=1)
        accumulator.add(_record("a", "APPROVE", "APPROVE"))
        self.assertEqual(accumulator.result(), accumulator.result())


if __name__ == "__main__":
    unittest.main()
