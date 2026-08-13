import unittest

from decision_audit.config import Config
from decision_audit.drift import MeanShiftDriftDetector


def _make_detector(window=10, threshold=3.0, min_test=3):
    config = Config(drift_window_size=window, drift_threshold=threshold,
                    drift_min_test_samples=min_test)
    return MeanShiftDriftDetector(config)


def _baseline(i):
    return [100 + (i % 5), 50 + (i % 3), 10 + (i % 4)]


def _shifted(i):
    return [200 + (i % 5), 90 + (i % 3), 30 + (i % 4)]


class DriftTests(unittest.TestCase):
    def test_reference_fills_first(self):
        det = _make_detector(window=10)
        for i in range(9):
            result = det.update(_baseline(i))
            self.assertTrue(result["filling_reference"])
            self.assertFalse(result["drift"])

    def test_min_test_samples_respected(self):
        det = _make_detector(window=5, min_test=3)
        for i in range(5):
            det.update(_baseline(i))
        result = det.update(_baseline(5))
        self.assertTrue(result.get("filling_test"))
        self.assertFalse(result["drift"])

    def test_no_drift_on_same_distribution(self):
        det = _make_detector(window=10)
        for i in range(30):
            result = det.update(_baseline(i))
        self.assertFalse(result["drift"], result)

    def test_drift_fires_on_mean_shift(self):
        det = _make_detector(window=10)
        for i in range(10):
            det.update(_baseline(i))
        fired = False
        for i in range(10):
            result = det.update(_shifted(i))
            if result["drift"]:
                fired = True
                self.assertGreater(result["score"], det.threshold)
                break
        self.assertTrue(fired)

    def test_rebaseline_after_confirmed_drift(self):
        det = _make_detector(window=5, min_test=2)
        for i in range(5):
            det.update(_baseline(i))
        for i in range(5):
            det.update(_shifted(i))
        result = det.update(_shifted(6))
        self.assertFalse(result["drift"], result)

    def test_zero_variance_shift_scores_high(self):
        det = _make_detector(window=5, min_test=2)
        for _ in range(5):
            det.update([1.0, 1.0])
        det.update([2.0, 2.0])
        result = det.update([2.0, 2.0])
        self.assertTrue(result["drift"])

    def test_feature_count_mismatch_raises(self):
        det = _make_detector()
        det.update([1.0, 2.0])
        with self.assertRaises(ValueError):
            det.update([1.0, 2.0, 3.0])

    def test_non_numeric_features_are_rejected_immediately(self):
        det = _make_detector()
        for bad in ("abc", {"a": 1}, [1.0, "x"], [1.0, None], 5):
            with self.assertRaises(ValueError):
                det.update(bad)

    def test_non_finite_features_are_rejected(self):
        det = _make_detector()
        with self.assertRaises(ValueError):
            det.update([1.0, float("nan")])

    def test_an_empty_vector_does_not_blind_the_detector(self):
        det = _make_detector()
        with self.assertRaises(ValueError):
            det.update([])
        self.assertIsNone(det.n_features)
        self.assertFalse(det.update([1.0, 2.0])["drift"])

    def test_stored_windows_with_no_features_are_not_adopted(self):
        det = _make_detector()
        refused = det.load_state({"reference": [[], []], "test": [],
                                  "window_size": det.window_size,
                                  "min_test_samples": det.min_test_samples})
        self.assertIn("no features", refused)
        self.assertIsNone(det.n_features)

    def test_a_test_window_that_could_never_fill_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            _make_detector(window=5, min_test=50)
        self.assertIn("never fill", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
