from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.dataset.loader import load_dataset
from ml.dataset.schema import DEFAULT_FEATURE_VERSION
from ml.features.sequence import FEATURE_NAMES, VECTOR_LENGTH, build_sequence_features, shannon_entropy
from ml.model.explain import explain_score
from ml.model.scorer import ScoreBreakdown, fuse_signals, score_event


class SequenceDetectionTest(unittest.TestCase):
    def test_deterministic_sequence(self) -> None:
        dataset = load_dataset(ROOT / "ml" / "testdata" / "training_events.json", DEFAULT_FEATURE_VERSION)
        left = build_sequence_features(dataset)
        right = build_sequence_features(dataset)

        self.assertEqual(left.feature_names, FEATURE_NAMES)
        self.assertEqual(left, right)
        self.assertEqual(len(left.vectors[0]), VECTOR_LENGTH)
        self.assertEqual(left.burst_scores, (0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0))

    def test_entropy_consistency(self) -> None:
        self.assertEqual(float(shannon_entropy(b"AAAA")), 0.0)
        self.assertEqual(float(shannon_entropy(b"ABAB")), 1.0)
        self.assertEqual(float(shannon_entropy(b"ABCDEFGH")), 3.0)
        self.assertEqual(float(shannon_entropy(b"ABCDEFGH")), float(shannon_entropy(b"ABCDEFGH")))

    def test_fusion_score(self) -> None:
        vector = (0.0, 0.0, 0.0)
        weights = (0.0, 0.0, 0.0)
        breakdown = score_event(
            vector=vector,
            weights=weights,
            bias=0.0,
            entropy_score=0.4,
            burst_score=1.0,
            process_anomaly=0.2,
        )

        self.assertEqual(float(breakdown.model_prediction), 0.5)
        self.assertEqual(float(breakdown.score), 0.515)
        self.assertEqual(breakdown.decision, "benign")
        self.assertTrue(breakdown.sine_pass)

    def test_explanation_stability(self) -> None:
        score = fuse_signals(0.9, 0.1, 1.0, 0.4)
        breakdown = ScoreBreakdown(
            model_prediction=0.9,
            entropy_score=0.1,
            burst_score=1.0,
            process_anomaly=0.4,
            score=score,
            decision="malicious",
            sine_pass=True,
        )

        left = explain_score(breakdown)
        right = explain_score(breakdown)

        self.assertEqual(left, right)
        self.assertEqual(tuple(item.feature for item in left), ("model_prediction", "burst_score", "process_anomaly", "entropy_score"))
        self.assertEqual(tuple(float(item.impact) for item in left), (0.495, 0.15, 0.06, 0.015))


if __name__ == "__main__":
    unittest.main()
