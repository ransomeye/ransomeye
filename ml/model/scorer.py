from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ml.common.np_compat import np


FUSION_VERSION = "sequence-fusion-v1"
FUSION_WEIGHTS = {
    "model_prediction": np.float64(0.55),
    "entropy_score": np.float64(0.15),
    "burst_score": np.float64(0.15),
    "process_anomaly": np.float64(0.15),
}
SCORE_THRESHOLD = np.float64(0.68)
SINE_MIN_THRESHOLD = np.float64(0.45)


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    model_prediction: float
    entropy_score: float
    burst_score: float
    process_anomaly: float
    score: float
    decision: str
    sine_pass: bool


def logistic_prediction(vector: tuple[float, ...], weights: tuple[float, ...], bias: float) -> float:
    if len(vector) != len(weights):
        raise ValueError("vector and weights must have identical length")
    total = np.float64(bias)
    for weight, value in zip(weights, vector):
        total = _round64(total + np.float64(np.float64(weight) * np.float64(value)))
    return _sigmoid(total)


def fuse_signals(
    model_prediction: float,
    entropy_score: float,
    burst_score: float,
    process_anomaly: float,
    weights: Mapping[str, float] = FUSION_WEIGHTS,
) -> float:
    return _round64(
        np.float64(weights["model_prediction"] * np.float64(model_prediction))
        + np.float64(weights["entropy_score"] * np.float64(entropy_score))
        + np.float64(weights["burst_score"] * np.float64(burst_score))
        + np.float64(weights["process_anomaly"] * np.float64(process_anomaly))
    )


def score_event(
    vector: tuple[float, ...],
    weights: tuple[float, ...],
    bias: float,
    entropy_score: float,
    burst_score: float,
    process_anomaly: float,
) -> ScoreBreakdown:
    model_prediction = logistic_prediction(vector, weights, bias)
    score = fuse_signals(model_prediction, entropy_score, burst_score, process_anomaly)
    return ScoreBreakdown(
        model_prediction=model_prediction,
        entropy_score=_round64(entropy_score),
        burst_score=_round64(burst_score),
        process_anomaly=_round64(process_anomaly),
        score=score,
        decision="malicious" if score > SCORE_THRESHOLD else "benign",
        sine_pass=bool(score > SINE_MIN_THRESHOLD),
    )


def _sigmoid(value: float) -> float:
    if value >= 0:
        exponent = np.exp(-value)
        return _round64(np.float64(np.float64(1.0) / np.float64(1.0 + exponent)))
    exponent = np.exp(value)
    return _round64(np.float64(exponent / np.float64(1.0 + exponent)))


def _round64(value: float) -> float:
    return np.float64(np.round(np.float64(value), 8))
