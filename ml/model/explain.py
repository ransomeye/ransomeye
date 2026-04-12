from __future__ import annotations

from dataclasses import dataclass

from ml.common.np_compat import np
from ml.model.scorer import ScoreBreakdown, fuse_signals


@dataclass(frozen=True, slots=True)
class LeaveOneOutImpact:
    feature: str
    impact: float
    value: float


def explain_score(breakdown: ScoreBreakdown, limit: int = 4) -> tuple[LeaveOneOutImpact, ...]:
    signals = (
        ("model_prediction", breakdown.model_prediction),
        ("entropy_score", breakdown.entropy_score),
        ("burst_score", breakdown.burst_score),
        ("process_anomaly", breakdown.process_anomaly),
    )
    impacts: list[LeaveOneOutImpact] = []
    for feature_name, value in signals:
        recomputed = _recompute_without(breakdown, feature_name)
        impacts.append(
            LeaveOneOutImpact(
                feature=feature_name,
                impact=_round64(breakdown.score - recomputed),
                value=_round64(value),
            )
        )
    impacts.sort(key=lambda item: (-item.impact, item.feature))
    return tuple(impacts[:limit])


def _recompute_without(breakdown: ScoreBreakdown, missing_feature: str) -> float:
    model_prediction = 0.0 if missing_feature == "model_prediction" else breakdown.model_prediction
    entropy_score = 0.0 if missing_feature == "entropy_score" else breakdown.entropy_score
    burst_score = 0.0 if missing_feature == "burst_score" else breakdown.burst_score
    process_anomaly = 0.0 if missing_feature == "process_anomaly" else breakdown.process_anomaly
    return _round64(fuse_signals(model_prediction, entropy_score, burst_score, process_anomaly))


def _round64(value: float) -> float:
    return np.float64(np.round(np.float64(value), 8))
