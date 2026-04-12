from __future__ import annotations

from dataclasses import dataclass

from ml.dataset.schema import CanonicalDataset, canonical_dataset_hash
from ml.features.sequence import VECTOR_LENGTH, build_sequence_features


@dataclass(frozen=True, slots=True)
class FeatureMatrix:
    feature_names: tuple[str, ...]
    vectors: tuple[tuple[float, ...], ...]
    labels: tuple[int, ...]
    entropy_scores: tuple[float, ...]
    burst_scores: tuple[float, ...]
    process_anomaly_scores: tuple[float, ...]
    dataset_hash: str
    feature_version: str


def extract_features(dataset: CanonicalDataset) -> FeatureMatrix:
    if not dataset.records:
        raise ValueError("canonical dataset must contain at least one record")

    sequence_features = build_sequence_features(dataset)
    labels: list[int] = []
    for record in dataset.records:
        labels.append(record.label_id)

    return FeatureMatrix(
        feature_names=sequence_features.feature_names,
        vectors=sequence_features.vectors,
        labels=tuple(labels),
        entropy_scores=sequence_features.entropy_scores,
        burst_scores=sequence_features.burst_scores,
        process_anomaly_scores=sequence_features.process_anomaly_scores,
        dataset_hash=canonical_dataset_hash(dataset),
        feature_version=dataset.feature_version,
    )
