from __future__ import annotations

import base64
import math
from dataclasses import dataclass
from hashlib import sha256

from ml.common.np_compat import np
from ml.dataset.schema import CanonicalDataset


SEQUENCE_WINDOW_SIZE = 10
MAX_TIME_DELTA_NS = 5_000_000_000
BURST_THRESHOLD_NS = 1_500_000_000
MAX_PROCESS_ID = 4095
MAX_CHAIN_DEPTH = 6
MAX_PRIVILEGE_LEVEL = 3
MAX_DROPPED_PACKETS = 8

PRIVILEGE_LEVEL_ENUM = {
    "USER_EVENT": 0,
    "FILE_EVENT": 1,
    "PROCESS_EVENT": 2,
    "NETWORK_EVENT": 2,
    "DECEPTION_EVENT": 3,
}

FEATURE_NAMES = (
    "event_type_norm",
    "time_delta_norm",
    "process_id_norm",
    "entropy_norm",
    "burst_flag",
    "chain_depth_norm",
    "execution_frequency_norm",
    "privilege_level_norm",
    "dropped_packets_norm",
    "window_entropy_mean",
    "window_burst_ratio",
    "window_process_anomaly_mean",
    "window_execution_frequency_mean",
    "window_time_delta_mean",
    "window_privilege_mean",
)
VECTOR_LENGTH = len(FEATURE_NAMES)


@dataclass(frozen=True, slots=True)
class SequenceFeatures:
    feature_names: tuple[str, ...]
    vectors: tuple[tuple[float, ...], ...]
    entropy_scores: tuple[float, ...]
    burst_scores: tuple[float, ...]
    process_anomaly_scores: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class _EventMetrics:
    process_id: int
    entropy_score: float
    burst_score: float
    chain_depth_norm: float
    execution_frequency_norm: float
    privilege_level_norm: float
    dropped_packets_norm: float
    time_delta_norm: float
    process_anomaly: float


def build_sequence_features(dataset: CanonicalDataset) -> SequenceFeatures:
    if not dataset.records:
        raise ValueError("canonical dataset must contain at least one record")

    window: list[_EventMetrics] = []
    vectors: list[tuple[float, ...]] = []
    entropy_scores: list[float] = []
    burst_scores: list[float] = []
    process_anomaly_scores: list[float] = []

    previous_timestamp = dataset.records[0].timestamp
    for index, record in enumerate(dataset.records):
        payload = _decode_payload(record.payload_base64)
        process_id = _process_id(payload)
        time_delta = 0 if index == 0 else max(record.timestamp - previous_timestamp, 0)
        previous_timestamp = record.timestamp

        entropy_score = _round64(_normalize_entropy(shannon_entropy(payload)))
        burst_score = _round64(np.float64(1.0 if index > 0 and time_delta < BURST_THRESHOLD_NS else 0.0))
        chain_depth_norm = _round64(
            _safe_ratio(_chain_depth(record.payload_sha256), MAX_CHAIN_DEPTH)
        )
        execution_frequency = _execution_frequency(window, process_id)
        execution_frequency_norm = _round64(_safe_ratio(execution_frequency, SEQUENCE_WINDOW_SIZE))
        privilege_level_norm = _round64(
            _safe_ratio(PRIVILEGE_LEVEL_ENUM[record.event_type], MAX_PRIVILEGE_LEVEL)
        )
        dropped_packets_norm = _round64(
            _safe_ratio(min(record.dropped_packets_before, MAX_DROPPED_PACKETS), MAX_DROPPED_PACKETS)
        )
        time_delta_norm = _round64(_safe_ratio(min(time_delta, MAX_TIME_DELTA_NS), MAX_TIME_DELTA_NS))
        process_anomaly = _round64(
            np.float64(
                (
                    np.float64(chain_depth_norm)
                    + np.float64(execution_frequency_norm)
                    + np.float64(privilege_level_norm)
                    + np.float64(dropped_packets_norm)
                )
                / np.float64(4.0)
            )
        )

        metrics = _EventMetrics(
            process_id=process_id,
            entropy_score=entropy_score,
            burst_score=burst_score,
            chain_depth_norm=chain_depth_norm,
            execution_frequency_norm=execution_frequency_norm,
            privilege_level_norm=privilege_level_norm,
            dropped_packets_norm=dropped_packets_norm,
            time_delta_norm=time_delta_norm,
            process_anomaly=process_anomaly,
        )
        current_window = tuple(window + [metrics])
        vectors.append(
            (
                _round64(_safe_ratio(record.event_type_id, 5)),
                time_delta_norm,
                _round64(_safe_ratio(process_id, MAX_PROCESS_ID)),
                entropy_score,
                burst_score,
                chain_depth_norm,
                execution_frequency_norm,
                privilege_level_norm,
                dropped_packets_norm,
                _window_mean(current_window, "entropy_score"),
                _window_mean(current_window, "burst_score"),
                _window_mean(current_window, "process_anomaly"),
                _window_mean(current_window, "execution_frequency_norm"),
                _window_mean(current_window, "time_delta_norm"),
                _window_mean(current_window, "privilege_level_norm"),
            )
        )
        entropy_scores.append(entropy_score)
        burst_scores.append(burst_score)
        process_anomaly_scores.append(process_anomaly)

        window.append(metrics)
        if len(window) > SEQUENCE_WINDOW_SIZE - 1:
            window.pop(0)

    return SequenceFeatures(
        feature_names=FEATURE_NAMES,
        vectors=tuple(vectors),
        entropy_scores=tuple(entropy_scores),
        burst_scores=tuple(burst_scores),
        process_anomaly_scores=tuple(process_anomaly_scores),
    )


def shannon_entropy(data: bytes) -> float:
    if not data:
        return np.float64(0.0)

    counts = [0] * 256
    for value in data:
        counts[value] += 1

    total = np.float64(len(data))
    entropy = np.float64(0.0)
    for count in counts:
        if count == 0:
            continue
        probability = np.float64(np.float64(count) / total)
        entropy = np.float64(entropy - np.float64(probability * np.float64(math.log2(float(probability)))))
    return np.float64(np.round(np.float64(entropy), 6))


def _decode_payload(payload_base64: str) -> bytes:
    return base64.b64decode(payload_base64.encode("ascii"), validate=True)


def _process_id(payload: bytes) -> int:
    digest = sha256(payload).hexdigest()
    return 1 + (int(digest[:4], 16) % MAX_PROCESS_ID)


def _chain_depth(payload_sha256: str) -> int:
    return 1 + (int(payload_sha256[4:6], 16) % MAX_CHAIN_DEPTH)


def _execution_frequency(window: list[_EventMetrics], process_id: int) -> int:
    count = 1
    for item in window:
        if item.process_id == process_id:
            count += 1
    return min(count, SEQUENCE_WINDOW_SIZE)


def _normalize_entropy(entropy_bits: float) -> float:
    return _safe_ratio(entropy_bits, 8.0)


def _window_mean(window: tuple[_EventMetrics, ...], field_name: str) -> float:
    total = np.float64(0.0)
    for item in window:
        total = _round64(total + np.float64(getattr(item, field_name)))
    return _round64(np.float64(total / np.float64(len(window))))


def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return np.float64(np.float64(numerator) / np.float64(denominator))


def _round64(value: float) -> float:
    return np.float64(np.round(np.float64(value), 8))
