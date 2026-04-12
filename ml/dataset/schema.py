from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any


SCHEMA_VERSION = "canonical-dataset-v1"
DEFAULT_FEATURE_VERSION = "ml.features.sequence.v2"

CANONICAL_DATASET_FIELDS = (
    "feature_version",
    "records",
    "schema_version",
)

CANONICAL_RECORD_FIELDS = (
    "sequence_id",
    "timestamp",
    "agent_id",
    "event_type",
    "event_type_id",
    "payload_base64",
    "payload_sha256",
    "payload_size",
    "dropped_packets_before",
    "label",
    "label_id",
)

RAW_WORM_TELEMETRY_FIELDS = (
    "sequence_id",
    "timestamp",
    "agent_id",
    "event_type",
    "payload_base64",
    "dropped_packets_before",
    "label",
)

RAW_WORM_TELEMETRY_NANO_FIELDS = (
    "sequence_id",
    "timestamp_unix_nano",
    "agent_id",
    "event_type",
    "payload_base64",
    "dropped_packets_before",
    "label",
)

RRE_ENVELOPE_FIELDS = (
    "config_hash",
    "events",
    "feature_version",
    "model_hash",
    "prd_hash",
)

RRE_EVENT_FIELDS = (
    "sequence_id",
    "timestamp_unix_nano",
    "dropped_packets_before",
    "agent_id",
    "event_type",
    "payload_base64",
    "agent_signature_base64",
)

EVENT_TYPE_ENUM = {
    "PROCESS_EVENT": 1,
    "FILE_EVENT": 2,
    "NETWORK_EVENT": 3,
    "USER_EVENT": 4,
    "DECEPTION_EVENT": 5,
}

LABEL_ENUM = {
    "benign": 0,
    "malicious": 1,
}


@dataclass(frozen=True, slots=True)
class CanonicalRecord:
    sequence_id: int
    timestamp: int
    agent_id: str
    event_type: str
    event_type_id: int
    payload_base64: str
    payload_sha256: str
    payload_size: int
    dropped_packets_before: int
    label: str
    label_id: int


@dataclass(frozen=True, slots=True)
class CanonicalDataset:
    schema_version: str
    feature_version: str
    records: tuple[CanonicalRecord, ...]


def canonical_dataset_bytes(dataset: CanonicalDataset) -> bytes:
    validate_canonical_dataset(dataset)
    payload = {
        "feature_version": dataset.feature_version,
        "records": [asdict(record) for record in dataset.records],
        "schema_version": dataset.schema_version,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_dataset_hash(dataset: CanonicalDataset) -> str:
    return sha256(canonical_dataset_bytes(dataset)).hexdigest()


def validate_canonical_dataset(dataset: CanonicalDataset) -> None:
    if dataset.schema_version != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION!r}, got {dataset.schema_version!r}")
    _require_text(dataset.feature_version, "feature_version")
    if not isinstance(dataset.records, tuple):
        raise ValueError("records must be a tuple")

    for index, record in enumerate(dataset.records):
        _validate_record(record, index)


def _validate_record(record: CanonicalRecord, index: int) -> None:
    if not isinstance(record, CanonicalRecord):
        raise ValueError(f"records[{index}] must be a CanonicalRecord")
    payload = asdict(record)
    if tuple(sorted(payload)) != tuple(sorted(CANONICAL_RECORD_FIELDS)):
        raise ValueError(f"records[{index}] must contain the strict canonical schema")

    _require_non_negative_int(payload["sequence_id"], f"records[{index}].sequence_id")
    _require_non_negative_int(payload["timestamp"], f"records[{index}].timestamp")
    _require_text(payload["agent_id"], f"records[{index}].agent_id")
    _require_text(payload["event_type"], f"records[{index}].event_type")
    _require_non_negative_int(payload["event_type_id"], f"records[{index}].event_type_id")
    _require_text(payload["payload_base64"], f"records[{index}].payload_base64")
    _require_hex(payload["payload_sha256"], f"records[{index}].payload_sha256", 64)
    _require_non_negative_int(payload["payload_size"], f"records[{index}].payload_size")
    _require_non_negative_int(
        payload["dropped_packets_before"],
        f"records[{index}].dropped_packets_before",
    )
    _require_text(payload["label"], f"records[{index}].label")
    _require_non_negative_int(payload["label_id"], f"records[{index}].label_id")


def _require_text(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_non_negative_int(value: Any, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")


def _require_hex(value: Any, field_name: str, expected_length: int) -> None:
    if not isinstance(value, str) or len(value) != expected_length:
        raise ValueError(f"{field_name} must be a {expected_length}-character hex string")
    if any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{field_name} must be lowercase hex")
