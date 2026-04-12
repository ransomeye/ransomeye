from __future__ import annotations

import base64
import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from .schema import (
    CanonicalDataset,
    CanonicalRecord,
    DEFAULT_FEATURE_VERSION,
    EVENT_TYPE_ENUM,
    LABEL_ENUM,
    RAW_WORM_TELEMETRY_FIELDS,
    RAW_WORM_TELEMETRY_NANO_FIELDS,
    RRE_ENVELOPE_FIELDS,
    RRE_EVENT_FIELDS,
    SCHEMA_VERSION,
    canonical_dataset_bytes,
)


def load_dataset(input_path: Path, feature_version: str = DEFAULT_FEATURE_VERSION) -> CanonicalDataset:
    path = Path(input_path)
    raw_records = _load_raw_records(path)
    canonical_records = tuple(
        sorted(
            (_canonical_record(record, path.suffix.lower()) for record in raw_records),
            key=lambda item: (item.sequence_id, item.timestamp),
        )
    )
    return CanonicalDataset(
        schema_version=SCHEMA_VERSION,
        feature_version=feature_version,
        records=canonical_records,
    )


def write_canonical_dataset(dataset: CanonicalDataset, output_path: Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_dataset_bytes(dataset) + b"\n")


def _load_raw_records(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".rre":
        return _load_rre(path)
    return _load_worm_json(path)


def _load_rre(path: Path) -> list[dict[str, Any]]:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    _require_mapping(envelope, "replay_envelope")
    _require_exact_keys(envelope, RRE_ENVELOPE_FIELDS, "replay_envelope")
    events = _require_list(envelope, "events")
    records: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        record = _require_mapping(event, f"events[{index}]")
        _require_exact_keys(record, RRE_EVENT_FIELDS, f"events[{index}]")
        event_type = _require_string(record, "event_type")
        dropped = _require_non_negative_int(record, "dropped_packets_before")
        records.append(
            {
                "sequence_id": _require_non_negative_int(record, "sequence_id"),
                "timestamp": _require_non_negative_int(record, "timestamp_unix_nano"),
                "agent_id": _require_string(record, "agent_id"),
                "event_type": event_type,
                "payload_base64": _require_string(record, "payload_base64"),
                "dropped_packets_before": dropped,
                "label": _label_from_replay_event(event_type, dropped),
            }
        )
    return records


def _load_worm_json(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"dataset input is empty: {path}")

    if text.startswith("["):
        values = json.loads(text)
        items = _require_list(values, "worm_telemetry")
        return [_normalize_worm_record(_require_mapping(item, "worm_telemetry")) for item in items]

    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        value = json.loads(stripped)
        records.append(_normalize_worm_record(_require_mapping(value, f"worm_telemetry line {line_no}")))
    return records


def _canonical_record(record: dict[str, Any], source_suffix: str) -> CanonicalRecord:
    payload_base64 = _require_string(record, "payload_base64")
    payload = _decode_base64(payload_base64)
    event_type = _require_string(record, "event_type")
    label = _require_string(record, "label")

    return CanonicalRecord(
        sequence_id=_require_non_negative_int(record, "sequence_id"),
        timestamp=_require_non_negative_int(record, "timestamp"),
        agent_id=_require_string(record, "agent_id"),
        event_type=event_type,
        event_type_id=_enum_id(EVENT_TYPE_ENUM, event_type, "event_type"),
        payload_base64=payload_base64,
        payload_sha256=sha256(payload).hexdigest(),
        payload_size=len(payload),
        dropped_packets_before=_require_non_negative_int(record, "dropped_packets_before"),
        label=label,
        label_id=_enum_id(LABEL_ENUM, label, "label"),
    )


def _label_from_replay_event(event_type: str, dropped_packets_before: int) -> str:
    if dropped_packets_before > 0 or event_type in {"NETWORK_EVENT", "DECEPTION_EVENT"}:
        return "malicious"
    return "benign"


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # pragma: no cover - invalid input path.
        raise ValueError("payload_base64 must be valid base64") from exc


def _enum_id(mapping: dict[str, int], value: str, field_name: str) -> int:
    if value not in mapping:
        raise ValueError(f"{field_name} must be one of {sorted(mapping)}, got {value!r}")
    return mapping[value]


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return value


def _require_list(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    return value


def _require_string(record: dict[str, Any], field_name: str) -> str:
    value = record.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required and must be a non-empty string")
    return value.strip()


def _require_non_negative_int(record: dict[str, Any], field_name: str) -> int:
    value = record.get(field_name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} is required and must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} is required and must be non-negative")
    return int(value)


def _require_exact_keys(record: dict[str, Any], expected_fields: tuple[str, ...], field_name: str) -> None:
    actual = set(record)
    expected = set(expected_fields)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing={missing}")
    if extra:
        details.append(f"extra={extra}")
    raise ValueError(f"{field_name} must contain the strict schema ({', '.join(details)})")


def _normalize_worm_record(record: dict[str, Any]) -> dict[str, Any]:
    fields = set(record)
    timestamp_value: int
    if fields == set(RAW_WORM_TELEMETRY_FIELDS):
        timestamp_value = _require_non_negative_int(record, "timestamp")
    elif fields == set(RAW_WORM_TELEMETRY_NANO_FIELDS):
        timestamp_value = _require_non_negative_int(record, "timestamp_unix_nano")
    else:
        _require_exact_keys(record, RAW_WORM_TELEMETRY_FIELDS, "worm_telemetry")
        timestamp_value = _require_non_negative_int(record, "timestamp")

    return {
        "sequence_id": _require_non_negative_int(record, "sequence_id"),
        "timestamp": timestamp_value,
        "agent_id": _require_string(record, "agent_id"),
        "event_type": _require_string(record, "event_type"),
        "payload_base64": _require_string(record, "payload_base64"),
        "dropped_packets_before": _require_non_negative_int(record, "dropped_packets_before"),
        "label": _require_string(record, "label"),
    }
