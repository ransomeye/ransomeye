-- PRD-10: immutable forensic index of exact payload bytes (never derived from parsed fields).
-- Stored hash MUST equal digest(payload_bytes) at all times.

ALTER TABLE telemetry_events
    ADD COLUMN IF NOT EXISTS payload_sha256 BYTEA
    GENERATED ALWAYS AS (digest(payload_bytes, 'sha256')) STORED;

COMMENT ON COLUMN telemetry_events.payload_sha256 IS 'SHA-256(payload_bytes); generated/stored for indexing and parity verification.';
