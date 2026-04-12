-- PRD-10 / Phase 3: transport envelope vs canonical byte payload (no JSON in telemetry row).
-- Replaces JSONB payload with exact agent bytes + agent Ed25519 signature.

DROP INDEX IF EXISTS idx_telemetry_payload;

ALTER TABLE telemetry_events
    DROP COLUMN IF EXISTS payload,
    ADD COLUMN IF NOT EXISTS payload_bytes BYTEA NOT NULL DEFAULT '\x'::bytea,
    ADD COLUMN IF NOT EXISTS agent_ed25519_sig BYTEA NOT NULL DEFAULT '\x'::bytea;

COMMENT ON COLUMN telemetry_events.payload_bytes IS 'Exact opaque canonical telemetry bytes (immutable, signed by agent).';
COMMENT ON COLUMN telemetry_events.agent_ed25519_sig IS 'Ed25519 detached signature (64 bytes) over payload_bytes only.';
