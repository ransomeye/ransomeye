BEGIN;

-- PRD-03 §2 Migration 013: chat_sessions (PRD-08 V0.0 — SINE).
-- SINE interactive chat audit metadata. SINE itself never writes to PostgreSQL (Core persists via gRPC).

CREATE TABLE IF NOT EXISTS chat_sessions (
    chat_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(tenant_id),
    detection_id   UUID        REFERENCES detections(detection_id),
    user_id        UUID,
    messages       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    worm_sealed    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_tenant_time
    ON chat_sessions(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_detection
    ON chat_sessions(detection_id);

COMMIT;

