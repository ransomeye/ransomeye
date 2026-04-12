BEGIN;

-- PRD-03 §2 Migration 017: signal_recalibration_audit (PRD-07 V0.0).
-- Analyst-approved signal weight changes (governed; auditable).

CREATE TABLE IF NOT EXISTS signal_recalibration_audit (
    audit_id        BIGSERIAL   NOT NULL PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    agent_id        UUID        REFERENCES agent_sessions(agent_id),
    signal_type     TEXT        NOT NULL CHECK (signal_type IN ('process','file','network','user','deception')),
    old_weight      NUMERIC(10,8) NOT NULL CHECK (old_weight >= 0),
    new_weight      NUMERIC(10,8) NOT NULL CHECK (new_weight >= 0),
    reason          TEXT,
    approved_by     TEXT        NOT NULL,
    approved_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signal_recalibration_tenant_time
    ON signal_recalibration_audit(tenant_id, approved_at DESC);

COMMIT;

