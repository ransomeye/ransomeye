BEGIN;

-- PRD-03 §2 Migration 020: governance_audit_log (PRD-19 V0.0 §12.1).
-- WORM-compliant table: INSERT-only. UPDATE/DELETE must raise IMMUTABILITY_VIOLATION.
-- Trigger function is defined in migrations/006_enforce_worm_immutability.sql.

-- Trigger function.
CREATE OR REPLACE FUNCTION enforce_worm_immutability()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'WORM: row is immutable';
    RETURN NULL;
END;
$$;

CREATE TABLE IF NOT EXISTS governance_audit_log (
    audit_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    event_type      TEXT        NOT NULL CHECK (event_type IN (
                        'POLICY_CREATED','POLICY_UPDATED','POLICY_DELETED',
                        'ACTION_APPROVED','ACTION_REJECTED',
                        'ROLE_GRANTED','ROLE_REVOKED',
                        'CONFIG_CHANGED','MODEL_LOADED','MODEL_REJECTED')),
    actor           TEXT        NOT NULL,
    details_json    JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant_time
    ON governance_audit_log(tenant_id, created_at DESC);

DROP TRIGGER IF EXISTS trg_governance_audit_immutable ON governance_audit_log;
CREATE TRIGGER trg_governance_audit_immutable
    BEFORE UPDATE OR DELETE ON governance_audit_log
    FOR EACH ROW EXECUTE FUNCTION enforce_worm_immutability();

COMMIT;

