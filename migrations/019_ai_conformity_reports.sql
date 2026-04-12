BEGIN;

-- PRD-03 §2 Migration 019: ai_conformity_reports (PRD-20 V0.0).

CREATE TABLE IF NOT EXISTS ai_conformity_reports (
    report_id     UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(tenant_id),
    model_id      TEXT        NOT NULL,
    model_version TEXT        NOT NULL,
    report_json   JSONB       NOT NULL,
    generated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ai_conformity UNIQUE (tenant_id, model_id, model_version)
);

CREATE INDEX IF NOT EXISTS idx_ai_conformity_tenant_time
    ON ai_conformity_reports(tenant_id, generated_at DESC);

COMMIT;

