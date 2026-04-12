BEGIN;

-- PRD-03 §2 Migration 016: fp_suppression_models, fp_suppression_audit (PRD-07 V0.0).
-- FP suppressor is gated; all suppressions must be audited.

CREATE TABLE IF NOT EXISTS fp_suppression_models (
    model_id       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(tenant_id),
    model_version  TEXT        NOT NULL,
    model_type     TEXT        NOT NULL CHECK (model_type IN ('KNN')),
    parameters     JSONB       NOT NULL,
    is_active      BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_fp_model_version UNIQUE (tenant_id, model_version)
);

CREATE TABLE IF NOT EXISTS fp_suppression_audit (
    audit_id          BIGSERIAL   NOT NULL PRIMARY KEY,
    tenant_id         UUID        NOT NULL REFERENCES tenants(tenant_id),
    detection_id      UUID        NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    model_id          UUID        REFERENCES fp_suppression_models(model_id),
    suppression_factor NUMERIC(6,5) NOT NULL CHECK (suppression_factor >= 0 AND suppression_factor <= 1),
    posterior_before  NUMERIC(10,8) NOT NULL CHECK (posterior_before > 0 AND posterior_before < 1),
    posterior_after   NUMERIC(10,8) NOT NULL CHECK (posterior_after > 0 AND posterior_after < 1),
    reason_json       JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fp_suppression_audit_detection
    ON fp_suppression_audit(detection_id);

COMMIT;

