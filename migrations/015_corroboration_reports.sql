BEGIN;

-- PRD-03 §2 Migration 015: corroboration_reports (PRD-07 V0.0 / PRD-08 V0.0).

CREATE TABLE IF NOT EXISTS corroboration_reports (
    report_id     UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(tenant_id),
    detection_id  UUID        NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    report_json   JSONB       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_corroboration_reports_detection
    ON corroboration_reports(detection_id);

COMMIT;

