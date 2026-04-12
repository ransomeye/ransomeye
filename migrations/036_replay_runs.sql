BEGIN;

-- PRD-03 §2 Migration 036: replay_runs (PRD-10 V0.0 §18 — Attack Replay Engine).
-- Ownership: PRD-10 V0.0 §18 (NOT PRD-29, which does not exist).

CREATE TABLE IF NOT EXISTS replay_runs (
    replay_id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL REFERENCES tenants(tenant_id),
    case_id              UUID        REFERENCES cases(case_id),
    detection_id         UUID        REFERENCES detections(detection_id),
    status               TEXT        NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED')),
    started_at           TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,
    events_processed     INTEGER     NOT NULL DEFAULT 0 CHECK (events_processed >= 0),
    replay_timeline_json JSONB,
    sine_narrative       TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;

