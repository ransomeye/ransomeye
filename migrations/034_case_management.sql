BEGIN;

-- PRD-03 §2 Migration 034: cases, case_artifacts, case_notes (PRD-10 V0.0 — Case Management).
-- Ownership: PRD-10 V0.0 (NOT PRD-25, which does not exist).

CREATE TABLE IF NOT EXISTS cases (
    case_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(tenant_id),
    title        TEXT        NOT NULL,
    description  TEXT,
    severity     TEXT        NOT NULL DEFAULT 'MEDIUM' CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    status       TEXT        NOT NULL DEFAULT 'OPEN' CHECK (status IN (
                    'OPEN','INVESTIGATING','PENDING_REVIEW','CLOSED_TRUE_POSITIVE','CLOSED_FALSE_POSITIVE')),
    created_by   TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS case_artifacts (
    artifact_id   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID        NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    tenant_id     UUID        NOT NULL REFERENCES tenants(tenant_id),
    artifact_type TEXT        NOT NULL CHECK (artifact_type IN (
                    'DETECTION','WORM_EVIDENCE','ACTION','TELEMETRY_EVENT','EXTERNAL_FILE')),
    reference_id  TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_notes (
    note_id     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id     UUID        NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    tenant_id   UUID        NOT NULL REFERENCES tenants(tenant_id),
    analyst     TEXT        NOT NULL,
    note_text   TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;

