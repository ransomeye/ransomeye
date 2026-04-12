-- Migration 015: incidents, cases, and investigative artifacts.

CREATE TABLE IF NOT EXISTS incidents (
    incident_id       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    title             TEXT        NOT NULL,
    description       TEXT        NOT NULL DEFAULT '',
    severity          TEXT        NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status            TEXT        NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')),
    assigned_to       TEXT        NOT NULL DEFAULT '',
    created_by        TEXT        NOT NULL DEFAULT '',
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS actions (
    action_id            UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL,
    detection_id         UUID,
    agent_id             UUID,
    action_type          TEXT        NOT NULL
                                      CHECK (action_type IN (
                                          'KILL_PROCESS',
                                          'BLOCK_IP',
                                          'ISOLATE_HOST',
                                          'FILE_ROLLBACK',
                                          'SNAPSHOT_MEMORY',
                                          'ALERT_ONLY'
                                      )),
    action_params        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    status               TEXT        NOT NULL DEFAULT 'PENDING'
                                      CHECK (status IN (
                                          'PENDING',
                                          'PENDING_CONFIRMATION',
                                          'PENDING_APPROVAL',
                                          'DISPATCHED',
                                          'COMPLETED',
                                          'FAILED',
                                          'CANCELLED'
                                      )),
    result_detail        TEXT        NOT NULL DEFAULT '',
    dispatched_by        TEXT        NOT NULL DEFAULT '',
    dispatched_at        TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    completed_at         TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    approval_required    BOOLEAN     NOT NULL DEFAULT FALSE,
    approved_by          TEXT        NOT NULL DEFAULT '',
    approved_at          TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    second_approver_id   UUID,
    second_approved_at   TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    totp_verified_at     TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cases (
    case_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id    UUID,
    tenant_id      UUID        NOT NULL,
    title          TEXT        NOT NULL,
    description    TEXT        NOT NULL DEFAULT '',
    severity       TEXT        NOT NULL DEFAULT 'MEDIUM' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status         TEXT        NOT NULL DEFAULT 'OPEN'
                                  CHECK (status IN (
                                      'OPEN',
                                      'INVESTIGATING',
                                      'PENDING_REVIEW',
                                      'CLOSED_TRUE_POSITIVE',
                                      'CLOSED_FALSE_POSITIVE'
                                  )),
    created_by     TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at      TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00'
);

CREATE TABLE IF NOT EXISTS corroboration_reports (
    report_id      UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL,
    detection_id   UUID        NOT NULL,
    report_json    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS chat_sessions (
    chat_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL,
    detection_id   UUID,
    user_id        UUID,
    messages       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    worm_sealed    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT register_migration(15, 'incidents');
