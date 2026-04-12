-- Migration 025: immutable bundle application audit trail.

CREATE TABLE IF NOT EXISTS bundle_application_log (
    log_id            UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    bundle_id         UUID        NOT NULL,
    bundle_type       TEXT        NOT NULL
                                   CHECK (bundle_type IN (
                                       'FULL',
                                       'BINARY',
                                       'MODEL_CONFIG',
                                       'MODEL_WEIGHTS',
                                       'INTEL_FEED',
                                       'CERT_ROTATION',
                                       'UI_ASSETS',
                                       'KEY_ROTATION'
                                   )),
    sequence_number   BIGINT      NOT NULL CHECK (sequence_number >= 1),
    applied_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by        TEXT        NOT NULL DEFAULT 'root',
    artifacts_json    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    migrations_json   JSONB       NOT NULL DEFAULT '[]'::jsonb,
    outcome           TEXT        NOT NULL CHECK (outcome IN ('SUCCESS', 'ROLLBACK', 'MANUAL_ROLLBACK')),
    failure_reason    TEXT        NOT NULL DEFAULT '',
    bundle_sha256     TEXT        NOT NULL CHECK (bundle_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT register_migration(25, 'bundle_application_log');
