-- Migration 019: policy versioning, SOC auth, and compliance audit objects.

CREATE TABLE IF NOT EXISTS policy_versions (
    version_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    rule_id           UUID        NOT NULL,
    version_number    INTEGER     NOT NULL CHECK (version_number >= 1),
    rule_sha256       TEXT        NOT NULL CHECK (rule_sha256 ~ '^[0-9a-f]{64}$'),
    rule_json         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_by        TEXT        NOT NULL DEFAULT '',
    approved_by       TEXT        NOT NULL DEFAULT '',
    approved_at       TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    superseded_at     TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_policy_versions_rule_version UNIQUE (rule_id, version_number)
);

CREATE TABLE IF NOT EXISTS soc_users (
    user_id           UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    username          TEXT        NOT NULL,
    password_hash     TEXT        NOT NULL,
    totp_secret       TEXT        NOT NULL,
    role              TEXT        NOT NULL DEFAULT 'ANALYST' CHECK (role IN ('ANALYST', 'ADMIN', 'AUDITOR')),
    is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at     TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    failed_attempts   INTEGER     NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until      TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    CONSTRAINT uq_soc_users_username UNIQUE (username)
);

CREATE TABLE IF NOT EXISTS soc_sessions (
    session_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token     TEXT        NOT NULL,
    user_id           UUID        NOT NULL,
    tenant_id         UUID        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '8 hours'),
    revoked_at        TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    ip_address        INET        NOT NULL DEFAULT '0.0.0.0'::inet,
    user_agent        TEXT        NOT NULL DEFAULT '',
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_soc_sessions_token UNIQUE (session_token)
);

CREATE TABLE IF NOT EXISTS compliance_reports (
    report_id             UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID        NOT NULL,
    report_type           TEXT        NOT NULL CHECK (report_type IN ('SOC2', 'ISO27001', 'GDPR', 'NIS2', 'CUSTOM')),
    report_period_start   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    report_period_end     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    report_json           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    report_pdf_path       TEXT        NOT NULL DEFAULT '',
    generated_by          TEXT        NOT NULL DEFAULT '',
    generated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_config_audit (
    audit_id          UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    config_hash       TEXT        NOT NULL CHECK (config_hash ~ '^[0-9a-f]{64}$'),
    config_version    TEXT        NOT NULL,
    action            TEXT        NOT NULL CHECK (action IN ('LOADED', 'VERIFIED', 'REJECTED', 'UPDATED')),
    signatures        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    signature_count   INTEGER     NOT NULL DEFAULT 0 CHECK (signature_count >= 0),
    details           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    source_service    TEXT        NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_conformity_reports (
    report_id         UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    model_id          TEXT        NOT NULL,
    model_version     TEXT        NOT NULL,
    report_json       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    generated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ai_conformity_reports UNIQUE (tenant_id, model_id, model_version)
);

SELECT register_migration(19, 'policy_versions');
