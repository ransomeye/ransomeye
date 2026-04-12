BEGIN;

-- PRD-03 §2 Migration 031: soc_users (PRD-14 V0.0).

CREATE TABLE IF NOT EXISTS soc_users (
    user_id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    username        TEXT        NOT NULL UNIQUE,
    password_hash   TEXT        NOT NULL,
    totp_secret     TEXT        NOT NULL,
    role            TEXT        NOT NULL DEFAULT 'ANALYST' CHECK (role IN ('ANALYST','ADMIN','AUDITOR')),
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ,
    failed_attempts INTEGER     NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ
);

ALTER TABLE chat_sessions ADD CONSTRAINT fk_chat_sessions_user FOREIGN KEY (user_id) REFERENCES soc_users(user_id);

COMMIT;

