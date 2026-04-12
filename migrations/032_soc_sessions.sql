BEGIN;

-- PRD-03 §2 Migration 032: soc_sessions (PRD-14 V0.0).

CREATE TABLE IF NOT EXISTS soc_sessions (
    session_token   TEXT        PRIMARY KEY,
    user_id         UUID        NOT NULL REFERENCES soc_users(user_id),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    ip_address      INET        NOT NULL,
    user_agent      TEXT
);

COMMIT;

