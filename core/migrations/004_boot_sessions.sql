-- Migration 004: boot session history.

CREATE TABLE IF NOT EXISTS boot_session_id_history (
    boot_history_id  UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id         UUID        NOT NULL,
    tenant_id        UUID        NOT NULL,
    boot_session_id  UUID        NOT NULL,
    first_seen_ip    INET        NOT NULL,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_boot_history_agent_session UNIQUE (agent_id, boot_session_id)
);

CREATE OR REPLACE VIEW boot_sessions AS
SELECT
    boot_history_id AS boot_session_record_id,
    agent_id,
    tenant_id,
    boot_session_id,
    first_seen_ip,
    first_seen_at,
    last_seen_at,
    created_at,
    updated_at
FROM boot_session_id_history;

SELECT register_migration(4, 'boot_sessions');
