-- Migration 003: current agent sessions.

CREATE TABLE IF NOT EXISTS agent_sessions (
    session_id         UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id           UUID        NOT NULL,
    tenant_id          UUID        NOT NULL,
    boot_session_id    UUID        NOT NULL,
    hostname           TEXT        NOT NULL,
    primary_ip         INET        NOT NULL,
    agent_type         TEXT        NOT NULL
                                  CHECK (agent_type IN ('linux', 'windows', 'dpi', 'netflow', 'syslog', 'snmp')),
    agent_version      TEXT        NOT NULL DEFAULT 'V0.0',
    binary_hash        TEXT        NOT NULL DEFAULT repeat('0', 64)
                                  CHECK (binary_hash ~ '^[0-9a-f]{64}$'),
    tpm_quote          BYTEA       NOT NULL DEFAULT '\x'::bytea,
    tpm_pcr_values     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    last_heartbeat     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status             TEXT        NOT NULL DEFAULT 'ACTIVE'
                                  CHECK (status IN ('ACTIVE', 'DEGRADED', 'OFFLINE', 'SUSPECTED_COMPROMISE', 'QUARANTINED')),
    lamport_clock      BIGINT      NOT NULL DEFAULT 0 CHECK (lamport_clock >= 0),
    os_info            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    last_seen_ip       INET        NOT NULL DEFAULT '0.0.0.0'::inet,
    is_critical_asset  BOOLEAN     NOT NULL DEFAULT FALSE,
    enrolled_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agent_sessions_agent UNIQUE (agent_id)
);

SELECT register_migration(3, 'agent_sessions');
