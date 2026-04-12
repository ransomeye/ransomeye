-- Migration 002: tenants and agent inventory.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id    UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_name  TEXT        NOT NULL,
    tenant_slug  TEXT        NOT NULL,
    dek_wrapped  BYTEA       NOT NULL CHECK (octet_length(dek_wrapped) = 60),
    status       TEXT        NOT NULL DEFAULT 'ACTIVE'
                            CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DECOMMISSIONED')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenants_name UNIQUE (tenant_name),
    CONSTRAINT uq_tenants_slug UNIQUE (tenant_slug)
);

INSERT INTO tenants (
    tenant_id,
    tenant_name,
    tenant_slug,
    dek_wrapped,
    status,
    created_at,
    updated_at
)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'SYSTEM',
    'system',
    decode(repeat('00', 60), 'hex'),
    'ACTIVE',
    '1970-01-01 00:00:00+00',
    '1970-01-01 00:00:00+00'
)
ON CONFLICT (tenant_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS agents (
    agent_id           UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL,
    external_agent_id  UUID,
    agent_type         TEXT        NOT NULL
                                  CHECK (agent_type IN ('linux', 'windows', 'dpi', 'netflow', 'syslog', 'snmp')),
    hostname           TEXT        NOT NULL,
    primary_ip         INET        NOT NULL,
    platform           TEXT        NOT NULL DEFAULT 'unknown',
    agent_version      TEXT        NOT NULL DEFAULT 'V0.0',
    binary_hash        TEXT        NOT NULL DEFAULT repeat('0', 64)
                                  CHECK (binary_hash ~ '^[0-9a-f]{64}$'),
    status             TEXT        NOT NULL DEFAULT 'ACTIVE'
                                  CHECK (status IN ('ACTIVE', 'DEGRADED', 'OFFLINE', 'QUARANTINED', 'RETIRED')),
    metadata           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    enrolled_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at         TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agents_tenant_host_type UNIQUE (tenant_id, hostname, agent_type)
);

SELECT register_migration(2, 'agents');
