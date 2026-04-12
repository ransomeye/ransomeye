BEGIN;

-- PRD-03 §2 Migration 021: threat_actor_groups (PRD-11 V0.0).

CREATE TABLE IF NOT EXISTS threat_actor_groups (
    group_id      UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(tenant_id),
    group_name    TEXT        NOT NULL,
    known_ttps    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    known_tools   TEXT[]      NOT NULL DEFAULT ARRAY[]::text[],
    notes         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_threat_actor_group UNIQUE (tenant_id, group_name)
);

CREATE INDEX IF NOT EXISTS idx_threat_actor_groups_tenant
    ON threat_actor_groups(tenant_id, updated_at DESC);

COMMIT;

