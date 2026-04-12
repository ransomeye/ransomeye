BEGIN;

-- PRD-03 §2 Migration 014: threat_hunt_rules (PRD-08 V0.0 — SINE / Hunt).

CREATE TABLE IF NOT EXISTS threat_hunt_rules (
    rule_id      UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(tenant_id),
    rule_name    TEXT        NOT NULL,
    description  TEXT,
    source       TEXT        NOT NULL CHECK (source IN ('analyst','sigmahq','sine_generated')),
    rule_yaml    TEXT        NOT NULL,
    tags         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    is_active    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_hunt_rule_name UNIQUE (tenant_id, rule_name)
);

CREATE INDEX IF NOT EXISTS idx_threat_hunt_rules_active
    ON threat_hunt_rules(tenant_id, is_active, updated_at DESC);

COMMIT;

