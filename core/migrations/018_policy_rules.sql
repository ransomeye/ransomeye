-- Migration 018: enforcement policy definitions.

CREATE TABLE IF NOT EXISTS policy_rules (
    rule_id                 UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,
    rule_name               TEXT        NOT NULL,
    description             TEXT        NOT NULL DEFAULT '',
    trigger_aec_class       SMALLINT    NOT NULL CHECK (trigger_aec_class IN (1, 2, 3)),
    trigger_posterior_min   NUMERIC(10,8) NOT NULL CHECK (trigger_posterior_min > 0 AND trigger_posterior_min < 1),
    action_type             TEXT        NOT NULL
                                         CHECK (action_type IN (
                                             'KILL_PROCESS',
                                             'BLOCK_IP',
                                             'ISOLATE_HOST',
                                             'FILE_ROLLBACK',
                                             'SNAPSHOT_MEMORY',
                                             'ALERT_ONLY'
                                         )),
    is_active               BOOLEAN     NOT NULL DEFAULT TRUE,
    requires_approval       BOOLEAN     NOT NULL DEFAULT FALSE,
    approval_count          INTEGER     NOT NULL DEFAULT 0 CHECK (approval_count >= 0),
    rule_json               JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_by              TEXT        NOT NULL DEFAULT '',
    signed_by               JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_policy_rules_name UNIQUE (tenant_id, rule_name)
);

CREATE TABLE IF NOT EXISTS threat_hunt_rules (
    hunt_rule_id     UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    rule_name        TEXT        NOT NULL,
    description      TEXT        NOT NULL DEFAULT '',
    source           TEXT        NOT NULL CHECK (source IN ('analyst', 'sigmahq', 'sine_generated')),
    rule_yaml        TEXT        NOT NULL,
    tags             JSONB       NOT NULL DEFAULT '[]'::jsonb,
    is_active        BOOLEAN     NOT NULL DEFAULT TRUE,
    created_by       TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_threat_hunt_rules_name UNIQUE (tenant_id, rule_name)
);

SELECT register_migration(18, 'policy_rules');
