-- Migration 021: threat intelligence catalog.

CREATE TABLE IF NOT EXISTS intel_indicators (
    indicator_id       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL,
    indicator_type     TEXT        NOT NULL CHECK (indicator_type IN ('IP_ADDRESS', 'DOMAIN', 'JA3_HASH', 'FILE_HASH', 'URL', 'EMAIL')),
    value              TEXT        NOT NULL,
    indicator          TEXT        GENERATED ALWAYS AS (value) STORED,
    indicator_sha256   TEXT        GENERATED ALWAYS AS (encode(digest(lower(value), 'sha256'), 'hex')) STORED,
    confidence         NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    threat_type        TEXT        NOT NULL DEFAULT '',
    source             TEXT        NOT NULL DEFAULT '',
    source_ref         TEXT        NOT NULL DEFAULT '',
    first_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NOT NULL DEFAULT '9999-12-31 00:00:00+00',
    is_active          BOOLEAN     NOT NULL DEFAULT TRUE,
    tags               JSONB       NOT NULL DEFAULT '[]'::jsonb,
    metadata           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_intel_indicator_value UNIQUE (tenant_id, indicator_type, value)
);

CREATE TABLE IF NOT EXISTS threat_actor_groups (
    group_id         UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    group_name       TEXT        NOT NULL,
    known_ttps       JSONB       NOT NULL DEFAULT '[]'::jsonb,
    known_tools      TEXT[]      NOT NULL DEFAULT ARRAY[]::text[],
    notes            TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_threat_actor_group UNIQUE (tenant_id, group_name)
);

CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    ioc_id           UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    indicator_id     UUID        NOT NULL,
    actor_group_id   UUID,
    confidence       NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    source_feed      TEXT        NOT NULL DEFAULT '',
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL DEFAULT '9999-12-31 00:00:00+00',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT register_migration(21, 'intel_indicators');
