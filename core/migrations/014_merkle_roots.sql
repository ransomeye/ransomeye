-- Migration 014: rolling and daily Merkle roots.

CREATE TABLE IF NOT EXISTS merkle_roots (
    root_id          UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    source_table     TEXT        NOT NULL,
    source_pk        UUID        NOT NULL,
    payload_hash     TEXT        NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    prev_root_hash   TEXT        NOT NULL DEFAULT '' CHECK (prev_root_hash = '' OR prev_root_hash ~ '^[0-9a-f]{64}$'),
    root_hash        TEXT        NOT NULL CHECK (root_hash ~ '^[0-9a-f]{64}$'),
    leaf_sequence    BIGINT      NOT NULL CHECK (leaf_sequence >= 1),
    computed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ed25519_sig      TEXT        NOT NULL DEFAULT '',
    CONSTRAINT uq_merkle_roots_tenant_sequence UNIQUE (tenant_id, leaf_sequence)
);

CREATE TABLE IF NOT EXISTS merkle_daily_roots (
    daily_root_id    UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    daily_date       DATE        NOT NULL,
    merkle_root      TEXT        NOT NULL CHECK (merkle_root ~ '^[0-9a-f]{64}$'),
    prev_root_hash   TEXT        NOT NULL DEFAULT '' CHECK (prev_root_hash = '' OR prev_root_hash ~ '^[0-9a-f]{64}$'),
    leaf_count       INTEGER     NOT NULL DEFAULT 0 CHECK (leaf_count >= 0),
    computed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ed25519_sig      TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_merkle_daily_roots_tenant_day UNIQUE (tenant_id, daily_date)
);

SELECT register_migration(14, 'merkle_roots');
