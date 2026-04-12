-- Migration 013: append-only Merkle leaf ledger.

CREATE TABLE IF NOT EXISTS merkle_tree (
    merkle_entry_id  UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    source_table     TEXT        NOT NULL,
    source_pk        UUID        NOT NULL,
    payload_hash     TEXT        NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    prev_root_hash   TEXT        NOT NULL DEFAULT '' CHECK (prev_root_hash = '' OR prev_root_hash ~ '^[0-9a-f]{64}$'),
    root_hash        TEXT        NOT NULL CHECK (root_hash ~ '^[0-9a-f]{64}$'),
    leaf_sequence    BIGINT      NOT NULL CHECK (leaf_sequence >= 1),
    chain_depth      BIGINT      NOT NULL DEFAULT 1 CHECK (chain_depth >= 1),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_merkle_tree_tenant_sequence UNIQUE (tenant_id, leaf_sequence)
);

CREATE TABLE IF NOT EXISTS exposure_worm_ledger (
    ledger_id         UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    evidence_id       UUID        NOT NULL,
    leaf_hash         TEXT        NOT NULL CHECK (leaf_hash ~ '^[0-9a-f]{64}$'),
    merkle_position   BIGINT      NOT NULL CHECK (merkle_position >= 1),
    daily_date        DATE        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_exposure_worm_ledger_evidence UNIQUE (evidence_id)
);

SELECT register_migration(13, 'merkle_tree');
