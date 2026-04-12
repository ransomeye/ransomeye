-- Migration 017: immutable incident notes and case notes.

CREATE TABLE IF NOT EXISTS incident_notes (
    note_id         UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID        NOT NULL,
    tenant_id       UUID        NOT NULL,
    author          TEXT        NOT NULL,
    note_text       TEXT        NOT NULL,
    note_sha256     TEXT        GENERATED ALWAYS AS (encode(digest(note_text, 'sha256'), 'hex')) STORED,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_notes (
    note_id         UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID        NOT NULL,
    tenant_id       UUID        NOT NULL,
    analyst         TEXT        NOT NULL,
    note_text       TEXT        NOT NULL,
    note_sha256     TEXT        GENERATED ALWAYS AS (encode(digest(note_text, 'sha256'), 'hex')) STORED,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT register_migration(17, 'incident_notes');
