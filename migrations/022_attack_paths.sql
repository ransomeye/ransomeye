BEGIN;

-- PRD-03 §2 Migration 022: attack_paths (PRD-00 V0.0 §13 DB-03).
--
-- CRITICAL INVARIANT (P0):
-- - (forbidden graph structures removed) DO NOT EXIST.
-- - They MUST NOT be created, referenced, queried, or assumed to exist anywhere in this system.
-- - Attack path summaries are stored ONLY in `attack_paths`; full graph stored as JSON in `attack_graphs`.

CREATE TABLE IF NOT EXISTS attack_paths (
    path_id         UUID         NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID         NOT NULL REFERENCES tenants(tenant_id),
    detection_id    UUID         NOT NULL REFERENCES detections(detection_id),
    node_sequence   JSONB        NOT NULL,
    score           NUMERIC(8,6) NOT NULL CHECK (score BETWEEN 0.0 AND 1.0),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_attack_path_detection UNIQUE (detection_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_paths_detection ON attack_paths(detection_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_tenant    ON attack_paths(tenant_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_score     ON attack_paths(score DESC);

COMMIT;

