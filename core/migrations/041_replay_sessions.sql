-- Migration 041: deterministic replay baselines and immutable stage artifacts.

CREATE TABLE IF NOT EXISTS replay_sessions (
    replay_id      UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    input_hash     TEXT        NOT NULL,
    expected_hash  TEXT        NOT NULL,
    actual_hash    TEXT        NOT NULL,
    status         TEXT        NOT NULL
);

CREATE TABLE IF NOT EXISTS replay_stage_artifacts (
    artifact_id      UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    replay_id        UUID        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stage_name       TEXT        NOT NULL CHECK (
        stage_name IN (
            'capture',
            'ingest',
            'feature',
            'model',
            'sine',
            'decision',
            'enforcement',
            'final'
        )
    ),
    stage_hash       TEXT        NOT NULL,
    canonical_json   TEXT        NOT NULL
);

ALTER TABLE replay_stage_artifacts
    DROP CONSTRAINT IF EXISTS fk_replay_stage_artifacts_replay;

ALTER TABLE replay_stage_artifacts
    ADD CONSTRAINT fk_replay_stage_artifacts_replay
    FOREIGN KEY (replay_id)
    REFERENCES replay_sessions(replay_id)
    ON DELETE RESTRICT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_replay_stage_artifacts_replay_stage
    ON replay_stage_artifacts(replay_id, stage_name);

CREATE INDEX IF NOT EXISTS idx_replay_sessions_created_at
    ON replay_sessions(created_at DESC);

DROP TRIGGER IF EXISTS trg_replay_sessions_no_update ON replay_sessions;
CREATE TRIGGER trg_replay_sessions_no_update
    BEFORE UPDATE ON replay_sessions
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_replay_sessions_no_delete ON replay_sessions;
CREATE TRIGGER trg_replay_sessions_no_delete
    BEFORE DELETE ON replay_sessions
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_replay_stage_artifacts_no_update ON replay_stage_artifacts;
CREATE TRIGGER trg_replay_stage_artifacts_no_update
    BEFORE UPDATE ON replay_stage_artifacts
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_replay_stage_artifacts_no_delete ON replay_stage_artifacts;
CREATE TRIGGER trg_replay_stage_artifacts_no_delete
    BEFORE DELETE ON replay_stage_artifacts
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();
