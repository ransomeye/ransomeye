BEGIN;

-- PRD-03 §2 Migration 030: bundle_application_log (PRD-16 V0.0 §13).
-- WORM-compliant table: INSERT-only. UPDATE/DELETE must raise IMMUTABILITY_VIOLATION.
-- Trigger function is defined in migrations/006_enforce_worm_immutability.sql.

CREATE TABLE IF NOT EXISTS bundle_application_log (
    log_id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_id        UUID         NOT NULL,
    bundle_type      TEXT         NOT NULL CHECK (bundle_type IN (
                                      'FULL','BINARY','MODEL_CONFIG','MODEL_WEIGHTS',
                                      'INTEL_FEED','CERT_ROTATION','UI_ASSETS','KEY_ROTATION')),
    sequence_number  BIGINT       NOT NULL CHECK (sequence_number >= 1),
    applied_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    applied_by       TEXT         NOT NULL DEFAULT 'root',
    artifacts_json   JSONB        NOT NULL,
    migrations_json  JSONB        NOT NULL DEFAULT '[]',
    outcome          TEXT         NOT NULL CHECK (outcome IN ('SUCCESS','ROLLBACK','MANUAL_ROLLBACK')),
    failure_reason   TEXT,
    bundle_sha256    TEXT         NOT NULL CHECK (bundle_sha256 ~ '^sha256:[0-9a-f]{64}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bundle_seq ON bundle_application_log(sequence_number);

DROP TRIGGER IF EXISTS trg_bundle_log_no_update ON bundle_application_log;
CREATE TRIGGER trg_bundle_log_no_update
    BEFORE UPDATE ON bundle_application_log
    FOR EACH ROW EXECUTE FUNCTION enforce_worm_immutability();

DROP TRIGGER IF EXISTS trg_bundle_log_no_delete ON bundle_application_log;
CREATE TRIGGER trg_bundle_log_no_delete
    BEFORE DELETE ON bundle_application_log
    FOR EACH ROW EXECUTE FUNCTION enforce_worm_immutability();

COMMIT;

