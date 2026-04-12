-- Migration 037: HASH indexes for SHA-256 and Merkle lookups.

CREATE INDEX IF NOT EXISTS idx_telemetry_payload_sha256_hash
    ON telemetry_events USING HASH (payload_sha256_hex);

CREATE INDEX IF NOT EXISTS idx_telemetry_dropped_payload_sha256_hash
    ON telemetry_dropped USING HASH (payload_sha256);

CREATE INDEX IF NOT EXISTS idx_worm_evidence_canonical_hash
    ON worm_evidence USING HASH (canonical_json_hash);

CREATE INDEX IF NOT EXISTS idx_worm_evidence_file_hash
    ON worm_evidence USING HASH (worm_file_hash);

CREATE INDEX IF NOT EXISTS idx_incident_notes_note_sha256_hash
    ON incident_notes USING HASH (note_sha256);

CREATE INDEX IF NOT EXISTS idx_case_notes_note_sha256_hash
    ON case_notes USING HASH (note_sha256);

CREATE INDEX IF NOT EXISTS idx_merkle_tree_payload_hash
    ON merkle_tree USING HASH (payload_hash);

CREATE INDEX IF NOT EXISTS idx_merkle_roots_root_hash
    ON merkle_roots USING HASH (root_hash);

CREATE INDEX IF NOT EXISTS idx_merkle_daily_roots_root_hash
    ON merkle_daily_roots USING HASH (merkle_root);

CREATE INDEX IF NOT EXISTS idx_policy_versions_rule_sha256_hash
    ON policy_versions USING HASH (rule_sha256);

CREATE INDEX IF NOT EXISTS idx_intel_indicators_sha256_hash
    ON intel_indicators USING HASH (indicator_sha256);

CREATE INDEX IF NOT EXISTS idx_bundle_application_sha256_hash
    ON bundle_application_log USING HASH (bundle_sha256);

SELECT register_migration(37, 'hash_indexes');
