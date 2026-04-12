-- Segment manifests and retention proofs; §3.11 commit groups (terminal scope metadata).

CREATE TABLE IF NOT EXISTS segment_manifests (
    partition_id BIGINT NOT NULL,
    segment_id BYTEA NOT NULL,
    first_partition_record_seq BIGINT NOT NULL,
    last_partition_record_seq BIGINT NOT NULL,
    first_record_hash BYTEA NOT NULL,
    last_record_hash BYTEA NOT NULL,
    record_count BIGINT NOT NULL,
    segment_root_hash BYTEA NOT NULL,
    manifest_hash BYTEA NOT NULL,
    PRIMARY KEY (partition_id, segment_id),
    CHECK (octet_length(first_record_hash) = 32),
    CHECK (octet_length(last_record_hash) = 32),
    CHECK (octet_length(segment_root_hash) = 32),
    CHECK (octet_length(manifest_hash) = 32)
);

CREATE TABLE IF NOT EXISTS retention_proofs (
    partition_id BIGINT NOT NULL,
    segment_id BYTEA NOT NULL,
    retention_proof_id BYTEA NOT NULL,
    first_record_hash BYTEA NOT NULL,
    last_record_hash BYTEA NOT NULL,
    segment_root_hash BYTEA NOT NULL,
    record_count BIGINT NOT NULL,
    retention_rule_id TEXT NOT NULL,
    proof_hash BYTEA NOT NULL,
    PRIMARY KEY (partition_id, retention_proof_id),
    UNIQUE (partition_id, segment_id),
    CHECK (octet_length(first_record_hash) = 32),
    CHECK (octet_length(last_record_hash) = 32),
    CHECK (octet_length(segment_root_hash) = 32),
    CHECK (octet_length(proof_hash) = 32)
);

CREATE TABLE IF NOT EXISTS commit_groups (
    partition_id BIGINT NOT NULL,
    logical_shard_id BYTEA NOT NULL,
    message_id BYTEA NOT NULL,
    commit_group_id BYTEA NOT NULL,
    commit_group_status TEXT NOT NULL,
    terminal_record_type TEXT NOT NULL,
    terminal_record_id BYTEA NOT NULL,
    batch_commit_seq BIGINT NOT NULL,
    PRIMARY KEY (partition_id, logical_shard_id, message_id),
    UNIQUE (commit_group_id),
    CHECK (commit_group_status IN (
        'ACTION_EXECUTED',
        'POLICY_DENIED',
        'APPROVAL_PENDING',
        'ROLLBACK_TERMINAL',
        'NO_ACTION_DEFERRED_RESOLVED'
    )),
    CHECK (terminal_record_type IN (
        'SIGNAL',
        'DETECTION',
        'DECISION',
        'SAFETY_EVALUATION',
        'ACTION',
        'EXECUTION_RESULT',
        'ROLLBACK',
        'ROLLBACK_OVERRIDE',
        'REDACTION',
        'QUERY',
        'QUERY_RESULT',
        'REPORT',
        'REPORT_DELIVERY',
        'UI_ACTION',
        'GROUP',
        'CASE',
        'INVESTIGATION',
        'RISK',
        'SIMULATION'
    )),
    CONSTRAINT commit_groups_batch_fk
        FOREIGN KEY (partition_id, batch_commit_seq)
        REFERENCES batch_commit_records (partition_id, batch_commit_seq),
    CONSTRAINT commit_groups_terminal_fk
        FOREIGN KEY (terminal_record_type, terminal_record_id)
        REFERENCES partition_records (record_type, record_id)
);

SELECT register_migration(46, 'prd13_segment_retention_commit_groups');
