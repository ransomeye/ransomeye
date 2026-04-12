CREATE TABLE IF NOT EXISTS partition_records (
    partition_id BIGINT NOT NULL,
    partition_epoch BIGINT NOT NULL,
    partition_record_seq BIGINT NOT NULL,
    shard_seq BIGINT NOT NULL,
    record_type TEXT NOT NULL,
    record_version TEXT NOT NULL,
    stage_order SMALLINT NOT NULL,
    record_id BYTEA NOT NULL,
    message_id BYTEA,
    agent_id BYTEA,
    boot_session_id BYTEA,
    logical_clock NUMERIC(20,0),
    logical_shard_id BYTEA NOT NULL,
    causal_parent_refs_text TEXT NOT NULL,
    canonical_payload_text TEXT,
    canonical_payload_bytes BYTEA,
    canonical_payload_hash BYTEA NOT NULL,
    payload_hash BYTEA,
    signature BYTEA,
    partition_context BYTEA,
    schema_version TEXT,
    schema_transform_hash BYTEA,
    previous_record_hash BYTEA NOT NULL,
    record_hash BYTEA NOT NULL,
    PRIMARY KEY (partition_id, partition_record_seq),
    UNIQUE (record_type, record_id),
    UNIQUE (message_id),
    UNIQUE (agent_id, boot_session_id, logical_clock),
    CHECK (shard_seq = partition_record_seq),
    CHECK (record_type IN (
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
    CHECK (stage_order IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19)),
    CHECK (octet_length(canonical_payload_hash) = 32),
    CHECK (octet_length(previous_record_hash) = 32),
    CHECK (octet_length(record_hash) = 32),
    CHECK (
        record_type <> 'SIGNAL' OR (
            message_id IS NOT NULL AND
            agent_id IS NOT NULL AND
            boot_session_id IS NOT NULL AND
            logical_clock IS NOT NULL AND
            canonical_payload_bytes IS NOT NULL AND
            payload_hash IS NOT NULL AND
            signature IS NOT NULL AND
            partition_context IS NOT NULL AND
            schema_version IS NOT NULL AND
            schema_transform_hash IS NOT NULL
        )
    )
);

CREATE TABLE IF NOT EXISTS batch_commit_records (
    partition_id BIGINT NOT NULL,
    batch_commit_seq BIGINT NOT NULL,
    batch_commit_id BYTEA NOT NULL,
    partition_epoch BIGINT NOT NULL,
    first_partition_record_seq BIGINT NOT NULL,
    last_partition_record_seq BIGINT NOT NULL,
    record_count BIGINT NOT NULL,
    first_record_hash BYTEA NOT NULL,
    last_record_hash BYTEA NOT NULL,
    batch_root_hash BYTEA NOT NULL,
    previous_batch_commit_hash BYTEA NOT NULL,
    signing_context TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_epoch BIGINT NOT NULL,
    execution_context_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    batch_commit_hash BYTEA NOT NULL,
    PRIMARY KEY (partition_id, batch_commit_seq),
    UNIQUE (batch_commit_id),
    CHECK (signing_context = 'batch_commit_record_v1'),
    CHECK (octet_length(first_record_hash) = 32),
    CHECK (octet_length(last_record_hash) = 32),
    CHECK (octet_length(batch_root_hash) = 32),
    CHECK (octet_length(previous_batch_commit_hash) = 32),
    CHECK (octet_length(execution_context_hash) = 32),
    CHECK (octet_length(batch_commit_hash) = 32)
);

CREATE TABLE IF NOT EXISTS authority_snapshots (
    authority_type TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    authority_version TEXT NOT NULL,
    canonical_payload_text TEXT NOT NULL,
    payload_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    PRIMARY KEY (authority_type, authority_id, authority_version),
    CHECK (authority_type IN (
        'CONFIG',
        'POLICY',
        'MODEL',
        'SHARD_CONFIG',
        'ENTITY_ROUTE_MAP',
        'PARAMETER_PROFILE',
        'ADAPTER_MANIFEST',
        'ACTION_CAPABILITY_DESCRIPTOR',
        'RETENTION_CONFIG'
    )),
    CHECK (octet_length(payload_hash) = 32),
    CHECK (octet_length(signature) > 0)
);

CREATE TABLE IF NOT EXISTS replay_guard (
    partition_id BIGINT NOT NULL,
    logical_shard_id BYTEA NOT NULL,
    emitter_id BYTEA NOT NULL,
    boot_session_id BYTEA NOT NULL,
    logical_clock NUMERIC(20,0) NOT NULL,
    message_id BYTEA NOT NULL,
    seen_state TEXT NOT NULL,
    pre_auth_nonce BYTEA,
    pre_auth_token BYTEA,
    pre_auth_message_type TEXT,
    pre_auth_validity_window TEXT,
    pre_auth_execution_context_hash BYTEA,
    escrow_handoff_id BYTEA,
    PRIMARY KEY (partition_id, logical_shard_id, message_id),
    UNIQUE (partition_id, logical_shard_id, emitter_id, boot_session_id, logical_clock),
    UNIQUE NULLS NOT DISTINCT (partition_id, logical_shard_id, pre_auth_nonce),
    CHECK (seen_state IN ('PENDING_QUEUE_COMMIT', 'ADMITTED')),
    CHECK (pre_auth_message_type IS NULL OR pre_auth_message_type = 'PRE_TLS_AUTH')
);

SELECT register_migration(44, 'prd13_authority_tables');
