-- Execution_context_hash on partition rows (batch uniformity) and
-- explicit binding of authority_snapshots at batch commit time.

ALTER TABLE partition_records
    ADD COLUMN IF NOT EXISTS execution_context_hash BYTEA;

UPDATE partition_records
SET execution_context_hash = decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
WHERE execution_context_hash IS NULL;

ALTER TABLE partition_records
    ALTER COLUMN execution_context_hash SET NOT NULL;

ALTER TABLE partition_records
    ADD CONSTRAINT partition_records_execution_context_hash_len
    CHECK (octet_length(execution_context_hash) = 32);

CREATE TABLE IF NOT EXISTS batch_commit_authority_bindings (
    partition_id BIGINT NOT NULL,
    batch_commit_seq BIGINT NOT NULL,
    authority_type TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    authority_version TEXT NOT NULL,
    PRIMARY KEY (partition_id, batch_commit_seq, authority_type, authority_id, authority_version),
    CONSTRAINT batch_commit_authority_bindings_batch_fk
        FOREIGN KEY (partition_id, batch_commit_seq)
        REFERENCES batch_commit_records (partition_id, batch_commit_seq),
    CONSTRAINT batch_commit_authority_bindings_snapshot_fk
        FOREIGN KEY (authority_type, authority_id, authority_version)
        REFERENCES authority_snapshots (authority_type, authority_id, authority_version)
);

SELECT register_migration(45, 'prd13_execution_context_and_batch_authority');
