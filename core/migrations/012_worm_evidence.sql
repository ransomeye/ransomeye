-- Migration 012: WORM evidence metadata.

CREATE TABLE IF NOT EXISTS worm_evidence (
    evidence_id             UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,
    detection_id            UUID,
    event_id                UUID,
    evidence_type           TEXT        NOT NULL
                                         CHECK (evidence_type IN (
                                             'FORENSIC_BUNDLE',
                                             'MEMORY_SNAPSHOT',
                                             'FILE_SAMPLE',
                                             'NETWORK_PCAP',
                                             'DISK_IMAGE',
                                             'LOG_EXPORT',
                                             'MERKLE_PROOF_BUNDLE',
                                             'CUSTOM'
                                         )),
    file_path               TEXT        NOT NULL,
    canonical_json_hash     TEXT        NOT NULL CHECK (canonical_json_hash ~ '^[0-9a-f]{64}$'),
    worm_file_hash          TEXT        NOT NULL CHECK (worm_file_hash ~ '^[0-9a-f]{64}$'),
    ed25519_sig             TEXT        NOT NULL,
    retention_tier          TEXT        NOT NULL CHECK (retention_tier IN ('hot', 'warm', 'cold', 'forensic-only')),
    file_size_bytes         BIGINT      NOT NULL CHECK (file_size_bytes >= 0),
    dropped_packets_before  BIGINT      NOT NULL DEFAULT 0 CHECK (dropped_packets_before >= 0),
    sealed_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT register_migration(12, 'worm_evidence');
