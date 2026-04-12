-- Migration 005: raw telemetry ingestion.

CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id                UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,
    agent_id                UUID        NOT NULL,
    event_type              TEXT        NOT NULL
                                        CHECK (event_type IN (
                                            'PROCESS_EVENT',
                                            'FILE_EVENT',
                                            'NETWORK_EVENT',
                                            'USER_EVENT',
                                            'DECEPTION_EVENT',
                                            'DPI_FLOW'
                                        )),
    event_time              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    timestamp               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logical_clock           BIGINT      NOT NULL DEFAULT 0 CHECK (logical_clock >= 0),
    payload_json            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    payload_bytes           BYTEA       NOT NULL DEFAULT '\x'::bytea,
    agent_ed25519_sig       BYTEA       NOT NULL DEFAULT '\x'::bytea,
    payload_sha256          BYTEA       GENERATED ALWAYS AS (digest(payload_bytes, 'sha256')) STORED,
    payload_sha256_hex      TEXT        GENERATED ALWAYS AS (encode(digest(payload_bytes, 'sha256'), 'hex')) STORED,
    source                  TEXT        NOT NULL
                                        CHECK (source IN ('linux_agent', 'windows_agent', 'dpi_probe', 'offline_sync')),
    dropped_packets_before  BIGINT      NOT NULL DEFAULT 0 CHECK (dropped_packets_before >= 0),
    ingest_status           TEXT        NOT NULL DEFAULT 'ACCEPTED'
                                        CHECK (ingest_status IN ('ACCEPTED', 'ENRICHED', 'DROPPED', 'SEALED')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (event_id, event_time)
);

SELECT create_hypertable(
    'telemetry_events',
    'event_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT register_migration(5, 'telemetry_events');
