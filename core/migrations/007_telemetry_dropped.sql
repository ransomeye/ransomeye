-- Migration 007: dropped telemetry records.

CREATE TABLE IF NOT EXISTS telemetry_dropped (
    drop_id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    agent_id         UUID        NOT NULL,
    event_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source           TEXT        NOT NULL
                                 CHECK (source IN ('linux_agent', 'windows_agent', 'dpi_probe', 'offline_sync')),
    drop_reason      TEXT        NOT NULL
                                 CHECK (drop_reason IN (
                                     'SCHEMA_INVALID',
                                     'QUEUE_FULL',
                                     'SIGNATURE_INVALID',
                                     'WORM_FAILURE',
                                     'RLS_DENIED',
                                     'DUPLICATE',
                                     'OTHER'
                                 )),
    dropped_count    BIGINT      NOT NULL DEFAULT 1 CHECK (dropped_count >= 1),
    payload_bytes    BYTEA       NOT NULL DEFAULT '\x'::bytea,
    payload_sha256   TEXT        GENERATED ALWAYS AS (encode(digest(payload_bytes, 'sha256'), 'hex')) STORED,
    details_json     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (drop_id, event_time)
);

SELECT register_migration(7, 'telemetry_dropped');
