-- Migration 024: ingestion, DPI, and network findings.

CREATE TABLE IF NOT EXISTS ingestion_stats (
    stat_id           UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    source            TEXT        NOT NULL CHECK (source IN ('linux_agent', 'windows_agent', 'dpi_probe', 'offline_sync')),
    stat_time         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_count    BIGINT      NOT NULL DEFAULT 0 CHECK (accepted_count >= 0),
    dropped_count     BIGINT      NOT NULL DEFAULT 0 CHECK (dropped_count >= 0),
    lag_ms            BIGINT      NOT NULL DEFAULT 0 CHECK (lag_ms >= 0),
    queue_depth       BIGINT      NOT NULL DEFAULT 0 CHECK (queue_depth >= 0),
    payload_bytes     BIGINT      NOT NULL DEFAULT 0 CHECK (payload_bytes >= 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (stat_id, stat_time)
);

CREATE TABLE IF NOT EXISTS dpi_flows (
    flow_id            UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL,
    probe_id           UUID,
    flow_time          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip             INET        NOT NULL,
    dst_ip             INET        NOT NULL,
    src_port           INTEGER     CHECK (src_port BETWEEN 0 AND 65535),
    dst_port           INTEGER     CHECK (dst_port BETWEEN 0 AND 65535),
    protocol           SMALLINT    NOT NULL CHECK (protocol IN (1, 6, 17, 58)),
    bytes_sent         BIGINT      NOT NULL DEFAULT 0 CHECK (bytes_sent >= 0),
    bytes_received     BIGINT      NOT NULL DEFAULT 0 CHECK (bytes_received >= 0),
    duration_ms        BIGINT      NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
    l7_protocol        TEXT        NOT NULL DEFAULT '',
    ja3_hash           TEXT        NOT NULL DEFAULT '' CHECK (ja3_hash = '' OR ja3_hash ~ '^[0-9a-f]{32}$'),
    sni                TEXT        NOT NULL DEFAULT '',
    http_host          TEXT        NOT NULL DEFAULT '',
    http_path          TEXT        NOT NULL DEFAULT '',
    dns_query          TEXT        NOT NULL DEFAULT '',
    dns_response_ip    INET,
    tls_version        TEXT        NOT NULL DEFAULT '',
    detection_flags    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    is_flagged         BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (flow_id, flow_time)
);

CREATE TABLE IF NOT EXISTS ndr_findings (
    finding_id           UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL,
    probe_id             UUID,
    finding_time         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finding_type         TEXT        NOT NULL,
    confidence           NUMERIC(6,5) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    src_ip               INET,
    dst_ip               INET,
    src_port             INTEGER     CHECK (src_port BETWEEN 0 AND 65535),
    dst_port             INTEGER     CHECK (dst_port BETWEEN 0 AND 65535),
    flow_id              UUID,
    details              TEXT        NOT NULL DEFAULT '',
    raw_evidence         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    linked_detection_id  UUID,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (finding_id, finding_time)
);

CREATE TABLE IF NOT EXISTS network_infra_findings (
    finding_id         UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL,
    probe_id           UUID        NOT NULL,
    finding_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finding_type       TEXT        NOT NULL,
    score              DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 1),
    compound_score     DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (compound_score >= 0),
    details_json       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    raw_evidence       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (finding_id, finding_time)
);

CREATE TABLE IF NOT EXISTS snmp_device_inventory (
    device_id          UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL,
    probe_id           UUID        NOT NULL,
    device_ip          INET        NOT NULL,
    device_type        TEXT        NOT NULL CHECK (device_type IN ('ROUTER', 'SWITCH', 'FIREWALL', 'WLC', 'AP', 'OTHER')),
    vendor             TEXT        NOT NULL DEFAULT '',
    model              TEXT        NOT NULL DEFAULT '',
    os_version         TEXT        NOT NULL DEFAULT '',
    snmp_v3_user       TEXT        NOT NULL DEFAULT '',
    snmp_v3_auth_enc   BYTEA       NOT NULL DEFAULT '\x'::bytea,
    last_polled_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_snmp_device_inventory UNIQUE (tenant_id, device_ip)
);

SELECT register_migration(24, 'ingestion_stats');
