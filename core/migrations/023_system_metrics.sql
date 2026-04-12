-- Migration 023: heartbeats, probe registry, and endpoint metrics.

CREATE TABLE IF NOT EXISTS agent_heartbeats (
    heartbeat_id      UUID        NOT NULL DEFAULT gen_random_uuid(),
    agent_id          UUID        NOT NULL,
    tenant_id         UUID        NOT NULL,
    heartbeat_time    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logical_clock     BIGINT      NOT NULL DEFAULT 0 CHECK (logical_clock >= 0),
    cpu_usage_pct     NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (cpu_usage_pct BETWEEN 0 AND 100),
    ram_used_mb       INTEGER     NOT NULL DEFAULT 0 CHECK (ram_used_mb >= 0),
    ram_total_mb      INTEGER     NOT NULL DEFAULT 1 CHECK (ram_total_mb > 0),
    load_avg_1m       NUMERIC(8,4) NOT NULL DEFAULT 0 CHECK (load_avg_1m >= 0),
    top_processes     JSONB       NOT NULL DEFAULT '[]'::jsonb,
    binary_hash       TEXT        NOT NULL DEFAULT repeat('0', 64) CHECK (binary_hash ~ '^[0-9a-f]{64}$'),
    tpm_quote         BYTEA       NOT NULL DEFAULT '\x'::bytea,
    event_drop_count  BIGINT      NOT NULL DEFAULT 0 CHECK (event_drop_count >= 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (heartbeat_id, heartbeat_time)
);

CREATE TABLE IF NOT EXISTS system_metrics (
    metric_id         UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    component         TEXT        NOT NULL,
    metric_name       TEXT        NOT NULL,
    metric_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metric_value      DOUBLE PRECISION NOT NULL,
    metric_labels     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (metric_id, metric_time)
);

CREATE TABLE IF NOT EXISTS registered_probes (
    probe_id          UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    probe_type        TEXT        NOT NULL CHECK (probe_type IN ('DPI', 'NETFLOW', 'NETWORK_POLLER', 'SYSLOG')),
    hostname          TEXT        NOT NULL,
    covered_subnets   CIDR[]      NOT NULL DEFAULT ARRAY[]::cidr[],
    status            TEXT        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEGRADED', 'OFFLINE')),
    enrolled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_registered_probe_hostname UNIQUE (tenant_id, hostname)
);

CREATE TABLE IF NOT EXISTS endpoint_software_inventory (
    inventory_id       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL,
    agent_id           UUID        NOT NULL,
    software_name      TEXT        NOT NULL,
    software_version   TEXT        NOT NULL DEFAULT '',
    vendor             TEXT        NOT NULL DEFAULT '',
    install_timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_endpoint_software UNIQUE (tenant_id, agent_id, software_name, software_version)
);

CREATE TABLE IF NOT EXISTS endpoint_vulnerability_scores (
    vuln_score_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL,
    agent_id             UUID        NOT NULL,
    cve_id               TEXT        NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    cvss_score           NUMERIC(4,1) NOT NULL DEFAULT 0 CHECK (cvss_score BETWEEN 0 AND 10),
    epss_score           NUMERIC(6,5) NOT NULL DEFAULT 0 CHECK (epss_score BETWEEN 0 AND 1),
    vulnerability_score  NUMERIC(10,6) NOT NULL DEFAULT 0 CHECK (vulnerability_score >= 0),
    computed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_endpoint_vulnerability_score UNIQUE (tenant_id, agent_id, cve_id)
);

SELECT register_migration(23, 'system_metrics');
