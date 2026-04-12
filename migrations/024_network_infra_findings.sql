BEGIN;

-- PRD-03 §2 Migration 024: network_infra_findings hypertable + 90-day retention (PRD-23 V0.0 §6.9).

CREATE TABLE IF NOT EXISTS network_infra_findings (
    finding_id     UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(tenant_id),
    probe_id       UUID        NOT NULL REFERENCES registered_probes(probe_id),
    timestamp      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finding_type   TEXT        NOT NULL,
    score          DOUBLE PRECISION NOT NULL CHECK (score >= 0.0 AND score <= 1.0),
    compound_score DOUBLE PRECISION CHECK (compound_score >= 0.0),
    details_json   JSONB,
    raw_evidence   JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (finding_id, timestamp)
);

SELECT create_hypertable(
    'network_infra_findings',
    'timestamp',
    chunk_time_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

CREATE INDEX IF NOT EXISTS idx_netinfra_tenant_time
    ON network_infra_findings(tenant_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_netinfra_probe_time
    ON network_infra_findings(probe_id, timestamp DESC);

SELECT add_retention_policy('network_infra_findings', INTERVAL '90 days');

COMMIT;

