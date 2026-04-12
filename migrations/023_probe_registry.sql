BEGIN;

-- PRD-03 §2 Migration 023: registered_probes (PRD-23 V0.0 §2).

CREATE OR REPLACE FUNCTION set_updated_at_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TABLE IF NOT EXISTS registered_probes (
    probe_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    probe_type      TEXT        NOT NULL CHECK (probe_type IN ('DPI','NETFLOW','NETWORK_POLLER','SYSLOG')),
    hostname        TEXT        NOT NULL,
    covered_subnets CIDR[]      NOT NULL DEFAULT ARRAY[]::cidr[],
    status          TEXT        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DEGRADED','OFFLINE')),
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_probe_hostname UNIQUE (tenant_id, hostname)
);

DROP TRIGGER IF EXISTS trg_registered_probes_set_updated_at ON registered_probes;
CREATE TRIGGER trg_registered_probes_set_updated_at
    BEFORE UPDATE ON registered_probes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at_timestamp();

CREATE INDEX IF NOT EXISTS idx_registered_probes_tenant_status
    ON registered_probes(tenant_id, status, updated_at DESC);

COMMIT;

