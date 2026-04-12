BEGIN;

-- PRD-03 §2 Migration 025: snmp_device_inventory (PRD-23 V0.0 §6.8).

CREATE TABLE IF NOT EXISTS snmp_device_inventory (
    device_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(tenant_id),
    probe_id         UUID        NOT NULL REFERENCES registered_probes(probe_id),
    device_ip        INET        NOT NULL,
    device_type      TEXT        NOT NULL CHECK (device_type IN ('ROUTER','SWITCH','FIREWALL','WLC','AP','OTHER')),
    vendor           TEXT,
    model            TEXT,
    os_version       TEXT,
    snmp_v3_user     TEXT,
    snmp_v3_auth_enc BYTEA, -- AES-256-GCM encrypted blob (envelope) per PRD-23; keying via Core.
    last_polled_at   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_snmp_device UNIQUE (tenant_id, device_ip)
);

CREATE INDEX IF NOT EXISTS idx_snmp_device_probe
    ON snmp_device_inventory(probe_id, last_polled_at DESC);

COMMIT;

