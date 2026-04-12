BEGIN;

-- PRD-03 §2 Migration 012: endpoint_software_inventory + endpoint_vulnerability_scores (PRD-07 V0.0).

CREATE TABLE IF NOT EXISTS endpoint_software_inventory (
    id               BIGSERIAL    NOT NULL PRIMARY KEY,
    tenant_id         UUID         NOT NULL REFERENCES tenants(tenant_id),
    agent_id          UUID         NOT NULL REFERENCES agent_sessions(agent_id),
    software_name     TEXT         NOT NULL,
    software_version  TEXT,
    vendor            TEXT,
    install_date      DATE,
    last_seen_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_endpoint_software 
    ON endpoint_software_inventory (tenant_id, agent_id, software_name, (COALESCE(software_version, '')));

CREATE INDEX IF NOT EXISTS idx_endpoint_software_agent
    ON endpoint_software_inventory(agent_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS endpoint_vulnerability_scores (
    id               BIGSERIAL    NOT NULL PRIMARY KEY,
    tenant_id         UUID         NOT NULL REFERENCES tenants(tenant_id),
    agent_id          UUID         NOT NULL REFERENCES agent_sessions(agent_id),
    cve_id            TEXT         NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    cvss_score        NUMERIC(4,1) CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    epss_score        NUMERIC(6,5) CHECK (epss_score BETWEEN 0.0 AND 1.0),
    vulnerability_score NUMERIC(10,6) NOT NULL CHECK (vulnerability_score >= 0),
    computed_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_endpoint_cve UNIQUE (tenant_id, agent_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_vuln_agent_time
    ON endpoint_vulnerability_scores(agent_id, computed_at DESC);

COMMIT;

