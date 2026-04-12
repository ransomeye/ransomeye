BEGIN;

-- PRD-03 §2 Migration tracking table (Core enforces checksum integrity).
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER     NOT NULL PRIMARY KEY,
    description TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum    TEXT        NOT NULL
);

-- PRD-03 §1.0 Extensions (PostgreSQL 16 + TimescaleDB 2.x).
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- PRD-03 §3.1 tenants
CREATE TABLE tenants (
    tenant_id       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_name     TEXT        NOT NULL,
    dek             BYTEA       NOT NULL CHECK (octet_length(dek) = 60),
    dek_version     INTEGER     NOT NULL DEFAULT 1 CHECK (dek_version >= 1),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenant_name UNIQUE (tenant_name)
);

-- PRD-03 §3.2 agent_sessions
CREATE TABLE agent_sessions (
    agent_id            UUID        NOT NULL PRIMARY KEY,
    tenant_id           UUID        NOT NULL REFERENCES tenants(tenant_id),
    boot_session_id     UUID        NOT NULL,
    hostname            TEXT        NOT NULL,
    primary_ip          INET        NOT NULL,
    agent_type          TEXT        NOT NULL CHECK (agent_type IN ('linux', 'windows', 'dpi')),
    agent_version       TEXT        NOT NULL DEFAULT 'V0.0',
    binary_hash         TEXT        CHECK (binary_hash ~ '^[0-9a-f]{64}$'),
    tpm_quote           BYTEA,
    tpm_pcr_values      JSONB,
    last_heartbeat      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status              TEXT        NOT NULL DEFAULT 'ACTIVE'
                                    CHECK (status IN ('ACTIVE','DEGRADED','OFFLINE','SUSPECTED_COMPROMISE','QUARANTINED')),
    lamport_clock       BIGINT      NOT NULL DEFAULT 0 CHECK (lamport_clock >= 0),
    os_info             JSONB,
    last_seen_ip        INET,
    is_critical_asset   BOOLEAN     NOT NULL DEFAULT FALSE,
    enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PRD-03 §3.3 boot_session_id_history
CREATE TABLE boot_session_id_history (
    id              BIGSERIAL   NOT NULL PRIMARY KEY,
    agent_id        UUID        NOT NULL REFERENCES agent_sessions(agent_id),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    boot_session_id UUID        NOT NULL,
    first_seen_ip   INET        NOT NULL,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agent_boot_session UNIQUE (agent_id, boot_session_id)
);

-- PRD-03 §3.4 agent_heartbeats (hypertable in migration 003)
CREATE TABLE agent_heartbeats (
    id               BIGSERIAL   NOT NULL,
    agent_id         UUID        NOT NULL REFERENCES agent_sessions(agent_id),
    tenant_id        UUID        NOT NULL REFERENCES tenants(tenant_id),
    timestamp        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logical_clock    BIGINT      NOT NULL CHECK (logical_clock >= 0),
    cpu_usage_pct    NUMERIC(5,2)    CHECK (cpu_usage_pct BETWEEN 0.0 AND 100.0),
    ram_used_mb      INTEGER         CHECK (ram_used_mb >= 0),
    ram_total_mb     INTEGER         CHECK (ram_total_mb > 0),
    load_avg_1m      NUMERIC(8,4)    CHECK (load_avg_1m >= 0.0),
    top_processes    JSONB,
    binary_hash      TEXT            CHECK (binary_hash ~ '^[0-9a-f]{64}$'),
    tpm_quote        BYTEA,
    event_drop_count BIGINT      NOT NULL DEFAULT 0 CHECK (event_drop_count >= 0),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, timestamp)
);

-- PRD-03 §3.6 telemetry_events (hypertable + indexes in later migrations; WORM triggers in migration 006)
CREATE TABLE telemetry_events (
    event_id        UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    agent_id        UUID        NOT NULL REFERENCES agent_sessions(agent_id),
    event_type      TEXT        NOT NULL CHECK (event_type IN (
                                    'PROCESS_EVENT','FILE_EVENT','NETWORK_EVENT',
                                    'USER_EVENT','DECEPTION_EVENT','DPI_FLOW')),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logical_clock   BIGINT      NOT NULL CHECK (logical_clock >= 0),
    payload         JSONB       NOT NULL,
    source          TEXT        NOT NULL CHECK (source IN (
                                    'linux_agent','windows_agent','dpi_probe','offline_sync')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT pk_telemetry_events PRIMARY KEY (event_id, timestamp)
);

-- PRD-03 §3.13 incidents
CREATE TABLE incidents (
    incident_id      UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(tenant_id),
    title            TEXT        NOT NULL,
    description      TEXT,
    severity         TEXT        NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    status           TEXT        NOT NULL CHECK (status IN ('OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED')),
    assigned_to      TEXT,
    created_by       TEXT,
    first_seen_at    TIMESTAMPTZ,
    last_updated_at  TIMESTAMPTZ,
    resolved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PRD-03 §3.7 detections
CREATE TABLE detections (
    detection_id         UUID          NOT NULL PRIMARY KEY,
    tenant_id            UUID          NOT NULL REFERENCES tenants(tenant_id),
    agent_id             UUID          NOT NULL REFERENCES agent_sessions(agent_id),
    event_id             UUID,
    timestamp            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    posterior_prob       NUMERIC(10,8) NOT NULL CHECK (posterior_prob > 0 AND posterior_prob < 1),
    aec_class            SMALLINT      NOT NULL CHECK (aec_class IN (0, 1, 2, 3)),
    threat_type          TEXT,
    signals              JSONB         NOT NULL,
    loo_importance       JSONB,
    bayesian_intermediate JSONB        NOT NULL,
    prior_used           NUMERIC(12,10) NOT NULL CHECK (prior_used > 0 AND prior_used <= 0.1),
    lambda_used          NUMERIC(4,3)  NOT NULL CHECK (lambda_used IN (0.100, 0.850)),
    model_hash           TEXT          NOT NULL CHECK (model_hash ~ '^[0-9a-f]{64}$'),
    drift_alert          BOOLEAN       NOT NULL DEFAULT FALSE,
    logical_clock        BIGINT        NOT NULL CHECK (logical_clock >= 0),
    analyst_disposition  TEXT          DEFAULT 'UNREVIEWED'
                                      CHECK (analyst_disposition IN (
                                          'UNREVIEWED','TRUE_POSITIVE','FALSE_POSITIVE','BENIGN','UNDER_INVESTIGATION')),
    analyst_notes        TEXT,
    analyst_id           TEXT,
    reviewed_at          TIMESTAMPTZ,
    incident_id          UUID          REFERENCES incidents(incident_id),
    created_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- PRD-03 §3.8 attack_graphs (stores graph JSON; (forbidden graph structures removed) DO NOT EXIST)
CREATE TABLE attack_graphs (
    id               BIGSERIAL    NOT NULL PRIMARY KEY,
    detection_id     UUID         NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    tenant_id        UUID         NOT NULL REFERENCES tenants(tenant_id),
    graph_json       JSONB        NOT NULL,
    mitre_techniques JSONB,
    kill_chain_phase TEXT         CHECK (kill_chain_phase IN (
                                     'reconnaissance','resource-development','initial-access','execution',
                                     'persistence','privilege-escalation','defense-evasion','credential-access',
                                     'discovery','lateral-movement','collection','command-and-control',
                                     'exfiltration','impact')),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_attack_graph_detection UNIQUE (detection_id)
);

-- PRD-03 §3.9 tinae_executive_summaries
CREATE TABLE tinae_executive_summaries (
    id               BIGSERIAL    NOT NULL PRIMARY KEY,
    detection_id     UUID         NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    tenant_id        UUID         NOT NULL REFERENCES tenants(tenant_id),
    summary_text     TEXT         NOT NULL,
    narrative_text   TEXT         NOT NULL,
    tinae_score      NUMERIC(5,2) NOT NULL,
    tinae_answers    JSONB        NOT NULL,
    model_version    TEXT         NOT NULL,
    sine_temperature NUMERIC(4,3),
    generated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tinae_summary_detection UNIQUE (detection_id)
);

-- PRD-03 §3.10 expert_analysis_reports (grounding columns altered in later migration)
CREATE TABLE expert_analysis_reports (
    id              BIGSERIAL    NOT NULL PRIMARY KEY,
    detection_id    UUID         NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    tenant_id       UUID         NOT NULL REFERENCES tenants(tenant_id),
    report_json     JSONB        NOT NULL,
    report_text     TEXT,
    recommendations JSONB,
    generated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_expert_report_detection UNIQUE (detection_id)
);

-- PRD-03 §3.12 actions (approval columns added in later migration)
CREATE TABLE actions (
    action_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(tenant_id),
    detection_id     UUID        REFERENCES detections(detection_id),
    agent_id         UUID        REFERENCES agent_sessions(agent_id),
    action_type      TEXT        NOT NULL CHECK (action_type IN (
                          'KILL_PROCESS','BLOCK_IP','ISOLATE_HOST','FILE_ROLLBACK',
                          'SNAPSHOT_MEMORY','ALERT_ONLY')),
    action_params    JSONB       NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'PENDING' CHECK (status IN (
                          'PENDING','PENDING_CONFIRMATION','PENDING_APPROVAL','DISPATCHED',
                          'COMPLETED','FAILED','CANCELLED')),
    result_detail    TEXT,
    dispatched_by    TEXT,
    dispatched_at    TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PRD-03 §3.14 dpi_flows (hypertable in migration 003)
CREATE TABLE dpi_flows (
    flow_id         UUID        NOT NULL,
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    probe_id        UUID,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip          INET        NOT NULL,
    dst_ip          INET        NOT NULL,
    src_port        INTEGER     CHECK (src_port BETWEEN 0 AND 65535),
    dst_port        INTEGER     CHECK (dst_port BETWEEN 0 AND 65535),
    protocol        SMALLINT    NOT NULL CHECK (protocol IN (1,6,17,58)),
    bytes_sent      BIGINT      NOT NULL DEFAULT 0 CHECK (bytes_sent >= 0),
    bytes_received  BIGINT      NOT NULL DEFAULT 0 CHECK (bytes_received >= 0),
    duration_ms     BIGINT      CHECK (duration_ms >= 0),
    l7_protocol     TEXT,
    ja3_hash        TEXT        CHECK (ja3_hash ~ '^[0-9a-f]{32}$'),
    sni             TEXT,
    http_host       TEXT,
    http_path       TEXT,
    dns_query       TEXT,
    dns_response_ip INET,
    tls_version     TEXT,
    detection_flags JSONB       NOT NULL DEFAULT '{}'::jsonb,
    is_flagged      BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (flow_id, timestamp)
);

-- PRD-03 §3.15 ndr_findings
CREATE TABLE ndr_findings (
    finding_id         UUID         NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID         NOT NULL REFERENCES tenants(tenant_id),
    probe_id           UUID,
    timestamp          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    finding_type       TEXT         NOT NULL,
    confidence         NUMERIC(6,5) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    src_ip             INET,
    dst_ip             INET,
    src_port           INTEGER      CHECK (src_port BETWEEN 0 AND 65535),
    dst_port           INTEGER      CHECK (dst_port BETWEEN 0 AND 65535),
    flow_id            UUID,
    details            TEXT,
    raw_evidence       JSONB,
    linked_detection_id UUID        REFERENCES detections(detection_id),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- PRD-03 §3.16 intel_indicators (soft-delete semantics enforced by application layer)
CREATE TABLE intel_indicators (
    indicator_id   UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(tenant_id),
    indicator_type TEXT        NOT NULL CHECK (indicator_type IN ('IP_ADDRESS','DOMAIN','JA3_HASH','FILE_HASH','URL','EMAIL')),
    value          TEXT        NOT NULL,
    confidence     NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    threat_type    TEXT,
    source         TEXT,
    source_ref     TEXT,
    first_seen     TIMESTAMPTZ,
    last_seen      TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    tags           JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_intel_indicator UNIQUE (tenant_id, indicator_type, value)
);

-- PRD-03 §3.19 policy_rules
CREATE TABLE policy_rules (
    rule_id              UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL REFERENCES tenants(tenant_id),
    rule_name            TEXT        NOT NULL,
    description          TEXT,
    trigger_aec_class    SMALLINT    NOT NULL CHECK (trigger_aec_class IN (1,2,3)),
    trigger_posterior_min NUMERIC(10,8) NOT NULL CHECK (trigger_posterior_min > 0 AND trigger_posterior_min < 1),
    action_type          TEXT        NOT NULL,
    is_active            BOOLEAN     NOT NULL DEFAULT TRUE,
    requires_approval    BOOLEAN     NOT NULL DEFAULT FALSE,
    approval_count       INTEGER     NOT NULL DEFAULT 0 CHECK (approval_count >= 0),
    rule_json            JSONB       NOT NULL,
    created_by           TEXT,
    signed_by            JSONB,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PRD-03 §3.20 compliance_reports
CREATE TABLE compliance_reports (
    report_id           UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(tenant_id),
    report_type         TEXT        NOT NULL CHECK (report_type IN ('SOC2','ISO27001','GDPR','NIS2','CUSTOM')),
    report_period_start DATE        NOT NULL,
    report_period_end   DATE        NOT NULL,
    report_json         JSONB       NOT NULL,
    report_pdf_path     TEXT,
    generated_by        TEXT,
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PRD-03 §3.21 model_config_audit
CREATE TABLE model_config_audit (
    audit_id         BIGSERIAL   NOT NULL PRIMARY KEY,
    tenant_id        UUID        NOT NULL REFERENCES tenants(tenant_id),
    config_hash      TEXT        NOT NULL CHECK (config_hash ~ '^[0-9a-f]{64}$'),
    config_version   TEXT        NOT NULL,
    action           TEXT        NOT NULL CHECK (action IN ('LOADED','VERIFIED','REJECTED','UPDATED')),
    signatures       JSONB,
    signature_count  INTEGER     NOT NULL DEFAULT 0 CHECK (signature_count >= 0),
    details          JSONB,
    source_service   TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- core_config referenced by PRD-03/PRD-10 for archiving WORM public key
CREATE TABLE core_config (
    key         TEXT        NOT NULL PRIMARY KEY,
    value       JSONB       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;

