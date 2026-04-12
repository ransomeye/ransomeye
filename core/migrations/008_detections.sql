-- Migration 008: detections and analysis artifacts.

CREATE TABLE IF NOT EXISTS detections (
    detection_id           UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID        NOT NULL,
    agent_id               UUID        NOT NULL,
    event_id               UUID,
    detected_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    timestamp              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posterior_prob         NUMERIC(10,8) NOT NULL CHECK (posterior_prob > 0 AND posterior_prob < 1),
    aec_class              SMALLINT    NOT NULL CHECK (aec_class IN (0, 1, 2, 3)),
    threat_type            TEXT        NOT NULL DEFAULT '',
    signals                JSONB       NOT NULL DEFAULT '{}'::jsonb,
    loo_importance         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    bayesian_intermediate  JSONB       NOT NULL DEFAULT '{}'::jsonb,
    prior_used             NUMERIC(12,10) NOT NULL CHECK (prior_used > 0 AND prior_used <= 0.1),
    lambda_used            NUMERIC(4,3) NOT NULL CHECK (lambda_used IN (0.100, 0.850)),
    model_hash             TEXT        NOT NULL DEFAULT repeat('0', 64)
                                        CHECK (model_hash ~ '^[0-9a-f]{64}$'),
    drift_alert            BOOLEAN     NOT NULL DEFAULT FALSE,
    logical_clock          BIGINT      NOT NULL DEFAULT 0 CHECK (logical_clock >= 0),
    analyst_disposition    TEXT        NOT NULL DEFAULT 'UNREVIEWED'
                                        CHECK (analyst_disposition IN (
                                            'UNREVIEWED',
                                            'TRUE_POSITIVE',
                                            'FALSE_POSITIVE',
                                            'BENIGN',
                                            'UNDER_INVESTIGATION'
                                        )),
    analyst_notes          TEXT        NOT NULL DEFAULT '',
    analyst_id             TEXT        NOT NULL DEFAULT '',
    reviewed_at            TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    incident_id            UUID,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attack_graphs (
    graph_id           UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id       UUID        NOT NULL,
    tenant_id          UUID        NOT NULL,
    graph_json         JSONB       NOT NULL,
    mitre_techniques   JSONB       NOT NULL DEFAULT '[]'::jsonb,
    kill_chain_phase   TEXT        NOT NULL DEFAULT 'execution'
                                   CHECK (kill_chain_phase IN (
                                       'reconnaissance',
                                       'resource-development',
                                       'initial-access',
                                       'execution',
                                       'persistence',
                                       'privilege-escalation',
                                       'defense-evasion',
                                       'credential-access',
                                       'discovery',
                                       'lateral-movement',
                                       'collection',
                                       'command-and-control',
                                       'exfiltration',
                                       'impact'
                                   )),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_attack_graphs_detection UNIQUE (detection_id)
);

CREATE TABLE IF NOT EXISTS attack_paths (
    path_id         UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    detection_id    UUID        NOT NULL,
    node_sequence   JSONB       NOT NULL,
    score           NUMERIC(8,6) NOT NULL CHECK (score BETWEEN 0.0 AND 1.0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_attack_paths_detection UNIQUE (detection_id)
);

CREATE TABLE IF NOT EXISTS tinae_executive_summaries (
    summary_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id      UUID        NOT NULL,
    tenant_id         UUID        NOT NULL,
    summary_text      TEXT        NOT NULL,
    narrative_text    TEXT        NOT NULL DEFAULT '',
    tinae_score       NUMERIC(5,2) NOT NULL CHECK (tinae_score BETWEEN 0.0 AND 100.0),
    tinae_answers     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    model_version     TEXT        NOT NULL DEFAULT 'V0.0',
    sine_temperature  NUMERIC(4,3) NOT NULL DEFAULT 0.000,
    generated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tinae_detection UNIQUE (detection_id)
);

CREATE TABLE IF NOT EXISTS expert_analysis_reports (
    report_id            UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id         UUID        NOT NULL,
    tenant_id            UUID        NOT NULL,
    report_json          JSONB       NOT NULL,
    report_text          TEXT        NOT NULL DEFAULT '',
    recommendations      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    grounding_context    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    grounding_sources    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    generated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_expert_reports_detection UNIQUE (detection_id)
);

SELECT register_migration(8, 'detections');
