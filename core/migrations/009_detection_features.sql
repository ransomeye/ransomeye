-- Migration 009: feature extraction state.

CREATE TABLE IF NOT EXISTS detection_features (
    feature_id       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id     UUID        NOT NULL,
    tenant_id        UUID        NOT NULL,
    feature_name     TEXT        NOT NULL,
    feature_scope    TEXT        NOT NULL
                                   CHECK (feature_scope IN (
                                       'process',
                                       'file',
                                       'network',
                                       'user',
                                       'deception',
                                       'behavioral',
                                       'context'
                                   )),
    feature_value    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    feature_weight   NUMERIC(12,8) NOT NULL DEFAULT 0,
    feature_rank     INTEGER     NOT NULL DEFAULT 0 CHECK (feature_rank >= 0),
    extracted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_detection_features_name UNIQUE (detection_id, feature_name)
);

CREATE TABLE IF NOT EXISTS agent_signal_baselines (
    baseline_id             UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,
    agent_id                UUID        NOT NULL,
    signal_type             TEXT        NOT NULL
                                        CHECK (signal_type IN ('process', 'file', 'network', 'user', 'deception')),
    mean_value              NUMERIC(18,8) NOT NULL DEFAULT 0,
    variance_accumulator    NUMERIC(18,8) NOT NULL DEFAULT 0,
    sample_count            BIGINT      NOT NULL DEFAULT 0 CHECK (sample_count >= 0),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agent_signal_baselines UNIQUE (agent_id, signal_type)
);

CREATE TABLE IF NOT EXISTS agent_signal_weights (
    weight_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    agent_id         UUID        NOT NULL,
    signal_type      TEXT        NOT NULL
                                   CHECK (signal_type IN ('process', 'file', 'network', 'user', 'deception')),
    weight_value     NUMERIC(18,8) NOT NULL DEFAULT 1,
    weight_source    TEXT        NOT NULL CHECK (weight_source IN ('MODEL', 'ANALYST', 'SYSTEM')),
    effective_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agent_signal_weights UNIQUE (agent_id, signal_type)
);

SELECT register_migration(9, 'detection_features');
