-- Migration 011: leave-one-out explainability and suppression audit state.

CREATE TABLE IF NOT EXISTS loo_importance (
    loo_id                   UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id             UUID        NOT NULL,
    tenant_id                UUID        NOT NULL,
    feature_name             TEXT        NOT NULL,
    importance_score         NUMERIC(18,8) NOT NULL,
    baseline_posterior       NUMERIC(12,10) NOT NULL CHECK (baseline_posterior > 0 AND baseline_posterior < 1),
    perturbed_posterior      NUMERIC(12,10) NOT NULL CHECK (perturbed_posterior > 0 AND perturbed_posterior < 1),
    rank_order               INTEGER     NOT NULL DEFAULT 0 CHECK (rank_order >= 0),
    circuit_breaker_tripped  BOOLEAN     NOT NULL DEFAULT FALSE,
    explanation_json         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_loo_detection_feature UNIQUE (detection_id, feature_name)
);

CREATE TABLE IF NOT EXISTS fp_suppression_models (
    model_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    model_version   TEXT        NOT NULL,
    model_type      TEXT        NOT NULL CHECK (model_type IN ('KNN')),
    parameters      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    is_active       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_fp_suppression_model UNIQUE (tenant_id, model_version)
);

CREATE TABLE IF NOT EXISTS fp_suppression_audit (
    audit_id             UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL,
    detection_id         UUID        NOT NULL,
    model_id             UUID,
    suppression_factor   NUMERIC(6,5) NOT NULL CHECK (suppression_factor >= 0 AND suppression_factor <= 1),
    posterior_before     NUMERIC(12,10) NOT NULL CHECK (posterior_before > 0 AND posterior_before < 1),
    posterior_after      NUMERIC(12,10) NOT NULL CHECK (posterior_after > 0 AND posterior_after < 1),
    reason_json          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS signal_recalibration_audit (
    audit_id        UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    agent_id        UUID,
    signal_type     TEXT        NOT NULL
                                   CHECK (signal_type IN ('process', 'file', 'network', 'user', 'deception')),
    old_weight      NUMERIC(18,8) NOT NULL CHECK (old_weight >= 0),
    new_weight      NUMERIC(18,8) NOT NULL CHECK (new_weight >= 0),
    reason          TEXT        NOT NULL DEFAULT '',
    approved_by     TEXT        NOT NULL,
    approved_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT register_migration(11, 'loo_importance');
