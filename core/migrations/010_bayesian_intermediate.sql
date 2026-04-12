-- Migration 010: Bayesian intermediate state and compound evidence tracking.

CREATE TABLE IF NOT EXISTS bayesian_intermediate (
    bayesian_id       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id      UUID        NOT NULL,
    tenant_id         UUID        NOT NULL,
    prior_prob        NUMERIC(12,10) NOT NULL CHECK (prior_prob > 0 AND prior_prob < 1),
    posterior_prob    NUMERIC(12,10) NOT NULL CHECK (posterior_prob > 0 AND posterior_prob < 1),
    lambda_used       NUMERIC(4,3) NOT NULL CHECK (lambda_used IN (0.100, 0.850)),
    frozen_prior      NUMERIC(12,10) NOT NULL CHECK (frozen_prior > 0 AND frozen_prior < 1),
    likelihoods_json  JSONB       NOT NULL DEFAULT '{}'::jsonb,
    posterior_vector  JSONB       NOT NULL DEFAULT '{}'::jsonb,
    evidence_json     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_bayesian_detection UNIQUE (detection_id)
);

CREATE TABLE IF NOT EXISTS compound_incidents (
    compound_id         UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL,
    detection_ids       UUID[]      NOT NULL DEFAULT ARRAY[]::uuid[],
    ioc_group_key       TEXT        NOT NULL,
    ioc_group_value     TEXT        NOT NULL,
    p_compound          NUMERIC(10,8) NOT NULL CHECK (p_compound > 0 AND p_compound < 1),
    aec_classification  SMALLINT    NOT NULL CHECK (aec_classification IN (0, 1, 2, 3)),
    n_detections        INTEGER     NOT NULL CHECK (n_detections >= 1),
    time_window_start   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    time_window_end     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (compound_id, time_window_end)
);

CREATE TABLE IF NOT EXISTS kill_chain_states (
    state_id          UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id          UUID        NOT NULL,
    tenant_id         UUID        NOT NULL,
    phase             TEXT        NOT NULL
                                  CHECK (phase IN (
                                      'reconnaissance',
                                      'initial-access',
                                      'execution',
                                      'persistence',
                                      'privilege-escalation',
                                      'defense-evasion',
                                      'lateral-movement',
                                      'exfiltration',
                                      'impact'
                                  )),
    phase_posterior   NUMERIC(10,8) NOT NULL CHECK (phase_posterior >= 0 AND phase_posterior <= 1),
    decay_weight      NUMERIC(10,8) NOT NULL CHECK (decay_weight >= 0 AND decay_weight <= 1),
    compound_score    NUMERIC(12,8) NOT NULL CHECK (compound_score >= 0),
    last_updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_kill_chain_state UNIQUE (agent_id, phase)
);

SELECT register_migration(10, 'bayesian_intermediate');
