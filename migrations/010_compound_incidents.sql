BEGIN;

-- PRD-03 §2 Migration 010: compound_incidents (PRD-07 V0.0).
-- TimescaleDB hypertable (1-day chunks). Cross-endpoint compound posteriors.

CREATE TABLE IF NOT EXISTS compound_incidents (
    id                 UUID          NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID          NOT NULL REFERENCES tenants(tenant_id),
    detection_ids       UUID[]        NOT NULL,
    ioc_group_key       TEXT          NOT NULL,
    ioc_group_value     TEXT          NOT NULL,
    p_compound          NUMERIC(10,8) NOT NULL CHECK (p_compound > 0 AND p_compound < 1),
    aec_classification  SMALLINT      NOT NULL CHECK (aec_classification IN (0, 1, 2, 3)),
    n_detections        INTEGER       NOT NULL CHECK (n_detections >= 1),
    time_window_start   TIMESTAMPTZ   NOT NULL,
    time_window_end     TIMESTAMPTZ   NOT NULL,
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT pk_compound_incidents PRIMARY KEY (id, time_window_end),
    CONSTRAINT chk_compound_window_order CHECK (time_window_end >= time_window_start)
);

SELECT create_hypertable(
    'compound_incidents',
    'time_window_end',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE INDEX IF NOT EXISTS idx_compound_incidents_tenant_time
    ON compound_incidents(tenant_id, time_window_end DESC);

CREATE INDEX IF NOT EXISTS idx_compound_incidents_group
    ON compound_incidents(tenant_id, ioc_group_key, ioc_group_value, time_window_end DESC);

COMMIT;

