BEGIN;

-- PRD-03 §2 Migration 035: simulation_runs (PRD-19 V0.0 §7 — ARSE Simulation Gate).

CREATE TABLE IF NOT EXISTS simulation_runs (
    sim_id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 UUID         NOT NULL REFERENCES tenants(tenant_id),
    detection_id              UUID         NOT NULL REFERENCES detections(detection_id),
    action_id                 UUID         REFERENCES actions(action_id),
    risk_score                NUMERIC(5,2) NOT NULL CHECK (risk_score BETWEEN 0.0 AND 100.0),
    affected_systems          JSONB        NOT NULL DEFAULT '[]',
    estimated_downtime_minutes INTEGER     NOT NULL DEFAULT 0 CHECK (estimated_downtime_minutes >= 0),
    recommendation            TEXT         NOT NULL CHECK (recommendation IN ('PROCEED','HOLD','ESCALATE')),
    simulation_detail         JSONB,
    simulated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMIT;

