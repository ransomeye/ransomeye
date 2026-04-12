BEGIN;

-- PRD-03 §2 Migration 011: kill_chain_states (PRD-07 V0.0).
-- Per-agent MITRE ATT&CK phase accumulation state (Core Engine KillChainFSM).

CREATE TABLE IF NOT EXISTS kill_chain_states (
    agent_id        UUID         NOT NULL REFERENCES agent_sessions(agent_id),
    tenant_id       UUID         NOT NULL REFERENCES tenants(tenant_id),
    phase           TEXT         NOT NULL CHECK (phase IN (
                        'reconnaissance','initial-access','execution','persistence',
                        'privilege-escalation','defense-evasion','lateral-movement',
                        'exfiltration','impact')),
    phase_posterior NUMERIC(10,8) NOT NULL CHECK (phase_posterior >= 0 AND phase_posterior <= 1),
    decay_weight    NUMERIC(10,8) NOT NULL CHECK (decay_weight >= 0 AND decay_weight <= 1),
    compound_score  NUMERIC(12,8) NOT NULL CHECK (compound_score >= 0),
    last_updated_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, phase)
);

CREATE INDEX IF NOT EXISTS idx_kill_chain_states_tenant
    ON kill_chain_states(tenant_id, last_updated_at DESC);

COMMIT;

