BEGIN;

-- PRD-03 §5: Row-Level Security (fail-closed via current_setting(..., TRUE)).

-- Enable RLS + FORCE on all specified tables.
ALTER TABLE telemetry_events      ENABLE ROW LEVEL SECURITY;
ALTER TABLE detections            ENABLE ROW LEVEL SECURITY;
ALTER TABLE worm_evidence         ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpi_flows             ENABLE ROW LEVEL SECURITY;
ALTER TABLE actions               ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents             ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_heartbeats      ENABLE ROW LEVEL SECURITY;
ALTER TABLE ndr_findings          ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel_indicators      ENABLE ROW LEVEL SECURITY;
ALTER TABLE exposure_worm_ledger  ENABLE ROW LEVEL SECURITY;
ALTER TABLE merkle_daily_roots    ENABLE ROW LEVEL SECURITY;

ALTER TABLE telemetry_events      FORCE ROW LEVEL SECURITY;
ALTER TABLE detections            FORCE ROW LEVEL SECURITY;
ALTER TABLE worm_evidence         FORCE ROW LEVEL SECURITY;
ALTER TABLE dpi_flows             FORCE ROW LEVEL SECURITY;
ALTER TABLE actions               FORCE ROW LEVEL SECURITY;
ALTER TABLE incidents             FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions        FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_heartbeats      FORCE ROW LEVEL SECURITY;
ALTER TABLE ndr_findings          FORCE ROW LEVEL SECURITY;
ALTER TABLE intel_indicators      FORCE ROW LEVEL SECURITY;
ALTER TABLE exposure_worm_ledger  FORCE ROW LEVEL SECURITY;
ALTER TABLE merkle_daily_roots    FORCE ROW LEVEL SECURITY;

-- Policies (one per table): tenant_id must match app.tenant_id.
DROP POLICY IF EXISTS pol_tenant_telemetry_events ON telemetry_events;
CREATE POLICY pol_tenant_telemetry_events ON telemetry_events
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_detections ON detections;
CREATE POLICY pol_tenant_detections ON detections
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_worm_evidence ON worm_evidence;
CREATE POLICY pol_tenant_worm_evidence ON worm_evidence
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_dpi_flows ON dpi_flows;
CREATE POLICY pol_tenant_dpi_flows ON dpi_flows
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_actions ON actions;
CREATE POLICY pol_tenant_actions ON actions
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_incidents ON incidents;
CREATE POLICY pol_tenant_incidents ON incidents
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_agent_sessions ON agent_sessions;
CREATE POLICY pol_tenant_agent_sessions ON agent_sessions
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_agent_heartbeats ON agent_heartbeats;
CREATE POLICY pol_tenant_agent_heartbeats ON agent_heartbeats
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_ndr_findings ON ndr_findings;
CREATE POLICY pol_tenant_ndr_findings ON ndr_findings
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_intel_indicators ON intel_indicators;
CREATE POLICY pol_tenant_intel_indicators ON intel_indicators
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_exposure_worm_ledger ON exposure_worm_ledger;
CREATE POLICY pol_tenant_exposure_worm_ledger ON exposure_worm_ledger
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

DROP POLICY IF EXISTS pol_tenant_merkle_daily_roots ON merkle_daily_roots;
CREATE POLICY pol_tenant_merkle_daily_roots ON merkle_daily_roots
    USING (tenant_id = current_setting('app.tenant_id', TRUE)::uuid);

COMMIT;

