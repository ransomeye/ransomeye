BEGIN;

-- PRD-03 §3 (all non-primary indexes)
CREATE INDEX IF NOT EXISTS idx_tenants_name                  ON tenants(tenant_name);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_tenant         ON agent_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_status         ON agent_sessions(status);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_heartbeat      ON agent_sessions(last_heartbeat DESC);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_boot_sid       ON agent_sessions(boot_session_id);

CREATE INDEX IF NOT EXISTS idx_boot_history_agent            ON boot_session_id_history(agent_id);
CREATE INDEX IF NOT EXISTS idx_boot_history_session          ON boot_session_id_history(boot_session_id);

CREATE INDEX IF NOT EXISTS idx_heartbeats_agent_time         ON agent_heartbeats(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_heartbeats_tenant             ON agent_heartbeats(tenant_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_agent_time          ON telemetry_events(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_tenant_time         ON telemetry_events(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_type                ON telemetry_events(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_clock               ON telemetry_events(logical_clock);
CREATE INDEX IF NOT EXISTS idx_telemetry_payload             ON telemetry_events USING GIN(payload);

CREATE INDEX IF NOT EXISTS idx_detections_tenant_time        ON detections(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detections_agent              ON detections(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detections_aec_class          ON detections(aec_class);
CREATE INDEX IF NOT EXISTS idx_detections_posterior          ON detections(posterior_prob DESC);
CREATE INDEX IF NOT EXISTS idx_detections_disposition        ON detections(analyst_disposition);
CREATE INDEX IF NOT EXISTS idx_detections_model              ON detections(model_hash);
CREATE INDEX IF NOT EXISTS idx_detections_signals            ON detections USING GIN(signals);
CREATE INDEX IF NOT EXISTS idx_detections_bayes              ON detections USING GIN(bayesian_intermediate);

CREATE INDEX IF NOT EXISTS idx_attack_graphs_detection       ON attack_graphs(detection_id);
CREATE INDEX IF NOT EXISTS idx_attack_graphs_tenant          ON attack_graphs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_attack_graphs_mitre           ON attack_graphs USING GIN(mitre_techniques);

COMMIT;

