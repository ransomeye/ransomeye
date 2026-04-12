-- Migration 026: deterministic B-tree indexes.

CREATE INDEX IF NOT EXISTS idx_tenants_slug
    ON tenants(tenant_slug);

CREATE INDEX IF NOT EXISTS idx_agents_tenant_status
    ON agents(tenant_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_tenant_status
    ON agent_sessions(tenant_id, status, last_heartbeat DESC);

CREATE INDEX IF NOT EXISTS idx_boot_session_history_agent_time
    ON boot_session_id_history(agent_id, first_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_tenant_event_time
    ON telemetry_events(tenant_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_agent_event_time
    ON telemetry_events(agent_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_type_event_time
    ON telemetry_events(event_type, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_enriched_tenant_time
    ON telemetry_enriched(tenant_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_dropped_tenant_time
    ON telemetry_dropped(tenant_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_detections_tenant_detected_at
    ON detections(tenant_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_detections_agent_detected_at
    ON detections(agent_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_detections_aec_class
    ON detections(aec_class);

CREATE INDEX IF NOT EXISTS idx_attack_graphs_detection
    ON attack_graphs(detection_id);

CREATE INDEX IF NOT EXISTS idx_attack_paths_detection
    ON attack_paths(detection_id);

CREATE INDEX IF NOT EXISTS idx_detection_features_detection
    ON detection_features(detection_id, feature_rank);

CREATE INDEX IF NOT EXISTS idx_bayesian_detection
    ON bayesian_intermediate(detection_id);

CREATE INDEX IF NOT EXISTS idx_loo_detection_rank
    ON loo_importance(detection_id, rank_order);

CREATE INDEX IF NOT EXISTS idx_worm_evidence_tenant_sealed_at
    ON worm_evidence(tenant_id, sealed_at DESC);

CREATE INDEX IF NOT EXISTS idx_merkle_tree_tenant_sequence
    ON merkle_tree(tenant_id, leaf_sequence DESC);

CREATE INDEX IF NOT EXISTS idx_merkle_roots_tenant_sequence
    ON merkle_roots(tenant_id, leaf_sequence DESC);

CREATE INDEX IF NOT EXISTS idx_merkle_daily_roots_tenant_date
    ON merkle_daily_roots(tenant_id, daily_date DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status_time
    ON incidents(tenant_id, status, last_updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_actions_tenant_status_time
    ON actions(tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_status_time
    ON cases(tenant_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_corroboration_reports_detection
    ON corroboration_reports(detection_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_detection
    ON chat_sessions(detection_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_incident_events_incident_time
    ON incident_events(incident_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_case_artifacts_case_time
    ON case_artifacts(case_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_simulation_runs_action_time
    ON simulation_runs(action_id, simulated_at DESC);

CREATE INDEX IF NOT EXISTS idx_replay_runs_detection_time
    ON replay_runs(detection_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_time
    ON incident_notes(incident_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_case_notes_case_time
    ON case_notes(case_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_policy_rules_tenant_active
    ON policy_rules(tenant_id, is_active, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_hunt_rules_tenant_active
    ON threat_hunt_rules(tenant_id, is_active, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_policy_versions_rule_version
    ON policy_versions(rule_id, version_number DESC);

CREATE INDEX IF NOT EXISTS idx_soc_users_tenant_role
    ON soc_users(tenant_id, role, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_soc_sessions_user_expiry
    ON soc_sessions(user_id, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant_created_at
    ON governance_audit_log(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_intel_indicators_tenant_active
    ON intel_indicators(tenant_id, is_active, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_intel_matches_tenant_event_time
    ON intel_matches(tenant_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_tenant_time
    ON agent_heartbeats(tenant_id, heartbeat_time DESC);

CREATE INDEX IF NOT EXISTS idx_system_metrics_component_time
    ON system_metrics(component, metric_time DESC);

CREATE INDEX IF NOT EXISTS idx_registered_probes_tenant_status
    ON registered_probes(tenant_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_endpoint_inventory_agent_time
    ON endpoint_software_inventory(agent_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_endpoint_vulnerability_agent_time
    ON endpoint_vulnerability_scores(agent_id, computed_at DESC);

CREATE INDEX IF NOT EXISTS idx_ingestion_stats_source_time
    ON ingestion_stats(source, stat_time DESC);

CREATE INDEX IF NOT EXISTS idx_dpi_flows_tenant_time
    ON dpi_flows(tenant_id, flow_time DESC);

CREATE INDEX IF NOT EXISTS idx_ndr_findings_tenant_time
    ON ndr_findings(tenant_id, finding_time DESC);

CREATE INDEX IF NOT EXISTS idx_network_infra_findings_tenant_time
    ON network_infra_findings(tenant_id, finding_time DESC);

CREATE INDEX IF NOT EXISTS idx_snmp_device_inventory_probe_time
    ON snmp_device_inventory(probe_id, updated_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bundle_application_log_sequence
    ON bundle_application_log(sequence_number);

SELECT register_migration(26, 'indexes');
