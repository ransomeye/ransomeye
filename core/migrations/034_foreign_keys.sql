-- Migration 034: relational integrity constraints.

ALTER TABLE agents
    DROP CONSTRAINT IF EXISTS fk_agents_tenant;
ALTER TABLE agents
    ADD CONSTRAINT fk_agents_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE agent_sessions
    DROP CONSTRAINT IF EXISTS fk_agent_sessions_tenant;
ALTER TABLE agent_sessions
    ADD CONSTRAINT fk_agent_sessions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE boot_session_id_history
    DROP CONSTRAINT IF EXISTS fk_boot_history_tenant;
ALTER TABLE boot_session_id_history
    ADD CONSTRAINT fk_boot_history_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE boot_session_id_history
    DROP CONSTRAINT IF EXISTS fk_boot_history_agent;
ALTER TABLE boot_session_id_history
    ADD CONSTRAINT fk_boot_history_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE telemetry_events
    DROP CONSTRAINT IF EXISTS fk_telemetry_events_tenant;
ALTER TABLE telemetry_events
    ADD CONSTRAINT fk_telemetry_events_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE telemetry_events
    DROP CONSTRAINT IF EXISTS fk_telemetry_events_agent;
ALTER TABLE telemetry_events
    ADD CONSTRAINT fk_telemetry_events_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE telemetry_enriched
    DROP CONSTRAINT IF EXISTS fk_telemetry_enriched_tenant;
ALTER TABLE telemetry_enriched
    ADD CONSTRAINT fk_telemetry_enriched_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE telemetry_dropped
    DROP CONSTRAINT IF EXISTS fk_telemetry_dropped_tenant;
ALTER TABLE telemetry_dropped
    ADD CONSTRAINT fk_telemetry_dropped_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE telemetry_dropped
    DROP CONSTRAINT IF EXISTS fk_telemetry_dropped_agent;
ALTER TABLE telemetry_dropped
    ADD CONSTRAINT fk_telemetry_dropped_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE detections
    DROP CONSTRAINT IF EXISTS fk_detections_tenant;
ALTER TABLE detections
    ADD CONSTRAINT fk_detections_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE detections
    DROP CONSTRAINT IF EXISTS fk_detections_agent;
ALTER TABLE detections
    ADD CONSTRAINT fk_detections_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE attack_graphs
    DROP CONSTRAINT IF EXISTS fk_attack_graphs_detection;
ALTER TABLE attack_graphs
    ADD CONSTRAINT fk_attack_graphs_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE;

ALTER TABLE attack_graphs
    DROP CONSTRAINT IF EXISTS fk_attack_graphs_tenant;
ALTER TABLE attack_graphs
    ADD CONSTRAINT fk_attack_graphs_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE attack_paths
    DROP CONSTRAINT IF EXISTS fk_attack_paths_detection;
ALTER TABLE attack_paths
    ADD CONSTRAINT fk_attack_paths_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE;

ALTER TABLE attack_paths
    DROP CONSTRAINT IF EXISTS fk_attack_paths_tenant;
ALTER TABLE attack_paths
    ADD CONSTRAINT fk_attack_paths_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE tinae_executive_summaries
    DROP CONSTRAINT IF EXISTS fk_tinae_detection;
ALTER TABLE tinae_executive_summaries
    ADD CONSTRAINT fk_tinae_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE;

ALTER TABLE tinae_executive_summaries
    DROP CONSTRAINT IF EXISTS fk_tinae_tenant;
ALTER TABLE tinae_executive_summaries
    ADD CONSTRAINT fk_tinae_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE expert_analysis_reports
    DROP CONSTRAINT IF EXISTS fk_expert_reports_detection;
ALTER TABLE expert_analysis_reports
    ADD CONSTRAINT fk_expert_reports_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE;

ALTER TABLE expert_analysis_reports
    DROP CONSTRAINT IF EXISTS fk_expert_reports_tenant;
ALTER TABLE expert_analysis_reports
    ADD CONSTRAINT fk_expert_reports_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE detection_features
    DROP CONSTRAINT IF EXISTS fk_detection_features_detection;
ALTER TABLE detection_features
    ADD CONSTRAINT fk_detection_features_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE;

ALTER TABLE detection_features
    DROP CONSTRAINT IF EXISTS fk_detection_features_tenant;
ALTER TABLE detection_features
    ADD CONSTRAINT fk_detection_features_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE agent_signal_baselines
    DROP CONSTRAINT IF EXISTS fk_agent_signal_baselines_tenant;
ALTER TABLE agent_signal_baselines
    ADD CONSTRAINT fk_agent_signal_baselines_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE agent_signal_baselines
    DROP CONSTRAINT IF EXISTS fk_agent_signal_baselines_agent;
ALTER TABLE agent_signal_baselines
    ADD CONSTRAINT fk_agent_signal_baselines_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE agent_signal_weights
    DROP CONSTRAINT IF EXISTS fk_agent_signal_weights_tenant;
ALTER TABLE agent_signal_weights
    ADD CONSTRAINT fk_agent_signal_weights_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE agent_signal_weights
    DROP CONSTRAINT IF EXISTS fk_agent_signal_weights_agent;
ALTER TABLE agent_signal_weights
    ADD CONSTRAINT fk_agent_signal_weights_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE bayesian_intermediate
    DROP CONSTRAINT IF EXISTS fk_bayesian_intermediate_detection;
ALTER TABLE bayesian_intermediate
    ADD CONSTRAINT fk_bayesian_intermediate_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE;

ALTER TABLE bayesian_intermediate
    DROP CONSTRAINT IF EXISTS fk_bayesian_intermediate_tenant;
ALTER TABLE bayesian_intermediate
    ADD CONSTRAINT fk_bayesian_intermediate_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE compound_incidents
    DROP CONSTRAINT IF EXISTS fk_compound_incidents_tenant;
ALTER TABLE compound_incidents
    ADD CONSTRAINT fk_compound_incidents_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE kill_chain_states
    DROP CONSTRAINT IF EXISTS fk_kill_chain_states_tenant;
ALTER TABLE kill_chain_states
    ADD CONSTRAINT fk_kill_chain_states_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE kill_chain_states
    DROP CONSTRAINT IF EXISTS fk_kill_chain_states_agent;
ALTER TABLE kill_chain_states
    ADD CONSTRAINT fk_kill_chain_states_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE loo_importance
    DROP CONSTRAINT IF EXISTS fk_loo_importance_detection;
ALTER TABLE loo_importance
    ADD CONSTRAINT fk_loo_importance_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE;

ALTER TABLE loo_importance
    DROP CONSTRAINT IF EXISTS fk_loo_importance_tenant;
ALTER TABLE loo_importance
    ADD CONSTRAINT fk_loo_importance_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE fp_suppression_models
    DROP CONSTRAINT IF EXISTS fk_fp_suppression_models_tenant;
ALTER TABLE fp_suppression_models
    ADD CONSTRAINT fk_fp_suppression_models_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE fp_suppression_audit
    DROP CONSTRAINT IF EXISTS fk_fp_suppression_audit_tenant;
ALTER TABLE fp_suppression_audit
    ADD CONSTRAINT fk_fp_suppression_audit_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE fp_suppression_audit
    DROP CONSTRAINT IF EXISTS fk_fp_suppression_audit_detection;
ALTER TABLE fp_suppression_audit
    ADD CONSTRAINT fk_fp_suppression_audit_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE;

ALTER TABLE fp_suppression_audit
    DROP CONSTRAINT IF EXISTS fk_fp_suppression_audit_model;
ALTER TABLE fp_suppression_audit
    ADD CONSTRAINT fk_fp_suppression_audit_model
    FOREIGN KEY (model_id) REFERENCES fp_suppression_models(model_id);

ALTER TABLE signal_recalibration_audit
    DROP CONSTRAINT IF EXISTS fk_signal_recalibration_audit_tenant;
ALTER TABLE signal_recalibration_audit
    ADD CONSTRAINT fk_signal_recalibration_audit_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE signal_recalibration_audit
    DROP CONSTRAINT IF EXISTS fk_signal_recalibration_audit_agent;
ALTER TABLE signal_recalibration_audit
    ADD CONSTRAINT fk_signal_recalibration_audit_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE worm_evidence
    DROP CONSTRAINT IF EXISTS fk_worm_evidence_tenant;
ALTER TABLE worm_evidence
    ADD CONSTRAINT fk_worm_evidence_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE worm_evidence
    DROP CONSTRAINT IF EXISTS fk_worm_evidence_detection;
ALTER TABLE worm_evidence
    ADD CONSTRAINT fk_worm_evidence_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id);

ALTER TABLE exposure_worm_ledger
    DROP CONSTRAINT IF EXISTS fk_exposure_worm_ledger_tenant;
ALTER TABLE exposure_worm_ledger
    ADD CONSTRAINT fk_exposure_worm_ledger_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE exposure_worm_ledger
    DROP CONSTRAINT IF EXISTS fk_exposure_worm_ledger_evidence;
ALTER TABLE exposure_worm_ledger
    ADD CONSTRAINT fk_exposure_worm_ledger_evidence
    FOREIGN KEY (evidence_id) REFERENCES worm_evidence(evidence_id);

ALTER TABLE merkle_tree
    DROP CONSTRAINT IF EXISTS fk_merkle_tree_tenant;
ALTER TABLE merkle_tree
    ADD CONSTRAINT fk_merkle_tree_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE merkle_roots
    DROP CONSTRAINT IF EXISTS fk_merkle_roots_tenant;
ALTER TABLE merkle_roots
    ADD CONSTRAINT fk_merkle_roots_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE merkle_daily_roots
    DROP CONSTRAINT IF EXISTS fk_merkle_daily_roots_tenant;
ALTER TABLE merkle_daily_roots
    ADD CONSTRAINT fk_merkle_daily_roots_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE incidents
    DROP CONSTRAINT IF EXISTS fk_incidents_tenant;
ALTER TABLE incidents
    ADD CONSTRAINT fk_incidents_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE detections
    DROP CONSTRAINT IF EXISTS fk_detections_incident;
ALTER TABLE detections
    ADD CONSTRAINT fk_detections_incident
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id);

ALTER TABLE actions
    DROP CONSTRAINT IF EXISTS fk_actions_tenant;
ALTER TABLE actions
    ADD CONSTRAINT fk_actions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE actions
    DROP CONSTRAINT IF EXISTS fk_actions_detection;
ALTER TABLE actions
    ADD CONSTRAINT fk_actions_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id);

ALTER TABLE actions
    DROP CONSTRAINT IF EXISTS fk_actions_agent;
ALTER TABLE actions
    ADD CONSTRAINT fk_actions_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE cases
    DROP CONSTRAINT IF EXISTS fk_cases_tenant;
ALTER TABLE cases
    ADD CONSTRAINT fk_cases_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE cases
    DROP CONSTRAINT IF EXISTS fk_cases_incident;
ALTER TABLE cases
    ADD CONSTRAINT fk_cases_incident
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id);

ALTER TABLE corroboration_reports
    DROP CONSTRAINT IF EXISTS fk_corroboration_reports_tenant;
ALTER TABLE corroboration_reports
    ADD CONSTRAINT fk_corroboration_reports_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE corroboration_reports
    DROP CONSTRAINT IF EXISTS fk_corroboration_reports_detection;
ALTER TABLE corroboration_reports
    ADD CONSTRAINT fk_corroboration_reports_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id);

ALTER TABLE chat_sessions
    DROP CONSTRAINT IF EXISTS fk_chat_sessions_tenant;
ALTER TABLE chat_sessions
    ADD CONSTRAINT fk_chat_sessions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE chat_sessions
    DROP CONSTRAINT IF EXISTS fk_chat_sessions_detection;
ALTER TABLE chat_sessions
    ADD CONSTRAINT fk_chat_sessions_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id);

ALTER TABLE incident_events
    DROP CONSTRAINT IF EXISTS fk_incident_events_tenant;
ALTER TABLE incident_events
    ADD CONSTRAINT fk_incident_events_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE incident_events
    DROP CONSTRAINT IF EXISTS fk_incident_events_incident;
ALTER TABLE incident_events
    ADD CONSTRAINT fk_incident_events_incident
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id);

ALTER TABLE incident_events
    DROP CONSTRAINT IF EXISTS fk_incident_events_detection;
ALTER TABLE incident_events
    ADD CONSTRAINT fk_incident_events_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id);

ALTER TABLE incident_events
    DROP CONSTRAINT IF EXISTS fk_incident_events_action;
ALTER TABLE incident_events
    ADD CONSTRAINT fk_incident_events_action
    FOREIGN KEY (action_id) REFERENCES actions(action_id);

ALTER TABLE case_artifacts
    DROP CONSTRAINT IF EXISTS fk_case_artifacts_tenant;
ALTER TABLE case_artifacts
    ADD CONSTRAINT fk_case_artifacts_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE case_artifacts
    DROP CONSTRAINT IF EXISTS fk_case_artifacts_case;
ALTER TABLE case_artifacts
    ADD CONSTRAINT fk_case_artifacts_case
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE;

ALTER TABLE simulation_runs
    DROP CONSTRAINT IF EXISTS fk_simulation_runs_tenant;
ALTER TABLE simulation_runs
    ADD CONSTRAINT fk_simulation_runs_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE simulation_runs
    DROP CONSTRAINT IF EXISTS fk_simulation_runs_detection;
ALTER TABLE simulation_runs
    ADD CONSTRAINT fk_simulation_runs_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id);

ALTER TABLE simulation_runs
    DROP CONSTRAINT IF EXISTS fk_simulation_runs_action;
ALTER TABLE simulation_runs
    ADD CONSTRAINT fk_simulation_runs_action
    FOREIGN KEY (action_id) REFERENCES actions(action_id);

ALTER TABLE replay_runs
    DROP CONSTRAINT IF EXISTS fk_replay_runs_tenant;
ALTER TABLE replay_runs
    ADD CONSTRAINT fk_replay_runs_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE replay_runs
    DROP CONSTRAINT IF EXISTS fk_replay_runs_case;
ALTER TABLE replay_runs
    ADD CONSTRAINT fk_replay_runs_case
    FOREIGN KEY (case_id) REFERENCES cases(case_id);

ALTER TABLE replay_runs
    DROP CONSTRAINT IF EXISTS fk_replay_runs_detection;
ALTER TABLE replay_runs
    ADD CONSTRAINT fk_replay_runs_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id);

ALTER TABLE incident_notes
    DROP CONSTRAINT IF EXISTS fk_incident_notes_tenant;
ALTER TABLE incident_notes
    ADD CONSTRAINT fk_incident_notes_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE incident_notes
    DROP CONSTRAINT IF EXISTS fk_incident_notes_incident;
ALTER TABLE incident_notes
    ADD CONSTRAINT fk_incident_notes_incident
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE;

ALTER TABLE case_notes
    DROP CONSTRAINT IF EXISTS fk_case_notes_tenant;
ALTER TABLE case_notes
    ADD CONSTRAINT fk_case_notes_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE case_notes
    DROP CONSTRAINT IF EXISTS fk_case_notes_case;
ALTER TABLE case_notes
    ADD CONSTRAINT fk_case_notes_case
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE;

ALTER TABLE policy_rules
    DROP CONSTRAINT IF EXISTS fk_policy_rules_tenant;
ALTER TABLE policy_rules
    ADD CONSTRAINT fk_policy_rules_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE threat_hunt_rules
    DROP CONSTRAINT IF EXISTS fk_threat_hunt_rules_tenant;
ALTER TABLE threat_hunt_rules
    ADD CONSTRAINT fk_threat_hunt_rules_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE policy_versions
    DROP CONSTRAINT IF EXISTS fk_policy_versions_tenant;
ALTER TABLE policy_versions
    ADD CONSTRAINT fk_policy_versions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE policy_versions
    DROP CONSTRAINT IF EXISTS fk_policy_versions_rule;
ALTER TABLE policy_versions
    ADD CONSTRAINT fk_policy_versions_rule
    FOREIGN KEY (rule_id) REFERENCES policy_rules(rule_id) ON DELETE CASCADE;

ALTER TABLE soc_users
    DROP CONSTRAINT IF EXISTS fk_soc_users_tenant;
ALTER TABLE soc_users
    ADD CONSTRAINT fk_soc_users_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE actions
    DROP CONSTRAINT IF EXISTS fk_actions_second_approver;
ALTER TABLE actions
    ADD CONSTRAINT fk_actions_second_approver
    FOREIGN KEY (second_approver_id) REFERENCES soc_users(user_id);

ALTER TABLE soc_sessions
    DROP CONSTRAINT IF EXISTS fk_soc_sessions_tenant;
ALTER TABLE soc_sessions
    ADD CONSTRAINT fk_soc_sessions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE soc_sessions
    DROP CONSTRAINT IF EXISTS fk_soc_sessions_user;
ALTER TABLE soc_sessions
    ADD CONSTRAINT fk_soc_sessions_user
    FOREIGN KEY (user_id) REFERENCES soc_users(user_id) ON DELETE CASCADE;

ALTER TABLE compliance_reports
    DROP CONSTRAINT IF EXISTS fk_compliance_reports_tenant;
ALTER TABLE compliance_reports
    ADD CONSTRAINT fk_compliance_reports_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE model_config_audit
    DROP CONSTRAINT IF EXISTS fk_model_config_audit_tenant;
ALTER TABLE model_config_audit
    ADD CONSTRAINT fk_model_config_audit_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE ai_conformity_reports
    DROP CONSTRAINT IF EXISTS fk_ai_conformity_reports_tenant;
ALTER TABLE ai_conformity_reports
    ADD CONSTRAINT fk_ai_conformity_reports_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE governance_audit_log
    DROP CONSTRAINT IF EXISTS fk_governance_audit_log_tenant;
ALTER TABLE governance_audit_log
    ADD CONSTRAINT fk_governance_audit_log_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE intel_indicators
    DROP CONSTRAINT IF EXISTS fk_intel_indicators_tenant;
ALTER TABLE intel_indicators
    ADD CONSTRAINT fk_intel_indicators_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE threat_actor_groups
    DROP CONSTRAINT IF EXISTS fk_threat_actor_groups_tenant;
ALTER TABLE threat_actor_groups
    ADD CONSTRAINT fk_threat_actor_groups_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE threat_intel_iocs
    DROP CONSTRAINT IF EXISTS fk_threat_intel_iocs_tenant;
ALTER TABLE threat_intel_iocs
    ADD CONSTRAINT fk_threat_intel_iocs_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE threat_intel_iocs
    DROP CONSTRAINT IF EXISTS fk_threat_intel_iocs_indicator;
ALTER TABLE threat_intel_iocs
    ADD CONSTRAINT fk_threat_intel_iocs_indicator
    FOREIGN KEY (indicator_id) REFERENCES intel_indicators(indicator_id);

ALTER TABLE threat_intel_iocs
    DROP CONSTRAINT IF EXISTS fk_threat_intel_iocs_actor_group;
ALTER TABLE threat_intel_iocs
    ADD CONSTRAINT fk_threat_intel_iocs_actor_group
    FOREIGN KEY (actor_group_id) REFERENCES threat_actor_groups(group_id);

ALTER TABLE intel_matches
    DROP CONSTRAINT IF EXISTS fk_intel_matches_tenant;
ALTER TABLE intel_matches
    ADD CONSTRAINT fk_intel_matches_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE intel_matches
    DROP CONSTRAINT IF EXISTS fk_intel_matches_indicator;
ALTER TABLE intel_matches
    ADD CONSTRAINT fk_intel_matches_indicator
    FOREIGN KEY (indicator_id) REFERENCES intel_indicators(indicator_id);

ALTER TABLE intel_matches
    DROP CONSTRAINT IF EXISTS fk_intel_matches_detection;
ALTER TABLE intel_matches
    ADD CONSTRAINT fk_intel_matches_detection
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id);

ALTER TABLE agent_heartbeats
    DROP CONSTRAINT IF EXISTS fk_agent_heartbeats_tenant;
ALTER TABLE agent_heartbeats
    ADD CONSTRAINT fk_agent_heartbeats_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE agent_heartbeats
    DROP CONSTRAINT IF EXISTS fk_agent_heartbeats_agent;
ALTER TABLE agent_heartbeats
    ADD CONSTRAINT fk_agent_heartbeats_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE system_metrics
    DROP CONSTRAINT IF EXISTS fk_system_metrics_tenant;
ALTER TABLE system_metrics
    ADD CONSTRAINT fk_system_metrics_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE registered_probes
    DROP CONSTRAINT IF EXISTS fk_registered_probes_tenant;
ALTER TABLE registered_probes
    ADD CONSTRAINT fk_registered_probes_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE endpoint_software_inventory
    DROP CONSTRAINT IF EXISTS fk_endpoint_software_inventory_tenant;
ALTER TABLE endpoint_software_inventory
    ADD CONSTRAINT fk_endpoint_software_inventory_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE endpoint_software_inventory
    DROP CONSTRAINT IF EXISTS fk_endpoint_software_inventory_agent;
ALTER TABLE endpoint_software_inventory
    ADD CONSTRAINT fk_endpoint_software_inventory_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE endpoint_vulnerability_scores
    DROP CONSTRAINT IF EXISTS fk_endpoint_vulnerability_scores_tenant;
ALTER TABLE endpoint_vulnerability_scores
    ADD CONSTRAINT fk_endpoint_vulnerability_scores_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE endpoint_vulnerability_scores
    DROP CONSTRAINT IF EXISTS fk_endpoint_vulnerability_scores_agent;
ALTER TABLE endpoint_vulnerability_scores
    ADD CONSTRAINT fk_endpoint_vulnerability_scores_agent
    FOREIGN KEY (agent_id) REFERENCES agent_sessions(agent_id);

ALTER TABLE ingestion_stats
    DROP CONSTRAINT IF EXISTS fk_ingestion_stats_tenant;
ALTER TABLE ingestion_stats
    ADD CONSTRAINT fk_ingestion_stats_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE dpi_flows
    DROP CONSTRAINT IF EXISTS fk_dpi_flows_tenant;
ALTER TABLE dpi_flows
    ADD CONSTRAINT fk_dpi_flows_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE dpi_flows
    DROP CONSTRAINT IF EXISTS fk_dpi_flows_probe;
ALTER TABLE dpi_flows
    ADD CONSTRAINT fk_dpi_flows_probe
    FOREIGN KEY (probe_id) REFERENCES registered_probes(probe_id);

ALTER TABLE ndr_findings
    DROP CONSTRAINT IF EXISTS fk_ndr_findings_tenant;
ALTER TABLE ndr_findings
    ADD CONSTRAINT fk_ndr_findings_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE ndr_findings
    DROP CONSTRAINT IF EXISTS fk_ndr_findings_probe;
ALTER TABLE ndr_findings
    ADD CONSTRAINT fk_ndr_findings_probe
    FOREIGN KEY (probe_id) REFERENCES registered_probes(probe_id);

ALTER TABLE ndr_findings
    DROP CONSTRAINT IF EXISTS fk_ndr_findings_detection;
ALTER TABLE ndr_findings
    ADD CONSTRAINT fk_ndr_findings_detection
    FOREIGN KEY (linked_detection_id) REFERENCES detections(detection_id);

ALTER TABLE network_infra_findings
    DROP CONSTRAINT IF EXISTS fk_network_infra_findings_tenant;
ALTER TABLE network_infra_findings
    ADD CONSTRAINT fk_network_infra_findings_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE network_infra_findings
    DROP CONSTRAINT IF EXISTS fk_network_infra_findings_probe;
ALTER TABLE network_infra_findings
    ADD CONSTRAINT fk_network_infra_findings_probe
    FOREIGN KEY (probe_id) REFERENCES registered_probes(probe_id);

ALTER TABLE snmp_device_inventory
    DROP CONSTRAINT IF EXISTS fk_snmp_device_inventory_tenant;
ALTER TABLE snmp_device_inventory
    ADD CONSTRAINT fk_snmp_device_inventory_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

ALTER TABLE snmp_device_inventory
    DROP CONSTRAINT IF EXISTS fk_snmp_device_inventory_probe;
ALTER TABLE snmp_device_inventory
    ADD CONSTRAINT fk_snmp_device_inventory_probe
    FOREIGN KEY (probe_id) REFERENCES registered_probes(probe_id);

ALTER TABLE bundle_application_log
    DROP CONSTRAINT IF EXISTS fk_bundle_application_log_tenant;
ALTER TABLE bundle_application_log
    ADD CONSTRAINT fk_bundle_application_log_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);

SELECT register_migration(34, 'foreign_keys');
