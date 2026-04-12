-- Migration 036: GIN indexes for JSONB forensic queries.

CREATE INDEX IF NOT EXISTS idx_agents_metadata_gin
    ON agents USING GIN (metadata);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_tpm_pcr_values_gin
    ON agent_sessions USING GIN (tpm_pcr_values);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_os_info_gin
    ON agent_sessions USING GIN (os_info);

CREATE INDEX IF NOT EXISTS idx_telemetry_payload_json_gin
    ON telemetry_events USING GIN (payload_json);

CREATE INDEX IF NOT EXISTS idx_telemetry_enriched_json_gin
    ON telemetry_enriched USING GIN (enrichment_json);

CREATE INDEX IF NOT EXISTS idx_telemetry_dropped_details_gin
    ON telemetry_dropped USING GIN (details_json);

CREATE INDEX IF NOT EXISTS idx_detections_signals_gin
    ON detections USING GIN (signals);

CREATE INDEX IF NOT EXISTS idx_detections_loo_importance_gin
    ON detections USING GIN (loo_importance);

CREATE INDEX IF NOT EXISTS idx_detections_bayesian_intermediate_gin
    ON detections USING GIN (bayesian_intermediate);

CREATE INDEX IF NOT EXISTS idx_attack_graphs_graph_json_gin
    ON attack_graphs USING GIN (graph_json);

CREATE INDEX IF NOT EXISTS idx_attack_graphs_mitre_gin
    ON attack_graphs USING GIN (mitre_techniques);

CREATE INDEX IF NOT EXISTS idx_attack_paths_node_sequence_gin
    ON attack_paths USING GIN (node_sequence);

CREATE INDEX IF NOT EXISTS idx_tinae_answers_gin
    ON tinae_executive_summaries USING GIN (tinae_answers);

CREATE INDEX IF NOT EXISTS idx_expert_reports_json_gin
    ON expert_analysis_reports USING GIN (report_json);

CREATE INDEX IF NOT EXISTS idx_expert_reports_recommendations_gin
    ON expert_analysis_reports USING GIN (recommendations);

CREATE INDEX IF NOT EXISTS idx_detection_features_value_gin
    ON detection_features USING GIN (feature_value);

CREATE INDEX IF NOT EXISTS idx_bayesian_intermediate_likelihoods_gin
    ON bayesian_intermediate USING GIN (likelihoods_json);

CREATE INDEX IF NOT EXISTS idx_bayesian_intermediate_posterior_vector_gin
    ON bayesian_intermediate USING GIN (posterior_vector);

CREATE INDEX IF NOT EXISTS idx_loo_importance_explanation_gin
    ON loo_importance USING GIN (explanation_json);

CREATE INDEX IF NOT EXISTS idx_fp_suppression_models_parameters_gin
    ON fp_suppression_models USING GIN (parameters);

CREATE INDEX IF NOT EXISTS idx_fp_suppression_audit_reason_gin
    ON fp_suppression_audit USING GIN (reason_json);

CREATE INDEX IF NOT EXISTS idx_corroboration_reports_json_gin
    ON corroboration_reports USING GIN (report_json);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_messages_gin
    ON chat_sessions USING GIN (messages);

CREATE INDEX IF NOT EXISTS idx_incident_events_payload_gin
    ON incident_events USING GIN (event_payload);

CREATE INDEX IF NOT EXISTS idx_policy_rules_rule_json_gin
    ON policy_rules USING GIN (rule_json);

CREATE INDEX IF NOT EXISTS idx_policy_rules_signed_by_gin
    ON policy_rules USING GIN (signed_by);

CREATE INDEX IF NOT EXISTS idx_policy_versions_rule_json_gin
    ON policy_versions USING GIN (rule_json);

CREATE INDEX IF NOT EXISTS idx_compliance_reports_json_gin
    ON compliance_reports USING GIN (report_json);

CREATE INDEX IF NOT EXISTS idx_model_config_audit_signatures_gin
    ON model_config_audit USING GIN (signatures);

CREATE INDEX IF NOT EXISTS idx_model_config_audit_details_gin
    ON model_config_audit USING GIN (details);

CREATE INDEX IF NOT EXISTS idx_ai_conformity_reports_json_gin
    ON ai_conformity_reports USING GIN (report_json);

CREATE INDEX IF NOT EXISTS idx_governance_audit_details_gin
    ON governance_audit_log USING GIN (details_json);

CREATE INDEX IF NOT EXISTS idx_intel_indicators_tags_gin
    ON intel_indicators USING GIN (tags);

CREATE INDEX IF NOT EXISTS idx_intel_indicators_metadata_gin
    ON intel_indicators USING GIN (metadata);

CREATE INDEX IF NOT EXISTS idx_threat_actor_groups_ttps_gin
    ON threat_actor_groups USING GIN (known_ttps);

CREATE INDEX IF NOT EXISTS idx_intel_matches_context_gin
    ON intel_matches USING GIN (raw_context);

CREATE INDEX IF NOT EXISTS idx_system_metrics_labels_gin
    ON system_metrics USING GIN (metric_labels);

CREATE INDEX IF NOT EXISTS idx_dpi_flows_flags_gin
    ON dpi_flows USING GIN (detection_flags);

CREATE INDEX IF NOT EXISTS idx_network_infra_details_gin
    ON network_infra_findings USING GIN (details_json);

CREATE INDEX IF NOT EXISTS idx_network_infra_raw_evidence_gin
    ON network_infra_findings USING GIN (raw_evidence);

CREATE INDEX IF NOT EXISTS idx_bundle_application_artifacts_gin
    ON bundle_application_log USING GIN (artifacts_json);

CREATE INDEX IF NOT EXISTS idx_bundle_application_migrations_gin
    ON bundle_application_log USING GIN (migrations_json);

SELECT register_migration(36, 'jsonb_indexes');
