-- Migration 040: final fail-closed sanity checks.
-- Version 040 is recorded by the external migration engine after this file succeeds.

SELECT assert_all_schema_versions(1, 42);
SELECT assert_no_forbidden_tables();
SELECT assert_setting_equals('ssl', 'on');
SELECT assert_setting_equals('ssl_min_protocol_version', 'TLSv1.3');
SELECT assert_setting_equals('listen_addresses', '127.0.0.1');
SELECT assert_function_exists('prevent_mutation()');
SELECT assert_function_exists('append_merkle_chain()');

DO $$
DECLARE
    t TEXT;
    required_tables TEXT[] := ARRAY[
        'schema_migrations',
        'tenants',
        'agents',
        'agent_sessions',
        'boot_session_id_history',
        'telemetry_events',
        'telemetry_enriched',
        'telemetry_dropped',
        'detections',
        'detection_features',
        'bayesian_intermediate',
        'loo_importance',
        'worm_evidence',
        'merkle_tree',
        'merkle_roots',
        'merkle_daily_roots',
        'exposure_worm_ledger',
        'incidents',
        'incident_events',
        'incident_notes',
        'policy_rules',
        'policy_versions',
        'governance_audit_log',
        'intel_indicators',
        'intel_matches',
        'agent_heartbeats',
        'system_metrics',
        'ingestion_stats',
        'bundle_application_log'
    ];
BEGIN
    FOREACH t IN ARRAY required_tables LOOP
        PERFORM assert_table_exists(t);
    END LOOP;
END
$$;

DO $$
DECLARE
    h TEXT;
    required_hypertables TEXT[] := ARRAY[
        'telemetry_events',
        'telemetry_enriched',
        'telemetry_dropped',
        'agent_heartbeats',
        'system_metrics',
        'ingestion_stats',
        'compound_incidents',
        'intel_matches',
        'dpi_flows',
        'ndr_findings',
        'network_infra_findings'
    ];
BEGIN
    FOREACH h IN ARRAY required_hypertables LOOP
        PERFORM assert_hypertable_exists(h);
    END LOOP;
END
$$;

DO $$
BEGIN
    PERFORM assert_trigger_exists('telemetry_events', 'worm_no_update_telemetry');
    PERFORM assert_trigger_exists('telemetry_events', 'worm_no_delete_telemetry');
    PERFORM assert_trigger_exists('worm_evidence', 'worm_no_update_evidence');
    PERFORM assert_trigger_exists('worm_evidence', 'worm_no_delete_evidence');
    PERFORM assert_trigger_exists('governance_audit_log', 'trg_governance_audit_immutable');
    PERFORM assert_trigger_exists('incident_notes', 'trg_incident_notes_immutable');
    PERFORM assert_trigger_exists('bundle_application_log', 'trg_bundle_log_no_update');
    PERFORM assert_trigger_exists('bundle_application_log', 'trg_bundle_log_no_delete');
    PERFORM assert_trigger_exists('telemetry_events', 'trg_merkle_telemetry_events_insert');
    PERFORM assert_trigger_exists('worm_evidence', 'trg_merkle_worm_evidence_insert');
END
$$;

DO $$
DECLARE
    i TEXT;
    required_indexes TEXT[] := ARRAY[
        'idx_telemetry_tenant_event_time',
        'idx_detections_tenant_detected_at',
        'idx_worm_evidence_tenant_sealed_at',
        'idx_policy_rules_tenant_active',
        'idx_governance_audit_tenant_created_at',
        'idx_intel_indicators_tenant_active',
        'idx_agent_heartbeats_tenant_time',
        'idx_ingestion_stats_source_time',
        'idx_bundle_application_log_sequence',
        'idx_telemetry_payload_json_gin',
        'idx_detections_bayesian_intermediate_gin',
        'idx_governance_audit_details_gin',
        'idx_telemetry_payload_sha256_hash',
        'idx_worm_evidence_file_hash',
        'idx_bundle_application_sha256_hash'
    ];
BEGIN
    FOREACH i IN ARRAY required_indexes LOOP
        PERFORM assert_index_exists(i);
    END LOOP;
END
$$;

SELECT assert_column_exists('detections', 'loo_importance');
SELECT assert_column_exists('loo_importance', 'importance_score');
