-- Migration 028: tenant isolation via row-level security.

DO $$
DECLARE
    t TEXT;
    tenant_tables TEXT[] := ARRAY[
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
        'actions',
        'cases',
        'corroboration_reports',
        'chat_sessions',
        'incident_events',
        'case_artifacts',
        'simulation_runs',
        'replay_runs',
        'incident_notes',
        'case_notes',
        'policy_rules',
        'threat_hunt_rules',
        'policy_versions',
        'soc_users',
        'soc_sessions',
        'compliance_reports',
        'model_config_audit',
        'ai_conformity_reports',
        'governance_audit_log',
        'intel_indicators',
        'threat_actor_groups',
        'threat_intel_iocs',
        'intel_matches',
        'agent_heartbeats',
        'system_metrics',
        'registered_probes',
        'endpoint_software_inventory',
        'endpoint_vulnerability_scores',
        'ingestion_stats',
        'dpi_flows',
        'ndr_findings',
        'network_infra_findings',
        'snmp_device_inventory',
        'bundle_application_log'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', 'pol_tenant_' || t, t);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (tenant_id = current_tenant_uuid()) WITH CHECK (tenant_id = current_tenant_uuid())',
            'pol_tenant_' || t,
            t
        );
    END LOOP;
END
$$;

SELECT register_migration(28, 'rls');
