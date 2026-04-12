-- Migration 029: immutability, time synchronization, and updated_at triggers.

CREATE OR REPLACE FUNCTION prevent_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION';
END;
$$;

CREATE OR REPLACE FUNCTION set_updated_at_timestamp()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION sync_telemetry_event_time()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.event_time = COALESCE(NEW.event_time, NEW.timestamp, NOW());
    NEW.timestamp = NEW.event_time;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION sync_detection_time()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.detected_at = COALESCE(NEW.detected_at, NEW.timestamp, NOW());
    NEW.timestamp = NEW.detected_at;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION sync_worm_evidence_expiry()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.sealed_at = COALESCE(NEW.sealed_at, NOW());
    NEW.expires_at = CASE NEW.retention_tier
        WHEN 'hot' THEN NEW.sealed_at + INTERVAL '90 days'
        WHEN 'warm' THEN NEW.sealed_at + INTERVAL '730 days'
        WHEN 'cold' THEN NEW.sealed_at + INTERVAL '2555 days'
        ELSE NEW.sealed_at + INTERVAL '2555 days'
    END;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_telemetry_sync_time ON telemetry_events;
CREATE TRIGGER trg_telemetry_sync_time
    BEFORE INSERT OR UPDATE ON telemetry_events
    FOR EACH ROW
    EXECUTE FUNCTION sync_telemetry_event_time();

DROP TRIGGER IF EXISTS trg_detection_sync_time ON detections;
CREATE TRIGGER trg_detection_sync_time
    BEFORE INSERT OR UPDATE ON detections
    FOR EACH ROW
    EXECUTE FUNCTION sync_detection_time();

DROP TRIGGER IF EXISTS trg_worm_evidence_sync_expiry ON worm_evidence;
CREATE TRIGGER trg_worm_evidence_sync_expiry
    BEFORE INSERT OR UPDATE ON worm_evidence
    FOR EACH ROW
    EXECUTE FUNCTION sync_worm_evidence_expiry();

DO $$
DECLARE
    t TEXT;
    tables_with_updated_at TEXT[] := ARRAY[
        'agents',
        'agent_sessions',
        'boot_session_id_history',
        'detections',
        'attack_graphs',
        'expert_analysis_reports',
        'agent_signal_baselines',
        'agent_signal_weights',
        'bayesian_intermediate',
        'compound_incidents',
        'fp_suppression_models',
        'fp_suppression_audit',
        'incidents',
        'actions',
        'cases',
        'corroboration_reports',
        'chat_sessions',
        'incident_events',
        'case_artifacts',
        'case_notes',
        'policy_rules',
        'threat_hunt_rules',
        'policy_versions',
        'soc_users',
        'model_config_audit',
        'ai_conformity_reports',
        'intel_indicators',
        'threat_actor_groups',
        'threat_intel_iocs',
        'registered_probes',
        'endpoint_software_inventory',
        'endpoint_vulnerability_scores',
        'ndr_findings',
        'snmp_device_inventory',
        'replay_runs'
    ];
BEGIN
    FOREACH t IN ARRAY tables_with_updated_at LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', 'trg_set_updated_at_' || t, t);
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION set_updated_at_timestamp()',
            'trg_set_updated_at_' || t,
            t
        );
    END LOOP;
END
$$;

DROP TRIGGER IF EXISTS worm_no_update_telemetry ON telemetry_events;
CREATE TRIGGER worm_no_update_telemetry
    BEFORE UPDATE ON telemetry_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS worm_no_delete_telemetry ON telemetry_events;
CREATE TRIGGER worm_no_delete_telemetry
    BEFORE DELETE ON telemetry_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS worm_no_update_evidence ON worm_evidence;
CREATE TRIGGER worm_no_update_evidence
    BEFORE UPDATE ON worm_evidence
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS worm_no_delete_evidence ON worm_evidence;
CREATE TRIGGER worm_no_delete_evidence
    BEFORE DELETE ON worm_evidence
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_governance_audit_immutable ON governance_audit_log;
CREATE TRIGGER trg_governance_audit_immutable
    BEFORE UPDATE OR DELETE ON governance_audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_incident_notes_immutable ON incident_notes;
CREATE TRIGGER trg_incident_notes_immutable
    BEFORE UPDATE OR DELETE ON incident_notes
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_bundle_log_no_update ON bundle_application_log;
CREATE TRIGGER trg_bundle_log_no_update
    BEFORE UPDATE ON bundle_application_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_bundle_log_no_delete ON bundle_application_log;
CREATE TRIGGER trg_bundle_log_no_delete
    BEFORE DELETE ON bundle_application_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_merkle_roots_immutable ON merkle_roots;
CREATE TRIGGER trg_merkle_roots_immutable
    BEFORE UPDATE OR DELETE ON merkle_roots
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

DROP TRIGGER IF EXISTS trg_merkle_daily_roots_immutable ON merkle_daily_roots;
CREATE TRIGGER trg_merkle_daily_roots_immutable
    BEFORE UPDATE OR DELETE ON merkle_daily_roots
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

SELECT register_migration(29, 'triggers_immutability');
