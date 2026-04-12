-- Migration 035: authoritative enum catalogs for typed clients and offline validation.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'agent_type_enum') THEN
        CREATE TYPE agent_type_enum AS ENUM ('linux', 'windows', 'dpi', 'netflow', 'syslog', 'snmp');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'agent_status_enum') THEN
        CREATE TYPE agent_status_enum AS ENUM ('ACTIVE', 'DEGRADED', 'OFFLINE', 'SUSPECTED_COMPROMISE', 'QUARANTINED', 'RETIRED');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'telemetry_source_enum') THEN
        CREATE TYPE telemetry_source_enum AS ENUM ('linux_agent', 'windows_agent', 'dpi_probe', 'offline_sync');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'telemetry_event_type_enum') THEN
        CREATE TYPE telemetry_event_type_enum AS ENUM ('PROCESS_EVENT', 'FILE_EVENT', 'NETWORK_EVENT', 'USER_EVENT', 'DECEPTION_EVENT', 'DPI_FLOW');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'evidence_type_enum') THEN
        CREATE TYPE evidence_type_enum AS ENUM ('FORENSIC_BUNDLE', 'MEMORY_SNAPSHOT', 'FILE_SAMPLE', 'NETWORK_PCAP', 'DISK_IMAGE', 'LOG_EXPORT', 'MERKLE_PROOF_BUNDLE', 'CUSTOM');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'incident_severity_enum') THEN
        CREATE TYPE incident_severity_enum AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'incident_status_enum') THEN
        CREATE TYPE incident_status_enum AS ENUM ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_type_enum') THEN
        CREATE TYPE action_type_enum AS ENUM ('KILL_PROCESS', 'BLOCK_IP', 'ISOLATE_HOST', 'FILE_ROLLBACK', 'SNAPSHOT_MEMORY', 'ALERT_ONLY');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_status_enum') THEN
        CREATE TYPE action_status_enum AS ENUM ('PENDING', 'PENDING_CONFIRMATION', 'PENDING_APPROVAL', 'DISPATCHED', 'COMPLETED', 'FAILED', 'CANCELLED');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'indicator_type_enum') THEN
        CREATE TYPE indicator_type_enum AS ENUM ('IP_ADDRESS', 'DOMAIN', 'JA3_HASH', 'FILE_HASH', 'URL', 'EMAIL');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'bundle_type_enum') THEN
        CREATE TYPE bundle_type_enum AS ENUM ('FULL', 'BINARY', 'MODEL_CONFIG', 'MODEL_WEIGHTS', 'INTEL_FEED', 'CERT_ROTATION', 'UI_ASSETS', 'KEY_ROTATION');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'bundle_outcome_enum') THEN
        CREATE TYPE bundle_outcome_enum AS ENUM ('SUCCESS', 'ROLLBACK', 'MANUAL_ROLLBACK');
    END IF;
END
$$;

SELECT register_migration(35, 'enum_types');
