-- Migration 043: governance audit event for telemetry ingest.

ALTER TABLE governance_audit_log
    DROP CONSTRAINT IF EXISTS governance_audit_log_event_type_check;

ALTER TABLE governance_audit_log
    ADD CONSTRAINT governance_audit_log_event_type_check
    CHECK (event_type IN (
        'POLICY_CREATED',
        'POLICY_UPDATED',
        'POLICY_VERSIONED',
        'POLICY_APPROVED',
        'POLICY_REJECTED',
        'ACTION_APPROVED',
        'ACTION_REJECTED',
        'ENFORCEMENT_DISPATCHED',
        'ROLE_GRANTED',
        'ROLE_REVOKED',
        'CONFIG_CHANGED',
        'MODEL_LOADED',
        'MODEL_REJECTED',
        'INCIDENT_NOTE_ADDED',
        'BUNDLE_APPLIED',
        'TELEMETRY_INGEST'
    ));

SELECT register_migration(43, 'governance_telemetry_ingest');
