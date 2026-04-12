-- Migration 020: governance audit trail.

CREATE TABLE IF NOT EXISTS governance_audit_log (
    audit_id         UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    event_type       TEXT        NOT NULL
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
                                       'BUNDLE_APPLIED'
                                   )),
    actor            TEXT        NOT NULL,
    details_json     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    signature_hex    TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    recorded_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT register_migration(20, 'governance_audit_log');
