-- Migration 030: transactional Merkle append logic.

CREATE OR REPLACE FUNCTION append_merkle_chain()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    row_json         JSONB;
    tenant_value     TEXT;
    source_pk_value  TEXT;
    tenant_uuid      UUID;
    source_pk_uuid   UUID;
    payload_hash     TEXT;
    prev_root_hash   TEXT := '';
    prev_sequence    BIGINT := 0;
    next_sequence    BIGINT;
    root_hash        TEXT;
    event_ts         TIMESTAMPTZ;
BEGIN
    row_json := to_jsonb(NEW);

    tenant_value := NULLIF(row_json ->> 'tenant_id', '');
    tenant_uuid := COALESCE(tenant_value::uuid, '00000000-0000-0000-0000-000000000000'::uuid);

    source_pk_value := NULLIF(row_json ->> TG_ARGV[0], '');
    IF source_pk_value IS NULL THEN
        RAISE EXCEPTION 'MERKLE_SOURCE_PK_MISSING';
    END IF;
    source_pk_uuid := source_pk_value::uuid;

    payload_hash := encode(digest(convert_to(row_json::text, 'UTF8'), 'sha256'), 'hex');

    SELECT mr.root_hash, mr.leaf_sequence
      INTO prev_root_hash, prev_sequence
      FROM merkle_roots mr
     WHERE mr.tenant_id = tenant_uuid
     ORDER BY mr.leaf_sequence DESC
     LIMIT 1;

    prev_root_hash := COALESCE(prev_root_hash, '');
    prev_sequence := COALESCE(prev_sequence, 0);
    next_sequence := prev_sequence + 1;

    IF prev_root_hash = '' THEN
        root_hash := payload_hash;
    ELSE
        root_hash := encode(
            digest(decode(prev_root_hash, 'hex') || decode(payload_hash, 'hex'), 'sha256'),
            'hex'
        );
    END IF;

    event_ts := COALESCE(
        NULLIF(row_json ->> 'created_at', '')::timestamptz,
        NULLIF(row_json ->> 'sealed_at', '')::timestamptz,
        NULLIF(row_json ->> 'event_time', '')::timestamptz,
        NULLIF(row_json ->> 'detected_at', '')::timestamptz,
        NOW()
    );

    INSERT INTO merkle_tree (
        merkle_entry_id,
        tenant_id,
        source_table,
        source_pk,
        payload_hash,
        prev_root_hash,
        root_hash,
        leaf_sequence,
        chain_depth,
        created_at
    )
    VALUES (
        gen_random_uuid(),
        tenant_uuid,
        TG_TABLE_NAME,
        source_pk_uuid,
        payload_hash,
        prev_root_hash,
        root_hash,
        next_sequence,
        next_sequence,
        event_ts
    );

    INSERT INTO merkle_roots (
        root_id,
        tenant_id,
        source_table,
        source_pk,
        payload_hash,
        prev_root_hash,
        root_hash,
        leaf_sequence,
        computed_at,
        created_at,
        ed25519_sig
    )
    VALUES (
        gen_random_uuid(),
        tenant_uuid,
        TG_TABLE_NAME,
        source_pk_uuid,
        payload_hash,
        prev_root_hash,
        root_hash,
        next_sequence,
        event_ts,
        event_ts,
        ''
    );

    IF TG_TABLE_NAME = 'worm_evidence' THEN
        INSERT INTO exposure_worm_ledger (
            ledger_id,
            tenant_id,
            evidence_id,
            leaf_hash,
            merkle_position,
            daily_date,
            created_at
        )
        VALUES (
            gen_random_uuid(),
            tenant_uuid,
            source_pk_uuid,
            payload_hash,
            next_sequence,
            (event_ts AT TIME ZONE 'UTC')::date,
            event_ts
        )
        ON CONFLICT (evidence_id) DO NOTHING;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_merkle_telemetry_events_insert ON telemetry_events;
CREATE TRIGGER trg_merkle_telemetry_events_insert
    AFTER INSERT ON telemetry_events
    FOR EACH ROW
    EXECUTE FUNCTION append_merkle_chain('event_id');

DROP TRIGGER IF EXISTS trg_merkle_worm_evidence_insert ON worm_evidence;
CREATE TRIGGER trg_merkle_worm_evidence_insert
    AFTER INSERT ON worm_evidence
    FOR EACH ROW
    EXECUTE FUNCTION append_merkle_chain('evidence_id');

DROP TRIGGER IF EXISTS trg_merkle_governance_audit_insert ON governance_audit_log;
CREATE TRIGGER trg_merkle_governance_audit_insert
    AFTER INSERT ON governance_audit_log
    FOR EACH ROW
    EXECUTE FUNCTION append_merkle_chain('audit_id');

DROP TRIGGER IF EXISTS trg_merkle_incident_notes_insert ON incident_notes;
CREATE TRIGGER trg_merkle_incident_notes_insert
    AFTER INSERT ON incident_notes
    FOR EACH ROW
    EXECUTE FUNCTION append_merkle_chain('note_id');

DROP TRIGGER IF EXISTS trg_merkle_bundle_application_insert ON bundle_application_log;
CREATE TRIGGER trg_merkle_bundle_application_insert
    AFTER INSERT ON bundle_application_log
    FOR EACH ROW
    EXECUTE FUNCTION append_merkle_chain('log_id');

SELECT register_migration(30, 'merkle_logic');
