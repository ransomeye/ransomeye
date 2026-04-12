-- SQL validation script (ingest/bootstrap assumptions).
-- Assumes migrations 001-040 have already been applied.

CREATE TEMP TABLE validation_ctx (
    tenant_id         UUID,
    agent_id          UUID,
    event_id          UUID,
    detection_id      UUID,
    evidence_id       UUID,
    incident_id       UUID,
    note_id           UUID,
    audit_id          UUID,
    bundle_log_id     UUID
) ON COMMIT DROP;

DO $$
DECLARE
    v_tenant_id     UUID := gen_random_uuid();
    v_agent_id      UUID := gen_random_uuid();
    v_event_id      UUID := gen_random_uuid();
    v_detection_id  UUID := gen_random_uuid();
    v_evidence_id   UUID := gen_random_uuid();
    v_incident_id   UUID := gen_random_uuid();
    v_note_id       UUID := gen_random_uuid();
    v_audit_id      UUID := gen_random_uuid();
    v_bundle_log_id UUID := gen_random_uuid();
    v_sequence      BIGINT;
BEGIN
    INSERT INTO tenants (
        tenant_id,
        tenant_name,
        tenant_slug,
        dek_wrapped,
        status,
        created_at,
        updated_at
    )
    VALUES (
        v_tenant_id,
        'validation-' || left(v_tenant_id::text, 8),
        'validation-' || replace(left(v_tenant_id::text, 8), '-', ''),
        decode(repeat('11', 60), 'hex'),
        'ACTIVE',
        NOW(),
        NOW()
    );

    PERFORM set_config('app.tenant_id', v_tenant_id::text, FALSE);

    INSERT INTO agent_sessions (
        agent_id,
        tenant_id,
        boot_session_id,
        hostname,
        primary_ip,
        agent_type,
        agent_version,
        last_heartbeat,
        status,
        lamport_clock,
        last_seen_ip,
        created_at,
        updated_at
    )
    VALUES (
        v_agent_id,
        v_tenant_id,
        gen_random_uuid(),
        'validation-host',
        '192.0.2.10'::inet,
        'linux',
        'V0.0',
        NOW(),
        'ACTIVE',
        1,
        '192.0.2.10'::inet,
        NOW(),
        NOW()
    );

    INSERT INTO boot_session_id_history (
        boot_history_id,
        agent_id,
        tenant_id,
        boot_session_id,
        first_seen_ip,
        first_seen_at,
        last_seen_at,
        created_at,
        updated_at
    )
    VALUES (
        gen_random_uuid(),
        v_agent_id,
        v_tenant_id,
        gen_random_uuid(),
        '192.0.2.10'::inet,
        NOW(),
        NOW(),
        NOW(),
        NOW()
    );

    INSERT INTO incidents (
        incident_id,
        tenant_id,
        title,
        description,
        severity,
        status,
        assigned_to,
        created_by,
        first_seen_at,
        last_updated_at,
        resolved_at,
        created_at,
        updated_at
    )
    VALUES (
        v_incident_id,
        v_tenant_id,
        'validation incident',
        'validation incident description',
        'HIGH',
        'OPEN',
        'analyst',
        'validator',
        NOW(),
        NOW(),
        '1970-01-01 00:00:00+00',
        NOW(),
        NOW()
    );

    INSERT INTO telemetry_events (
        event_id,
        tenant_id,
        agent_id,
        event_type,
        event_time,
        timestamp,
        logical_clock,
        payload_json,
        payload_bytes,
        agent_ed25519_sig,
        source,
        dropped_packets_before,
        ingest_status,
        created_at
    )
    VALUES (
        v_event_id,
        v_tenant_id,
        v_agent_id,
        'PROCESS_EVENT',
        NOW(),
        NOW(),
        42,
        '{"process":"cmd.exe","path":"C:\\\\Windows\\\\System32\\\\cmd.exe"}'::jsonb,
        decode('deadbeef', 'hex'),
        decode(repeat('ab', 64), 'hex'),
        'linux_agent',
        0,
        'ACCEPTED',
        NOW()
    );

    INSERT INTO detections (
        detection_id,
        tenant_id,
        agent_id,
        event_id,
        detected_at,
        timestamp,
        posterior_prob,
        aec_class,
        threat_type,
        signals,
        loo_importance,
        bayesian_intermediate,
        prior_used,
        lambda_used,
        model_hash,
        drift_alert,
        logical_clock,
        analyst_disposition,
        analyst_notes,
        analyst_id,
        reviewed_at,
        incident_id,
        created_at,
        updated_at
    )
    VALUES (
        v_detection_id,
        v_tenant_id,
        v_agent_id,
        v_event_id,
        NOW(),
        NOW(),
        0.99100000,
        3,
        'ransomware',
        '{"process":0.95,"file":0.91,"network":0.72,"user":0.10}'::jsonb,
        '{"top_feature":"process","top_delta":0.88}'::jsonb,
        '{"frozen_prior":0.0000100000,"geo_country":"IN"}'::jsonb,
        0.0000100000,
        0.850,
        repeat('a', 64),
        FALSE,
        42,
        'UNREVIEWED',
        '',
        '',
        '1970-01-01 00:00:00+00',
        v_incident_id,
        NOW(),
        NOW()
    );

    INSERT INTO worm_evidence (
        evidence_id,
        tenant_id,
        detection_id,
        event_id,
        evidence_type,
        file_path,
        canonical_json_hash,
        worm_file_hash,
        ed25519_sig,
        retention_tier,
        file_size_bytes,
        dropped_packets_before,
        sealed_at,
        expires_at,
        created_at
    )
    VALUES (
        v_evidence_id,
        v_tenant_id,
        v_detection_id,
        v_event_id,
        'FORENSIC_BUNDLE',
        '/var/lib/ransomeye/worm/validation.bundle',
        repeat('b', 64),
        repeat('c', 64),
        'validation-signature',
        'hot',
        4096,
        0,
        NOW(),
        NOW() + INTERVAL '90 days',
        NOW()
    );

    INSERT INTO governance_audit_log (
        audit_id,
        tenant_id,
        event_type,
        actor,
        details_json,
        signature_hex,
        created_at,
        recorded_at
    )
    VALUES (
        v_audit_id,
        v_tenant_id,
        'ACTION_APPROVED',
        'validator',
        '{"source":"validation_ingest_bootstrap.sql"}'::jsonb,
        '',
        NOW(),
        NOW()
    );

    INSERT INTO incident_notes (
        note_id,
        incident_id,
        tenant_id,
        author,
        note_text,
        created_at
    )
    VALUES (
        v_note_id,
        v_incident_id,
        v_tenant_id,
        'validator',
        'initial validation note',
        NOW()
    );

    SELECT COALESCE(MAX(sequence_number), 0) + 1
      INTO v_sequence
      FROM bundle_application_log;

    INSERT INTO bundle_application_log (
        log_id,
        tenant_id,
        bundle_id,
        bundle_type,
        sequence_number,
        applied_at,
        applied_by,
        artifacts_json,
        migrations_json,
        outcome,
        failure_reason,
        bundle_sha256,
        created_at
    )
    VALUES (
        v_bundle_log_id,
        v_tenant_id,
        gen_random_uuid(),
        'FULL',
        v_sequence,
        NOW(),
        'validator',
        '{"bundle":"validation"}'::jsonb,
        '[1,2,3,4,5]'::jsonb,
        'SUCCESS',
        '',
        'sha256:' || repeat('d', 64),
        NOW()
    );

    INSERT INTO validation_ctx (
        tenant_id,
        agent_id,
        event_id,
        detection_id,
        evidence_id,
        incident_id,
        note_id,
        audit_id,
        bundle_log_id
    )
    VALUES (
        v_tenant_id,
        v_agent_id,
        v_event_id,
        v_detection_id,
        v_evidence_id,
        v_incident_id,
        v_note_id,
        v_audit_id,
        v_bundle_log_id
    );
END
$$;

DO $$
DECLARE
    ctx validation_ctx%ROWTYPE;
BEGIN
    SELECT * INTO ctx FROM validation_ctx LIMIT 1;

    BEGIN
        UPDATE worm_evidence SET file_path = '/tmp/tampered' WHERE evidence_id = ctx.evidence_id;
        RAISE EXCEPTION 'UPDATE_WORM_EVIDENCE_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%IMMUTABILITY_VIOLATION%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        DELETE FROM worm_evidence WHERE evidence_id = ctx.evidence_id;
        RAISE EXCEPTION 'DELETE_WORM_EVIDENCE_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%IMMUTABILITY_VIOLATION%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        UPDATE governance_audit_log SET actor = 'tampered' WHERE audit_id = ctx.audit_id;
        RAISE EXCEPTION 'UPDATE_GOVERNANCE_AUDIT_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%IMMUTABILITY_VIOLATION%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        DELETE FROM governance_audit_log WHERE audit_id = ctx.audit_id;
        RAISE EXCEPTION 'DELETE_GOVERNANCE_AUDIT_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%IMMUTABILITY_VIOLATION%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        UPDATE incident_notes SET note_text = 'tampered' WHERE note_id = ctx.note_id;
        RAISE EXCEPTION 'UPDATE_INCIDENT_NOTES_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%IMMUTABILITY_VIOLATION%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        DELETE FROM incident_notes WHERE note_id = ctx.note_id;
        RAISE EXCEPTION 'DELETE_INCIDENT_NOTES_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%IMMUTABILITY_VIOLATION%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        UPDATE bundle_application_log SET applied_by = 'tampered' WHERE log_id = ctx.bundle_log_id;
        RAISE EXCEPTION 'UPDATE_BUNDLE_LOG_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%IMMUTABILITY_VIOLATION%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        DELETE FROM bundle_application_log WHERE log_id = ctx.bundle_log_id;
        RAISE EXCEPTION 'DELETE_BUNDLE_LOG_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%IMMUTABILITY_VIOLATION%' THEN
                RAISE;
            END IF;
    END;
END
$$;

DO $$
DECLARE
    ctx validation_ctx%ROWTYPE;
    rec RECORD;
    previous_root TEXT := '';
    root_count INTEGER := 0;
BEGIN
    SELECT * INTO ctx FROM validation_ctx LIMIT 1;

    FOR rec IN
        SELECT leaf_sequence, prev_root_hash, root_hash
        FROM merkle_roots
        WHERE tenant_id = ctx.tenant_id
        ORDER BY leaf_sequence
    LOOP
        root_count := root_count + 1;
        IF root_count = 1 THEN
            IF rec.prev_root_hash <> '' THEN
                RAISE EXCEPTION 'MERKLE_CHAIN_INVALID: first prev_root_hash must be empty';
            END IF;
        ELSE
            IF rec.prev_root_hash <> previous_root THEN
                RAISE EXCEPTION 'MERKLE_CHAIN_INVALID: expected prev_root_hash %, got %', previous_root, rec.prev_root_hash;
            END IF;
        END IF;
        previous_root := rec.root_hash;
    END LOOP;

    IF root_count < 5 THEN
        RAISE EXCEPTION 'MERKLE_CHAIN_INVALID: expected at least 5 linked roots, got %', root_count;
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'detections'
          AND column_name = 'loo_importance'
    ) THEN
        RAISE EXCEPTION 'LOO_FIELD_MISSING:detections.loo_importance';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'loo_importance'
          AND column_name IN ('detection_id', 'feature_name', 'importance_score')
        GROUP BY table_name
        HAVING COUNT(*) = 3
    ) THEN
        RAISE EXCEPTION 'LOO_TABLE_FIELDS_MISSING';
    END IF;
END
$$;
