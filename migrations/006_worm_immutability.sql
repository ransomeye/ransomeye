BEGIN;

-- PRD-03 §5 / PRD-10 §3 — WORM immutability enforcement (forensic grade).
-- Prevents UPDATE and DELETE on forensic-grade tables.
-- Trigger names MUST match core boot validation in ransomeye-core/main.go.
--
-- SECURITY HARDENING:
--   SECURITY DEFINER — executes as function owner (postgres), not calling role.
--   SET search_path = pg_catalog — prevents search_path hijacking attacks.

-- ============================================================================
-- TRIGGER FUNCTIONS (forensic-grade: SECURITY DEFINER + pinned search_path)
-- ============================================================================

CREATE OR REPLACE FUNCTION worm_reject_telemetry_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'WORM: telemetry_events rows are immutable';
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION worm_reject_telemetry_delete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'WORM: telemetry_events rows cannot be deleted';
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION worm_reject_evidence_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'WORM: worm_evidence rows are immutable';
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION worm_reject_evidence_delete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'WORM: worm_evidence rows cannot be deleted';
    RETURN NULL;
END;
$$;

-- ============================================================================
-- TRIGGERS ON telemetry_events
-- Names: worm_no_update_telemetry, worm_no_delete_telemetry
-- ============================================================================

DROP TRIGGER IF EXISTS worm_no_update_telemetry ON telemetry_events;
CREATE TRIGGER worm_no_update_telemetry
    BEFORE UPDATE ON telemetry_events
    FOR EACH ROW
    EXECUTE FUNCTION worm_reject_telemetry_update();

DROP TRIGGER IF EXISTS worm_no_delete_telemetry ON telemetry_events;
CREATE TRIGGER worm_no_delete_telemetry
    BEFORE DELETE ON telemetry_events
    FOR EACH ROW
    EXECUTE FUNCTION worm_reject_telemetry_delete();

-- ============================================================================
-- TRIGGERS ON worm_evidence
-- Names: worm_no_update_evidence, worm_no_delete_evidence
-- ============================================================================

DROP TRIGGER IF EXISTS worm_no_update_evidence ON worm_evidence;
CREATE TRIGGER worm_no_update_evidence
    BEFORE UPDATE ON worm_evidence
    FOR EACH ROW
    EXECUTE FUNCTION worm_reject_evidence_update();

DROP TRIGGER IF EXISTS worm_no_delete_evidence ON worm_evidence;
CREATE TRIGGER worm_no_delete_evidence
    BEFORE DELETE ON worm_evidence
    FOR EACH ROW
    EXECUTE FUNCTION worm_reject_evidence_delete();

COMMIT;
