BEGIN;

-- PRD-03 §4.1 / §4.2: Merkle daily roots are immutable (RAISE EXCEPTION on UPDATE/DELETE).
CREATE OR REPLACE FUNCTION enforce_merkle_root_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: table [%] is INSERT-only. UPDATE and DELETE prohibited.', TG_TABLE_NAME
        USING ERRCODE = '23000';
END;
$$;

DROP TRIGGER IF EXISTS trg_merkle_root_no_update ON merkle_daily_roots;
CREATE TRIGGER trg_merkle_root_no_update
    BEFORE UPDATE ON merkle_daily_roots
    FOR EACH ROW EXECUTE FUNCTION enforce_merkle_root_immutability();

DROP TRIGGER IF EXISTS trg_merkle_root_no_delete ON merkle_daily_roots;
CREATE TRIGGER trg_merkle_root_no_delete
    BEFORE DELETE ON merkle_daily_roots
    FOR EACH ROW EXECUTE FUNCTION enforce_merkle_root_immutability();

COMMIT;

