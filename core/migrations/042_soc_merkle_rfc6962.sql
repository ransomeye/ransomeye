-- SOC control-plane: RFC 6962 leaf preimages on worm_evidence + intraday merkle_daily_roots rollup updates.

ALTER TABLE worm_evidence
    ADD COLUMN IF NOT EXISTS soc_merkle_leaf BYTEA;

COMMENT ON COLUMN worm_evidence.soc_merkle_leaf IS 'RFC 6962 leaf preimage (canonical control JSON bytes). Set for CUSTOM evidence under soc_control/.';

DROP TRIGGER IF EXISTS trg_merkle_daily_roots_immutable ON merkle_daily_roots;

DROP TRIGGER IF EXISTS trg_merkle_daily_roots_no_delete ON merkle_daily_roots;
CREATE TRIGGER trg_merkle_daily_roots_no_delete
    BEFORE DELETE ON merkle_daily_roots
    FOR EACH ROW
    EXECUTE FUNCTION prevent_mutation();

CREATE OR REPLACE FUNCTION merkle_daily_roots_guard_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'IMMUTABILITY_VIOLATION';
    END IF;
    IF OLD.daily_date IS DISTINCT FROM NEW.daily_date THEN
        RAISE EXCEPTION 'IMMUTABILITY_VIOLATION';
    END IF;
    IF OLD.daily_root_id IS DISTINCT FROM NEW.daily_root_id THEN
        RAISE EXCEPTION 'IMMUTABILITY_VIOLATION';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_merkle_daily_roots_guard_update ON merkle_daily_roots;
CREATE TRIGGER trg_merkle_daily_roots_guard_update
    BEFORE UPDATE ON merkle_daily_roots
    FOR EACH ROW
    EXECUTE FUNCTION merkle_daily_roots_guard_update();
