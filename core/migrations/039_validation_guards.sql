-- Migration 039: reusable fail-closed validation helpers.

CREATE OR REPLACE FUNCTION assert_schema_version(p_version INTEGER)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = p_version) THEN
        RAISE EXCEPTION 'MISSING_MIGRATION:%', p_version;
    END IF;
END;
$$;

-- Caps the upper bound at the highest migration version already recorded. This keeps
-- historical callers such as migration 040's assert_all_schema_versions(1, 42) valid:
-- during migration 040 execution only versions 1..39 exist, so versions 40..42 are not
-- required yet (linear migrator inserts the current version after the file succeeds).
CREATE OR REPLACE FUNCTION assert_all_schema_versions(p_min INTEGER, p_max INTEGER)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v INTEGER;
    applied_max INTEGER;
BEGIN
    SELECT COALESCE(MAX(version), 0) INTO applied_max FROM schema_migrations;
    FOR v IN p_min..LEAST(p_max, applied_max) LOOP
        PERFORM assert_schema_version(v);
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION assert_table_exists(p_table_name TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF to_regclass(format('public.%s', p_table_name)) IS NULL THEN
        RAISE EXCEPTION 'MISSING_TABLE:%', p_table_name;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION assert_column_exists(p_table_name TEXT, p_column_name TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = p_table_name
          AND column_name = p_column_name
    ) THEN
        RAISE EXCEPTION 'MISSING_COLUMN:%.%', p_table_name, p_column_name;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION assert_trigger_exists(p_table_name TEXT, p_trigger_name TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname = p_table_name
          AND t.tgname = p_trigger_name
          AND NOT t.tgisinternal
    ) THEN
        RAISE EXCEPTION 'MISSING_TRIGGER:%.%', p_table_name, p_trigger_name;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION assert_hypertable_exists(p_table_name TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM timescaledb_information.hypertables
        WHERE hypertable_schema = 'public'
          AND hypertable_name = p_table_name
    ) THEN
        RAISE EXCEPTION 'MISSING_HYPERTABLE:%', p_table_name;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION assert_index_exists(p_index_name TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF to_regclass(format('public.%s', p_index_name)) IS NULL THEN
        RAISE EXCEPTION 'MISSING_INDEX:%', p_index_name;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION assert_setting_equals(p_setting_name TEXT, p_expected_value TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    actual_value TEXT;
BEGIN
    EXECUTE format('SHOW %I', p_setting_name) INTO actual_value;
    IF actual_value IS DISTINCT FROM p_expected_value THEN
        RAISE EXCEPTION 'INVALID_SETTING:% expected=% actual=%', p_setting_name, p_expected_value, actual_value;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION assert_function_exists(p_function_signature TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF to_regprocedure(p_function_signature) IS NULL THEN
        RAISE EXCEPTION 'MISSING_FUNCTION:%', p_function_signature;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION assert_no_forbidden_tables()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_tables
        WHERE schemaname = 'public'
          AND tablename IN ('graph_nodes', 'graph_edges')
    ) THEN
        RAISE EXCEPTION 'FORBIDDEN_TABLE_PRESENT';
    END IF;
END;
$$;

SELECT register_migration(39, 'validation_guards');
