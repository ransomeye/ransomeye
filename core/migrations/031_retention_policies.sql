-- Migration 031: retention and compression policy helpers.

CREATE OR REPLACE FUNCTION apply_timescaledb_policies(
    p_table_name TEXT,
    p_compress_after INTERVAL,
    p_retain_after INTERVAL,
    p_segmentby TEXT,
    p_orderby TEXT
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    rls_enabled BOOLEAN := FALSE;
BEGIN
    SELECT c.relrowsecurity
      INTO rls_enabled
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = p_table_name;

    IF NOT COALESCE(rls_enabled, FALSE) THEN
        EXECUTE format(
            'ALTER TABLE %I SET (timescaledb.compress, timescaledb.compress_segmentby = %L, timescaledb.compress_orderby = %L)',
            p_table_name,
            p_segmentby,
            p_orderby
        );

        PERFORM add_compression_policy(p_table_name, p_compress_after, if_not_exists => TRUE);
    END IF;

    PERFORM add_retention_policy(p_table_name, p_retain_after, if_not_exists => TRUE);
END;
$$;

SELECT apply_timescaledb_policies(
    'telemetry_events',
    INTERVAL '7 days',
    INTERVAL '365 days',
    'tenant_id,agent_id,event_type,source',
    'event_time DESC'
);

SELECT register_migration(31, 'retention_policies');
