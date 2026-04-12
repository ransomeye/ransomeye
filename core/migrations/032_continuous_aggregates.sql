-- Migration 032: continuous and materialized aggregates.

DO $$
DECLARE
    rls_enabled BOOLEAN := FALSE;
BEGIN
    SELECT c.relrowsecurity
      INTO rls_enabled
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = 'telemetry_events';

    IF COALESCE(rls_enabled, FALSE) THEN
        EXECUTE $mv$
            CREATE MATERIALIZED VIEW IF NOT EXISTS telemetry_event_hourly_summary AS
            SELECT
                date_trunc('hour', event_time) AS bucket,
                tenant_id,
                event_type,
                source,
                COUNT(*) AS event_count,
                SUM(dropped_packets_before) AS dropped_packet_total
            FROM telemetry_events
            GROUP BY bucket, tenant_id, event_type, source
            WITH NO DATA
        $mv$;
    ELSE
        EXECUTE $mv$
            CREATE MATERIALIZED VIEW IF NOT EXISTS telemetry_event_hourly_summary
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('1 hour', event_time) AS bucket,
                tenant_id,
                event_type,
                source,
                COUNT(*) AS event_count,
                SUM(dropped_packets_before) AS dropped_packet_total
            FROM telemetry_events
            GROUP BY bucket, tenant_id, event_type, source
            WITH NO DATA
        $mv$;

        PERFORM add_continuous_aggregate_policy(
            'telemetry_event_hourly_summary',
            start_offset => INTERVAL '2 hours',
            end_offset => INTERVAL '1 hour',
            schedule_interval => INTERVAL '1 hour',
            if_not_exists => TRUE
        );
    END IF;
END
$$;

CREATE MATERIALIZED VIEW IF NOT EXISTS detection_hourly_summary AS
SELECT
    date_trunc('hour', detected_at) AS bucket,
    tenant_id,
    aec_class,
    COUNT(*) AS detection_count,
    AVG(posterior_prob) AS avg_posterior,
    MAX(posterior_prob) AS max_posterior
FROM detections
GROUP BY bucket, tenant_id, aec_class
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS agent_status_summary_view AS
SELECT
    tenant_id,
    status,
    COUNT(*) AS agent_count,
    MIN(last_heartbeat) AS oldest_heartbeat,
    MAX(last_heartbeat) AS newest_heartbeat
FROM agent_sessions
GROUP BY tenant_id, status
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS threat_geo_hourly AS
SELECT
    date_trunc('hour', detected_at) AS bucket,
    tenant_id,
    COALESCE(bayesian_intermediate ->> 'geo_country', 'UNKNOWN') AS country,
    COUNT(*) AS detection_count,
    AVG(posterior_prob) AS avg_posterior
FROM detections
GROUP BY bucket, tenant_id, country
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS signal_distribution_hourly AS
SELECT
    date_trunc('hour', detected_at) AS bucket,
    tenant_id,
    AVG(COALESCE((signals ->> 'process')::numeric, 0)) AS avg_signal_process,
    AVG(COALESCE((signals ->> 'file')::numeric, 0)) AS avg_signal_file,
    AVG(COALESCE((signals ->> 'network')::numeric, 0)) AS avg_signal_network,
    AVG(COALESCE((signals ->> 'user')::numeric, 0)) AS avg_signal_user,
    COUNT(*) AS sample_count
FROM detections
GROUP BY bucket, tenant_id
WITH NO DATA;

SELECT register_migration(32, 'continuous_aggregates');
