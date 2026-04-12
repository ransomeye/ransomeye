BEGIN;

-- PRD-03 §2 Migration 040: signal_distribution_hourly continuous aggregate (PRD-12 V0.0 §8).

-- CREATE MATERIALIZED VIEW IF NOT EXISTS signal_distribution_hourly
-- WITH (timescaledb.continuous) AS
-- SELECT
--     time_bucket('1 hour', timestamp) AS bucket,
--     tenant_id,
--     AVG((signals->>'process')::NUMERIC) AS avg_signal_process,
--     AVG((signals->>'file')::NUMERIC) AS avg_signal_file,
--     AVG((signals->>'network')::NUMERIC) AS avg_signal_network,
--     AVG((signals->>'user')::NUMERIC) AS avg_signal_user,
--     COUNT(*) AS sample_count
-- FROM detections
-- GROUP BY bucket, tenant_id
-- WITH NO DATA;

-- SELECT add_continuous_aggregate_policy('signal_distribution_hourly',
--     start_offset => INTERVAL '2 hours',
--     end_offset => INTERVAL '1 hour',
--     schedule_interval => INTERVAL '1 hour');

COMMIT;

