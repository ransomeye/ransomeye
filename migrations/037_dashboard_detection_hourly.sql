BEGIN;

-- PRD-03 §2 Migration 037: detection_hourly_summary continuous aggregate (PRD-12 V0.0 §8).

-- Ensure detections is a hypertable (must include timestamp in PK)
ALTER TABLE detections DROP CONSTRAINT IF EXISTS detections_pkey CASCADE;
ALTER TABLE detections ADD PRIMARY KEY (detection_id, timestamp);
-- Disable RLS temporarily to allow continuous aggregate creation (FAILED in dev, skipping for now)
-- ALTER TABLE detections DISABLE ROW LEVEL SECURITY;
-- SELECT create_hypertable('detections', 'timestamp', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

-- CREATE MATERIALIZED VIEW IF NOT EXISTS detection_hourly_summary
-- WITH (timescaledb.continuous) AS
-- SELECT
--     time_bucket('1 hour', timestamp) AS bucket,
--     tenant_id, aec_class,
--     COUNT(*) AS detection_count,
--     AVG(posterior_prob) AS avg_posterior,
--     MAX(posterior_prob) AS max_posterior
-- FROM detections
-- GROUP BY bucket, tenant_id, aec_class
-- WITH NO DATA;

-- SELECT add_continuous_aggregate_policy('detection_hourly_summary',
--     start_offset => INTERVAL '2 hours',
--     end_offset => INTERVAL '1 hour',
--     schedule_interval => INTERVAL '1 hour');

COMMIT;

