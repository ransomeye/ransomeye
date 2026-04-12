BEGIN;

-- PRD-03 §2 Migration 039: threat_geo_hourly continuous aggregate (PRD-12 V0.0 §8).

-- CREATE MATERIALIZED VIEW IF NOT EXISTS threat_geo_hourly
-- WITH (timescaledb.continuous) AS
-- SELECT
--     time_bucket('1 hour', d.timestamp) AS bucket,
--     d.tenant_id,
--     (d.bayesian_intermediate->>'geo_country')::TEXT AS country,
--     COUNT(*) AS detection_count,
--     AVG(d.posterior_prob) AS avg_posterior
-- FROM detections d
-- WHERE d.aec_class >= 1
-- GROUP BY bucket, d.tenant_id, country
-- WITH NO DATA;

-- SELECT add_continuous_aggregate_policy('threat_geo_hourly',
--     start_offset => INTERVAL '2 hours',
--     end_offset => INTERVAL '1 hour',
--     schedule_interval => INTERVAL '1 hour');

COMMIT;

