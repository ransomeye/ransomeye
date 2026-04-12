BEGIN;

-- PRD-03 §3.5 agent_metrics_minute_bucket (continuous aggregate)
CREATE MATERIALIZED VIEW agent_metrics_minute_bucket
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 minute', timestamp) AS bucket,
    agent_id, tenant_id,
    AVG(cpu_usage_pct) AS avg_cpu_pct, MAX(cpu_usage_pct) AS max_cpu_pct,
    AVG(ram_used_mb) AS avg_ram_mb, MAX(ram_used_mb) AS max_ram_mb,
    ROUND(AVG(ram_used_mb)::NUMERIC / NULLIF(AVG(ram_total_mb), 0) * 100, 2) AS avg_ram_pct,
    COUNT(*) AS sample_count
FROM agent_heartbeats
GROUP BY bucket, agent_id, tenant_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('agent_metrics_minute_bucket',
    start_offset => INTERVAL '10 minutes',
    end_offset => INTERVAL '1 minute',
    schedule_interval => INTERVAL '1 minute');

COMMIT;

