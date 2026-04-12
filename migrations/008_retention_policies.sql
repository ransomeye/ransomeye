BEGIN;

-- PRD-03 §6 retention policies (TimescaleDB).
SELECT add_retention_policy('agent_heartbeats', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('telemetry_events', INTERVAL '365 days', if_not_exists => TRUE);
SELECT add_retention_policy('dpi_flows', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('agent_metrics_minute_bucket', INTERVAL '365 days', if_not_exists => TRUE);

COMMIT;

