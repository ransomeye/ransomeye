BEGIN;

-- PRD-03 §2 Migration: Convert base tables to hypertables.
SELECT create_hypertable('agent_heartbeats', 'timestamp', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);
SELECT create_hypertable('telemetry_events', 'timestamp', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);
SELECT create_hypertable('dpi_flows', 'timestamp', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

COMMIT;

