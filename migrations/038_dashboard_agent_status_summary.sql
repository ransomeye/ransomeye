BEGIN;

-- PRD-03 §2 Migration 038: agent_status_summary_view materialized view (PRD-12 V0.0 §8).

CREATE MATERIALIZED VIEW IF NOT EXISTS agent_status_summary_view AS
SELECT
    tenant_id, status,
    COUNT(*) AS agent_count,
    MIN(last_heartbeat) AS oldest_heartbeat,
    MAX(last_heartbeat) AS newest_heartbeat
FROM agent_sessions
GROUP BY tenant_id, status;

COMMIT;

