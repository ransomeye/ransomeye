-- Migration 033: TimescaleDB partitioning for additional time-series tables.

SELECT create_hypertable(
    'telemetry_enriched',
    'event_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'telemetry_dropped',
    'event_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'agent_heartbeats',
    'heartbeat_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'system_metrics',
    'metric_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'ingestion_stats',
    'stat_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'compound_incidents',
    'time_window_end',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'intel_matches',
    'event_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'dpi_flows',
    'flow_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'ndr_findings',
    'finding_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT create_hypertable(
    'network_infra_findings',
    'finding_time',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

SELECT apply_timescaledb_policies(
    'telemetry_enriched',
    INTERVAL '7 days',
    INTERVAL '365 days',
    'tenant_id,enrichment_stage,enrichment_source',
    'event_time DESC'
);

SELECT apply_timescaledb_policies(
    'telemetry_dropped',
    INTERVAL '7 days',
    INTERVAL '90 days',
    'tenant_id,agent_id,source,drop_reason',
    'event_time DESC'
);

SELECT apply_timescaledb_policies(
    'agent_heartbeats',
    INTERVAL '7 days',
    INTERVAL '90 days',
    'tenant_id,agent_id',
    'heartbeat_time DESC'
);

SELECT apply_timescaledb_policies(
    'system_metrics',
    INTERVAL '7 days',
    INTERVAL '180 days',
    'tenant_id,component,metric_name',
    'metric_time DESC'
);

SELECT apply_timescaledb_policies(
    'ingestion_stats',
    INTERVAL '7 days',
    INTERVAL '365 days',
    'tenant_id,source',
    'stat_time DESC'
);

SELECT apply_timescaledb_policies(
    'compound_incidents',
    INTERVAL '7 days',
    INTERVAL '365 days',
    'tenant_id,ioc_group_key,ioc_group_value',
    'time_window_end DESC'
);

SELECT apply_timescaledb_policies(
    'intel_matches',
    INTERVAL '7 days',
    INTERVAL '365 days',
    'tenant_id,match_source,match_type',
    'event_time DESC'
);

SELECT apply_timescaledb_policies(
    'dpi_flows',
    INTERVAL '7 days',
    INTERVAL '90 days',
    'tenant_id,probe_id,protocol',
    'flow_time DESC'
);

SELECT apply_timescaledb_policies(
    'ndr_findings',
    INTERVAL '7 days',
    INTERVAL '90 days',
    'tenant_id,probe_id,finding_type',
    'finding_time DESC'
);

SELECT apply_timescaledb_policies(
    'network_infra_findings',
    INTERVAL '7 days',
    INTERVAL '90 days',
    'tenant_id,probe_id,finding_type',
    'finding_time DESC'
);

SELECT register_migration(33, 'partitioning');
