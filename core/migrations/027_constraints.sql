-- Migration 027: cross-column and semantic constraints.

ALTER TABLE telemetry_events
    DROP CONSTRAINT IF EXISTS chk_telemetry_events_time_sync;

ALTER TABLE telemetry_events
    ADD CONSTRAINT chk_telemetry_events_time_sync
    CHECK (event_time = timestamp);

ALTER TABLE detections
    DROP CONSTRAINT IF EXISTS chk_detections_time_sync;

ALTER TABLE detections
    ADD CONSTRAINT chk_detections_time_sync
    CHECK (detected_at = timestamp);

ALTER TABLE worm_evidence
    DROP CONSTRAINT IF EXISTS chk_worm_evidence_expiry;

ALTER TABLE worm_evidence
    ADD CONSTRAINT chk_worm_evidence_expiry
    CHECK (expires_at >= sealed_at);

ALTER TABLE compound_incidents
    DROP CONSTRAINT IF EXISTS chk_compound_incidents_window;

ALTER TABLE compound_incidents
    ADD CONSTRAINT chk_compound_incidents_window
    CHECK (time_window_end >= time_window_start);

ALTER TABLE incidents
    DROP CONSTRAINT IF EXISTS chk_incidents_resolution_time;

ALTER TABLE incidents
    ADD CONSTRAINT chk_incidents_resolution_time
    CHECK (resolved_at = '1970-01-01 00:00:00+00'::timestamptz OR resolved_at >= first_seen_at);

ALTER TABLE actions
    DROP CONSTRAINT IF EXISTS chk_actions_time_order;

ALTER TABLE actions
    ADD CONSTRAINT chk_actions_time_order
    CHECK (
        dispatched_at = '1970-01-01 00:00:00+00'::timestamptz
        OR dispatched_at >= created_at
    );

ALTER TABLE actions
    DROP CONSTRAINT IF EXISTS chk_actions_completion_time;

ALTER TABLE actions
    ADD CONSTRAINT chk_actions_completion_time
    CHECK (
        completed_at = '1970-01-01 00:00:00+00'::timestamptz
        OR completed_at >= dispatched_at
    );

ALTER TABLE cases
    DROP CONSTRAINT IF EXISTS chk_cases_closed_time;

ALTER TABLE cases
    ADD CONSTRAINT chk_cases_closed_time
    CHECK (
        closed_at = '1970-01-01 00:00:00+00'::timestamptz
        OR closed_at >= created_at
    );

ALTER TABLE policy_versions
    DROP CONSTRAINT IF EXISTS chk_policy_versions_approval_time;

ALTER TABLE policy_versions
    ADD CONSTRAINT chk_policy_versions_approval_time
    CHECK (
        approved_at = '1970-01-01 00:00:00+00'::timestamptz
        OR approved_at >= created_at
    );

ALTER TABLE soc_sessions
    DROP CONSTRAINT IF EXISTS chk_soc_sessions_expiry;

ALTER TABLE soc_sessions
    ADD CONSTRAINT chk_soc_sessions_expiry
    CHECK (expires_at > created_at);

ALTER TABLE replay_runs
    DROP CONSTRAINT IF EXISTS chk_replay_runs_time_order;

ALTER TABLE replay_runs
    ADD CONSTRAINT chk_replay_runs_time_order
    CHECK (
        started_at = '1970-01-01 00:00:00+00'::timestamptz
        OR completed_at = '1970-01-01 00:00:00+00'::timestamptz
        OR completed_at >= started_at
    );

ALTER TABLE intel_indicators
    DROP CONSTRAINT IF EXISTS chk_intel_indicators_time_order;

ALTER TABLE intel_indicators
    ADD CONSTRAINT chk_intel_indicators_time_order
    CHECK (last_seen >= first_seen);

ALTER TABLE bundle_application_log
    DROP CONSTRAINT IF EXISTS chk_bundle_application_log_failure_reason;

ALTER TABLE bundle_application_log
    ADD CONSTRAINT chk_bundle_application_log_failure_reason
    CHECK (
        (outcome = 'SUCCESS' AND failure_reason = '')
        OR outcome <> 'SUCCESS'
    );

SELECT register_migration(27, 'constraints');
