-- PRD-02 / PRD-10 / PRD-18: preserve probe-reported drop accounting end-to-end.

ALTER TABLE telemetry_events
    ADD COLUMN IF NOT EXISTS dropped_packets_before BIGINT NOT NULL DEFAULT 0;

ALTER TABLE telemetry_events
    DROP CONSTRAINT IF EXISTS chk_telemetry_events_dropped_packets_before_nonnegative;

ALTER TABLE telemetry_events
    ADD CONSTRAINT chk_telemetry_events_dropped_packets_before_nonnegative
    CHECK (dropped_packets_before >= 0);

COMMENT ON COLUMN telemetry_events.dropped_packets_before IS 'Probe-reported packets dropped before this event reached core ingest.';

ALTER TABLE worm_evidence
    ADD COLUMN IF NOT EXISTS dropped_packets_before BIGINT NOT NULL DEFAULT 0;

ALTER TABLE worm_evidence
    DROP CONSTRAINT IF EXISTS chk_worm_evidence_dropped_packets_before_nonnegative;

ALTER TABLE worm_evidence
    ADD CONSTRAINT chk_worm_evidence_dropped_packets_before_nonnegative
    CHECK (dropped_packets_before >= 0);

COMMENT ON COLUMN worm_evidence.dropped_packets_before IS 'Probe-reported packets dropped before the persisted telemetry event that produced this evidence.';
