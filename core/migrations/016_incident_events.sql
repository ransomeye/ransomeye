-- Migration 016: incident activity streams and simulation history.

CREATE TABLE IF NOT EXISTS incident_events (
    incident_event_id  UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id        UUID        NOT NULL,
    tenant_id          UUID        NOT NULL,
    detection_id       UUID,
    action_id          UUID,
    event_type         TEXT        NOT NULL
                                      CHECK (event_type IN (
                                          'DETECTION_LINKED',
                                          'ACTION_CREATED',
                                          'ACTION_DISPATCHED',
                                          'ACTION_COMPLETED',
                                          'NOTE_ADDED',
                                          'STATUS_CHANGED',
                                          'SEVERITY_CHANGED',
                                          'CASE_LINKED'
                                      )),
    event_payload      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    event_time         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_artifacts (
    artifact_id       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id           UUID        NOT NULL,
    tenant_id         UUID        NOT NULL,
    artifact_type     TEXT        NOT NULL
                                      CHECK (artifact_type IN (
                                          'DETECTION',
                                          'WORM_EVIDENCE',
                                          'ACTION',
                                          'TELEMETRY_EVENT',
                                          'EXTERNAL_FILE'
                                      )),
    reference_table   TEXT        NOT NULL DEFAULT '',
    reference_id      TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS simulation_runs (
    sim_id                       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                    UUID        NOT NULL,
    detection_id                 UUID        NOT NULL,
    action_id                    UUID,
    risk_score                   NUMERIC(5,2) NOT NULL CHECK (risk_score BETWEEN 0.0 AND 100.0),
    affected_systems             JSONB       NOT NULL DEFAULT '[]'::jsonb,
    estimated_downtime_minutes   INTEGER     NOT NULL DEFAULT 0 CHECK (estimated_downtime_minutes >= 0),
    recommendation               TEXT        NOT NULL CHECK (recommendation IN ('PROCEED', 'HOLD', 'ESCALATE')),
    simulation_detail            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    simulated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS replay_runs (
    replay_id             UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID        NOT NULL,
    case_id               UUID,
    detection_id          UUID,
    status                TEXT        NOT NULL DEFAULT 'PENDING'
                                       CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    started_at            TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    completed_at          TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00+00',
    events_processed      INTEGER     NOT NULL DEFAULT 0 CHECK (events_processed >= 0),
    replay_timeline_json  JSONB       NOT NULL DEFAULT '[]'::jsonb,
    sine_narrative        TEXT        NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT register_migration(16, 'incident_events');
