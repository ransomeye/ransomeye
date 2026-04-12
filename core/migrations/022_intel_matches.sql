-- Migration 022: intelligence match events.

CREATE TABLE IF NOT EXISTS intel_matches (
    match_id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    indicator_id      UUID,
    detection_id      UUID,
    event_id          UUID,
    match_source      TEXT        NOT NULL CHECK (match_source IN ('telemetry', 'detection', 'enrichment', 'manual')),
    match_type        TEXT        NOT NULL CHECK (match_type IN ('INDICATOR_MATCH', 'BEHAVIORAL_MATCH', 'CONTEXTUAL_MATCH')),
    matched_value     TEXT        NOT NULL,
    confidence        NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    raw_context       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    event_time        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (match_id, event_time)
);

SELECT register_migration(22, 'intel_matches');
