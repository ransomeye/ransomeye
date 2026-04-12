-- Migration 006: enriched telemetry records.

CREATE TABLE IF NOT EXISTS telemetry_enriched (
    enriched_id         UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL,
    event_id            UUID        NOT NULL,
    detection_id        UUID,
    event_time          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enrichment_stage    TEXT        NOT NULL
                                    CHECK (enrichment_stage IN (
                                        'NORMALIZED',
                                        'INTEL',
                                        'BAYESIAN',
                                        'LOO',
                                        'FORENSIC',
                                        'MANUAL'
                                    )),
    enrichment_source   TEXT        NOT NULL
                                    CHECK (enrichment_source IN ('core', 'sine', 'intel', 'policy', 'analyst')),
    enrichment_json     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (enriched_id, event_time)
);

SELECT register_migration(6, 'telemetry_enriched');
