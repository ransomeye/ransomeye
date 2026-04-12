-- Mishka PRD-25: honest SOC-side reporting/export lineage projection (not partition_records authority).
-- Written on successful forensics export; read via GET /api/v1/reporting/lineage.
-- partition_records QUERY/REPORT types remain the separate PRD-13 commit path when wired.

CREATE TABLE IF NOT EXISTS mishka_soc_report_lineage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope TEXT NOT NULL,
    query_spec JSONB NOT NULL,
    result_ref TEXT NOT NULL,
    authority_note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope, result_ref)
);

CREATE INDEX IF NOT EXISTS mishka_soc_report_lineage_created_at_idx
    ON mishka_soc_report_lineage (created_at DESC);

SELECT register_migration(48, 'mishka_soc_report_lineage');
