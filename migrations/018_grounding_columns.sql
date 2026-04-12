BEGIN;

-- PRD-03 §2 Migration 018: grounding columns for expert_analysis_reports (PRD-08 V0.0).
-- Grounding is stored as auditable structured metadata; SINE itself remains DB-read-only (Core persists).

ALTER TABLE expert_analysis_reports
    ADD COLUMN IF NOT EXISTS grounding_score NUMERIC(4,3) CHECK (grounding_score BETWEEN 0.0 AND 1.0),
    ADD COLUMN IF NOT EXISTS grounding_report JSONB,
    ADD COLUMN IF NOT EXISTS grounded_at TIMESTAMPTZ;

COMMIT;

