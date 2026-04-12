BEGIN;

-- Add source_type to telemetry_events for unified visibility (PHASE 2/3)
-- Allowed values: 'agent', 'syslog', 'netflow', 'dpi'
ALTER TABLE telemetry_events ADD COLUMN IF NOT EXISTS source_type TEXT;

-- Update existing rows based on the 'source' column
UPDATE telemetry_events SET source_type = 'agent' WHERE source IN ('linux_agent', 'windows_agent');
UPDATE telemetry_events SET source_type = 'dpi' WHERE source = 'dpi_probe';
UPDATE telemetry_events SET source_type = 'agent' WHERE source_type IS NULL;

-- Enforce check constraint
ALTER TABLE telemetry_events ADD CONSTRAINT chk_telemetry_source_type 
    CHECK (source_type IN ('agent', 'syslog', 'netflow', 'dpi'));

-- Set default for new rows
ALTER TABLE telemetry_events ALTER COLUMN source_type SET DEFAULT 'agent';
ALTER TABLE telemetry_events ALTER COLUMN source_type SET NOT NULL;

COMMIT;
