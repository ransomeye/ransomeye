BEGIN;

-- PRD-03 §3.11 worm_evidence (WORM triggers in migration 006)
CREATE TABLE worm_evidence (
    evidence_id          UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL REFERENCES tenants(tenant_id),
    detection_id         UUID        REFERENCES detections(detection_id),
    event_id             UUID,
    evidence_type        TEXT        NOT NULL CHECK (evidence_type IN (
                              'FORENSIC_BUNDLE','MEMORY_SNAPSHOT','FILE_SAMPLE','NETWORK_PCAP','DISK_IMAGE',
                              'LOG_EXPORT','MERKLE_PROOF_BUNDLE','CUSTOM')),
    file_path            TEXT        NOT NULL,
    canonical_json_hash  TEXT        NOT NULL CHECK (canonical_json_hash ~ '^[0-9a-f]{64}$'),
    worm_file_hash       TEXT        NOT NULL CHECK (worm_file_hash ~ '^[0-9a-f]{64}$'),
    ed25519_sig          TEXT        NOT NULL,
    retention_tier       TEXT        NOT NULL CHECK (retention_tier IN ('hot','warm','cold')),
    file_size_bytes      BIGINT      NOT NULL CHECK (file_size_bytes >= 0),
    sealed_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ
);

CREATE OR REPLACE FUNCTION calculate_worm_evidence_expiry()
RETURNS TRIGGER AS $$
BEGIN
    CASE NEW.retention_tier
        WHEN 'hot'  THEN NEW.expires_at := NEW.sealed_at + INTERVAL '90 days';
        WHEN 'warm' THEN NEW.expires_at := NEW.sealed_at + INTERVAL '730 days';
        WHEN 'cold' THEN NEW.expires_at := NEW.sealed_at + INTERVAL '2555 days';
        ELSE NEW.expires_at := NEW.sealed_at + INTERVAL '90 days';
    END CASE;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_calculate_worm_evidence_expiry
BEFORE INSERT ON worm_evidence
FOR EACH ROW
EXECUTE FUNCTION calculate_worm_evidence_expiry();

-- PRD-03 §3.17 exposure_worm_ledger
CREATE TABLE exposure_worm_ledger (
    ledger_id       BIGSERIAL   NOT NULL PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    evidence_id     UUID        NOT NULL REFERENCES worm_evidence(evidence_id),
    leaf_hash       TEXT        NOT NULL CHECK (leaf_hash ~ '^[0-9a-f]{64}$'),
    merkle_position INTEGER,
    daily_date      DATE        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ledger_evidence UNIQUE (evidence_id)
);

-- PRD-03 §3.18 merkle_daily_roots (immutability triggers in migration 009)
CREATE TABLE merkle_daily_roots (
    root_id      BIGSERIAL   NOT NULL PRIMARY KEY,
    tenant_id    UUID        NOT NULL REFERENCES tenants(tenant_id),
    daily_date   DATE        NOT NULL,
    merkle_root  TEXT        NOT NULL CHECK (merkle_root ~ '^[0-9a-f]{64}$'),
    leaf_count   INTEGER     NOT NULL CHECK (leaf_count >= 0),
    computed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ed25519_sig  TEXT        NOT NULL,
    CONSTRAINT uq_merkle_root_day UNIQUE (tenant_id, daily_date)
);

COMMIT;

