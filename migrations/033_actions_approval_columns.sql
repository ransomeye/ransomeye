BEGIN;

-- PRD-03 §2 Migration 033: actions approval columns (PRD-19 V0.0 §6).

ALTER TABLE actions
    ADD COLUMN IF NOT EXISTS approval_required  BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS approved_by        TEXT,
    ADD COLUMN IF NOT EXISTS approved_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS second_approver_id UUID        REFERENCES soc_users(user_id),
    ADD COLUMN IF NOT EXISTS second_approved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS totp_verified_at   TIMESTAMPTZ;

COMMIT;

