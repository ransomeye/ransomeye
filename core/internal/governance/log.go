package governance

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	corecrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/forensics"
)

const EventTypeTelemetryIngest = "TELEMETRY_INGEST"

type Event struct {
	EventType string
	Actor     string
	TenantID  string
	CreatedAt time.Time
	Details   map[string]any
}

type execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

var (
	signingKeyOnce sync.Once
	signingKey     ed25519.PrivateKey
	signingKeyErr  error
)

func LogEventTx(ctx context.Context, db execer, event Event) error {
	if db == nil {
		return errors.New("nil governance execer")
	}
	if event.EventType == "" {
		return errors.New("governance event_type is required")
	}
	if event.Actor == "" {
		return errors.New("governance actor is required")
	}
	if event.TenantID == "" {
		return errors.New("governance tenant_id is required")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	if event.Details == nil {
		event.Details = map[string]any{}
	}

	payload, err := canonicalPayload(event)
	if err != nil {
		return err
	}
	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("marshal governance details: %w", err)
	}

	key, err := loadSigningKey()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(key, payload)

	const q = `
INSERT INTO governance_audit_log (
    audit_id,
    tenant_id,
    event_type,
    actor,
    details_json,
    signature_hex,
    created_at,
    recorded_at
)
VALUES (
    gen_random_uuid(),
    $1::uuid,
    $2::text,
    $3::text,
    $4::jsonb,
    $5::text,
    $6::timestamptz,
    $6::timestamptz
)`

	if _, err := db.Exec(
		ctx,
		q,
		event.TenantID,
		event.EventType,
		event.Actor,
		detailsJSON,
		hex.EncodeToString(sig),
		event.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert governance audit log: %w", err)
	}
	return nil
}

func canonicalPayload(event Event) ([]byte, error) {
	return forensics.MarshalCanonical(map[string]any{
		"actor":      event.Actor,
		"created_at": event.CreatedAt.UTC().Format(time.RFC3339Nano),
		"details":    event.Details,
		"event_type": event.EventType,
		"tenant_id":  event.TenantID,
	})
}

func loadSigningKey() (ed25519.PrivateKey, error) {
	signingKeyOnce.Do(func() {
		raw, err := corecrypto.ReadValidatedWormSeed(corecrypto.WormSigningKeyPath, true)
		if err != nil {
			signingKeyErr = fmt.Errorf("read governance signing key: %w", err)
			return
		}
		signingKey = ed25519.NewKeyFromSeed(raw)
	})
	if signingKeyErr != nil {
		return nil, signingKeyErr
	}
	return signingKey, nil
}
