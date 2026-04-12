package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	coreconfig "ransomeye/core/internal/config"
	appdb "ransomeye/core/internal/db"
	"ransomeye/core/internal/contracts"
	"ransomeye/core/internal/forensics"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/netcfg"
	pb "ransomeye/proto/ransomeyepb"
)

const (
	defaultPGPort = 5432

	defaultPGTLSCAPath = "/opt/ransomeye/core/certs/ca-chain.crt"
)

var (
	ErrInvalidDSN = errors.New("invalid postgres dsn")
)

type DB struct {
	Pool *pgxpool.Pool
}

type DBOptions struct {
	// BaseDSN may omit sslmode/host/port; all will be enforced.
	// Example: "user=ransomeye password=... dbname=ransomeye"
	BaseDSN string

	Host string
	Port int

	// TLSRootCAPath is the PEM trust bundle used to verify the PostgreSQL server certificate
	// under sslmode=verify-full. Defaults to /opt/ransomeye/core/certs/ca-chain.crt (full chain).
	TLSRootCAPath string

	// TLSServerName is used for verify-full hostname validation.
	// For loopback deployments, this is commonly the IPv4 loopback host (if present in SAN).
	TLSServerName string

	MaxConns int32
}

func Open(ctx context.Context, opts DBOptions) (*DB, error) {
	host := opts.Host
	if host == "" {
		host = netcfg.LoopbackHost
	}
	if !netcfg.IsLoopbackHost(host) {
		return nil, fmt.Errorf("%w: host must be %q", ErrInvalidDSN, netcfg.LoopbackHost)
	}

	port := opts.Port
	if port == 0 {
		port = defaultPGPort
	}
	if port != 5432 && port != 5433 {
		return nil, fmt.Errorf("%w: port must be 5432 or 5433", ErrInvalidDSN)
	}

	caPath := opts.TLSRootCAPath
	if caPath == "" {
		caPath = defaultPGTLSCAPath
	}

	serverName := opts.TLSServerName
	if serverName == "" {
		serverName = host
	}

	dsn, err := enforceDSN(opts.BaseDSN, host, port)
	if err != nil {
		return nil, err
	}
	pc, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	envCfg := appdb.LoadConfigFromEnv()
	cc, err := coreconfig.LoadVerifiedCommonConfig(
		coreconfig.InstalledCommonConfigPath,
		coreconfig.IntermediateCACertPath,
	)
	if err != nil {
		return nil, fmt.Errorf("load signed common config for postgres fingerprint: %w", err)
	}
	fp := strings.TrimSpace(cc.Database.ExpectedServerFingerprint)
	if fp == "" {
		return nil, fmt.Errorf("Missing PostgreSQL fingerprint — installer misconfiguration")
	}
	dbCfg := appdb.Config{
		User:                              firstNonEmpty(strings.TrimSpace(pc.User), envCfg.User),
		Password:                          pc.Password,
		Database:                          firstNonEmpty(strings.TrimSpace(pc.Database), envCfg.Database),
		SSLRootCert:                       caPath,
		SSLClientCert:                     envCfg.SSLClientCert,
		SSLClientKey:                      envCfg.SSLClientKey,
		TLSServerName:                     serverName,
		ExpectedPostgresServerFingerprint: fp,
		PoolMaxConns:                      opts.MaxConns,
	}

	pool, err := appdb.NewPool(ctx, dbCfg)
	if err != nil {
		return nil, err
	}

	return &DB{Pool: pool}, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (db *DB) Close() {
	if db == nil || db.Pool == nil {
		return
	}
	db.Pool.Close()
}

type InsertTelemetryOptions struct {
	Source string // 'linux_agent'|'windows_agent'|'dpi_probe'|'offline_sync'
}

type TelemetryRecord struct {
	EventID      string
	TenantID     string
	AgentID      string
	SessionID    string
	EventType    string
	LogicalClock int64
	Payload      []byte
	PayloadHash  string
	CreatedAt    time.Time
}

func GetLatestTelemetryWithValidation(ctx context.Context, pool *pgxpool.Pool, limit int) ([]TelemetryRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	rows, err := pool.Query(ctx, `
SELECT event_id, tenant_id, agent_id, session_id, event_type, logical_clock, payload, payload_hash, created_at
FROM telemetry_events
ORDER BY created_at DESC
LIMIT $1
`, limit)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("telemetry query timeout")
		}
		return nil, err
	}
	defer rows.Close()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("telemetry query timeout")
	}

	var records []TelemetryRecord
	for rows.Next() {
		var r TelemetryRecord
		err := rows.Scan(
			&r.EventID,
			&r.TenantID,
			&r.AgentID,
			&r.SessionID,
			&r.EventType,
			&r.LogicalClock,
			&r.Payload,
			&r.PayloadHash,
			&r.CreatedAt,
		)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("telemetry query timeout")
			}
			return nil, err
		}
		records = append(records, r)
	}

	if err := rows.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("telemetry query timeout")
		}
		return nil, err
	}

	// Hard fail if there are no telemetry rows.
	if len(records) == 0 {
		return nil, fmt.Errorf("no telemetry data available")
	}

	// Hard fail if the newest row is stale.
	now := time.Now()
	if now.Sub(records[0].CreatedAt) > 60*time.Second {
		return nil, fmt.Errorf("telemetry data stale")
	}

	return records, nil
}

func (db *DB) InsertTelemetryTx(ctx context.Context, ev *ingest.VerifiedTelemetry, opt InsertTelemetryOptions) (eventID string, err error) {
	_ = db
	_ = ev
	_ = opt
	if err := forensics.MustBeSealed(nil); err != nil {
		return "", fmt.Errorf("telemetry insert requires WORM-sealed pipeline path: %w", err)
	}
	return "", errors.New("telemetry insert requires WORM-sealed pipeline path")
}

// LogActionResultTx appends an immutable WORM audit record for an agent-reported action result.
// The governance_audit_log table is WORM-protected (Migration 020) and rejects UPDATE/DELETE.
func LogActionResultTx(ctx context.Context, pool *pgxpool.Pool, result *pb.ActionResult) error {
	if pool == nil {
		return errors.New("nil pgxpool")
	}
	if result == nil {
		return errors.New("nil action result")
	}
	if result.AgentId == "" || result.ActionId == "" {
		return errors.New("missing agent_id or action_id")
	}

	statusName := pb.ActionStatus_name[int32(result.Status)]
	if statusName == "" {
		statusName = "UNKNOWN"
	}

	// Map to allowed governance_audit_log event types (per current PRD-03 migration constraints).
	eventType := "ACTION_APPROVED"
	if !result.Success {
		eventType = "ACTION_REJECTED"
	}

	details := map[string]any{
		"action_id":        result.ActionId,
		"agent_id":         result.AgentId,
		"status":           statusName,
		"success":          result.Success,
		"error_message":    result.ErrorMessage,
		"logical_clock":    result.LogicalClock,
		"wall_clock_epoch": result.WallClockEpoch,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return err
	}
	if err := forensics.MustBeSealed(&forensics.Event{}); err != nil {
		return err
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
INSERT INTO governance_audit_log (audit_id, tenant_id, event_type, actor, details_json)
VALUES (
    gen_random_uuid(),
    (SELECT tenant_id FROM agent_sessions WHERE agent_id = $1::uuid),
    $2::text,
    $3::text,
    $4::jsonb
)
`
	if _, err := tx.Exec(ctx, q, result.AgentId, eventType, result.AgentId, detailsJSON); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// LogEnforcementEvent appends an immutable audit record for an enforcement event (PRD-01).
func LogEnforcementEvent(ctx context.Context, pool *pgxpool.Pool, event contracts.EnforcementEvent) error {
	if pool == nil {
		return errors.New("nil pgxpool")
	}
	payloadHash := sha256.Sum256([]byte(event.CanonicalPayload()))
	if err := forensics.MustBeSealed(&forensics.Event{
		WormSignature: event.Signature,
		Hash:          fmt.Sprintf("%x", payloadHash[:]),
	}); err != nil {
		return err
	}
	details := map[string]any{
		"seq":       event.Seq,
		"action":    event.Action,
		"target":    event.Target,
		"status":    event.Status,
		"timestamp": event.Timestamp,
		"signature": event.Signature, // Ed25519 seal from enforcement (required for persistence)
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return err
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const q = `
INSERT INTO governance_audit_log (audit_id, tenant_id, event_type, actor, details_json)
VALUES (gen_random_uuid(), (SELECT tenant_id FROM agent_sessions WHERE agent_id = $1::uuid LIMIT 1), 'ENFORCEMENT_DISPATCHED', $2::text, $3::jsonb)
`
	if _, err := tx.Exec(ctx, q, event.AgentID, event.AgentID, detailsJSON); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func enforceDSN(base string, host string, port int) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", fmt.Errorf("%w: empty base dsn", ErrInvalidDSN)
	}

	if strings.Contains(base, "://") {
		u, err := url.Parse(base)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidDSN, err)
		}
		mode := strings.TrimSpace(strings.ToLower(u.Query().Get("sslmode")))
		if mode != "" && mode != "verify-full" {
			return "", fmt.Errorf("%w: sslmode must be verify-full", ErrInvalidDSN)
		}
		q := u.Query()
		q.Set("sslmode", "verify-full")
		u.RawQuery = q.Encode()
		out := u.String()
		if err := appdb.ValidateInboundPostgresDSN(out); err != nil {
			return "", err
		}
		return out, nil
	}

	lower := strings.ToLower(base)
	for _, bad := range []string{"sslmode=disable", "sslmode=allow", "sslmode=prefer", "sslmode=require", "sslmode=verify-ca"} {
		if strings.Contains(lower, bad) {
			return "", fmt.Errorf("%w: forbidden %q", ErrInvalidDSN, bad)
		}
	}

	kv := strings.TrimSpace(base)
	if strings.Contains(lower, "sslmode=") && !strings.Contains(lower, "sslmode=verify-full") {
		return "", fmt.Errorf("%w: sslmode must be verify-full", ErrInvalidDSN)
	}
	var b strings.Builder
	b.WriteString(kv)
	if !strings.HasSuffix(kv, " ") {
		b.WriteByte(' ')
	}
	if !strings.Contains(lower, "host=") {
		fmt.Fprintf(&b, "host=%s ", host)
	}
	if !strings.Contains(lower, "port=") {
		fmt.Fprintf(&b, "port=%d ", port)
	}
	if !strings.Contains(lower, "sslmode=") {
		b.WriteString("sslmode=verify-full ")
	}
	out := strings.TrimSpace(b.String())
	if err := appdb.ValidateInboundPostgresDSN(out); err != nil {
		return "", err
	}
	return out, nil
}
