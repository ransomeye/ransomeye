package db_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	redb "ransomeye/core/internal/db"
)

// TestWORMImmutability_TelemetryEventsRejectUpdate connects to PostgreSQL via the
// trusted DB path (TLS 1.3, loopback-only, fingerprint-verified), inserts a
// telemetry row, then validates that UPDATE and DELETE are rejected by the
// WORM immutability triggers installed by migration 006.
//
// Prerequisites:
//   - A running PostgreSQL instance on 127.0.0.1:5432 with TLS 1.3 + mTLS.
//   - Environment: POSTGRES_DSN, PGUSER, PGPASSWORD, etc.
//   - Migration 006 applied (worm_no_update_telemetry, worm_no_delete_telemetry).
//
// This test is skipped automatically if POSTGRES_DSN is not set, allowing
// `go test ./...` to pass in environments without a database.
func TestWORMImmutability_TelemetryEventsRejectUpdate(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}

	db := mustOpenDB(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Seed a minimal row via the application INSERT path.
	tenantID := mustSeedTenant(ctx, t, db)
	agentID := mustSeedAgent(ctx, t, db, tenantID)
	eventID := mustInsertTelemetryEvent(ctx, t, db, tenantID, agentID)

	// ---------- UPDATE must fail ----------
	_, err := db.ExecContext(ctx,
		`UPDATE telemetry_events SET event_type = 'USER_EVENT' WHERE event_id = $1`,
		eventID,
	)
	if err == nil {
		t.Fatal("WORM violation: UPDATE on telemetry_events succeeded — trigger missing or broken")
	}
	if !strings.Contains(err.Error(), "WORM") {
		t.Fatalf("expected WORM exception message, got: %v", err)
	}

	// ---------- DELETE must fail ----------
	_, err = db.ExecContext(ctx,
		`DELETE FROM telemetry_events WHERE event_id = $1`, eventID,
	)
	if err == nil {
		t.Fatal("WORM violation: DELETE on telemetry_events succeeded — trigger missing or broken")
	}
	if !strings.Contains(err.Error(), "WORM") {
		t.Fatalf("expected WORM exception message, got: %v", err)
	}

	t.Log("PASS: telemetry_events WORM immutability enforced (UPDATE+DELETE rejected)")
}

// TestWORMImmutability_WormEvidenceRejectUpdate validates that UPDATE and DELETE
// are rejected on the worm_evidence table by triggers worm_no_update_evidence
// and worm_no_delete_evidence.
func TestWORMImmutability_WormEvidenceRejectUpdate(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}

	db := mustOpenDB(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tenantID := mustSeedTenant(ctx, t, db)
	evidenceID := mustInsertWormEvidence(ctx, t, db, tenantID)

	// ---------- UPDATE must fail ----------
	_, err := db.ExecContext(ctx,
		`UPDATE worm_evidence SET retention_tier = 'cold' WHERE evidence_id = $1`,
		evidenceID,
	)
	if err == nil {
		t.Fatal("WORM violation: UPDATE on worm_evidence succeeded — trigger missing or broken")
	}
	if !strings.Contains(err.Error(), "WORM") {
		t.Fatalf("expected WORM exception message, got: %v", err)
	}

	// ---------- DELETE must fail ----------
	_, err = db.ExecContext(ctx,
		`DELETE FROM worm_evidence WHERE evidence_id = $1`, evidenceID,
	)
	if err == nil {
		t.Fatal("WORM violation: DELETE on worm_evidence succeeded — trigger missing or broken")
	}
	if !strings.Contains(err.Error(), "WORM") {
		t.Fatalf("expected WORM exception message, got: %v", err)
	}

	t.Log("PASS: worm_evidence WORM immutability enforced (UPDATE+DELETE rejected)")
}

// TestWORMTriggersExist verifies that the four required trigger names are present
// in pg_trigger for the telemetry_events and worm_evidence tables.
func TestWORMTriggersExist(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}

	db := mustOpenDB(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	requiredTriggers := []struct {
		table   string
		trigger string
	}{
		{"telemetry_events", "worm_no_update_telemetry"},
		{"telemetry_events", "worm_no_delete_telemetry"},
		{"worm_evidence", "worm_no_update_evidence"},
		{"worm_evidence", "worm_no_delete_evidence"},
	}

	for _, rt := range requiredTriggers {
		var count int
		err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pg_trigger WHERE tgname = $1 AND tgrelid = $2::regclass`,
			rt.trigger, rt.table,
		).Scan(&count)
		if err != nil {
			t.Fatalf("trigger existence query for %s on %s failed: %v", rt.trigger, rt.table, err)
		}
		if count == 0 {
			t.Fatalf("WORM trigger %s missing on table %s", rt.trigger, rt.table)
		}
	}

	t.Log("PASS: all four WORM triggers exist in pg_trigger")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustOpenDB(t *testing.T) *sql.DB {
	t.Helper()
	cfg := redb.LoadConfigFromEnv()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := redb.NewPool(ctx, cfg)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "Missing PostgreSQL fingerprint") ||
			strings.Contains(msg, "permission denied") {
			t.Skipf("database integration prerequisites not satisfied: %v", err)
		}
		t.Fatalf("NewPool: %v", err)
	}
	return stdlib.OpenDBFromPool(pool)
}

func mustSeedTenant(ctx context.Context, t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	dek := make([]byte, 60)
	err := db.QueryRowContext(ctx,
		`INSERT INTO tenants (tenant_name, dek) VALUES ($1, $2) RETURNING tenant_id`,
		"worm-test-"+time.Now().Format("150405.000"), dek,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return id
}

func mustSeedAgent(ctx context.Context, t *testing.T, db *sql.DB, tenantID string) string {
	t.Helper()
	var id string
	err := db.QueryRowContext(ctx,
		`INSERT INTO agent_sessions (agent_id, tenant_id, boot_session_id, hostname, primary_ip, agent_type)
		 VALUES (gen_random_uuid(), $1, gen_random_uuid(), 'worm-test', '127.0.0.1', 'linux')
		 RETURNING agent_id`,
		tenantID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return id
}

func mustInsertTelemetryEvent(ctx context.Context, t *testing.T, db *sql.DB, tenantID, agentID string) string {
	t.Helper()
	var id string
	err := db.QueryRowContext(ctx,
		`INSERT INTO telemetry_events (tenant_id, agent_id, event_type, logical_clock, payload, source)
		 VALUES ($1, $2, 'PROCESS_EVENT', 1, '{"test": true}'::jsonb, 'linux_agent')
		 RETURNING event_id`,
		tenantID, agentID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert telemetry_event: %v", err)
	}
	return id
}

func mustInsertWormEvidence(ctx context.Context, t *testing.T, db *sql.DB, tenantID string) string {
	t.Helper()
	var id string
	err := db.QueryRowContext(ctx,
		`INSERT INTO worm_evidence (tenant_id, evidence_type, file_path, canonical_json_hash, worm_file_hash, ed25519_sig, retention_tier, file_size_bytes)
		 VALUES ($1, 'FORENSIC_BUNDLE', '/tmp/worm-test.bin',
		         'a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01',
		         'b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef0123',
		         'ed25519-test-sig', 'hot', 1024)
		 RETURNING evidence_id`,
		tenantID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert worm_evidence: %v", err)
	}
	return id
}

// Ensure pgx import is used (required by stdlib.OpenDBFromPool).
var _ = pgx.ConnConfig{}
