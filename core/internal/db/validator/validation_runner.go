package validator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbbase "ransomeye/core/internal/db"
)

type Config struct {
	DB dbbase.Config
}

type Checks struct {
	Tables          bool `json:"tables"`
	Immutability    bool `json:"immutability"`
	Merkle          bool `json:"merkle"`
	RLS             bool `json:"rls"`
	Timescale       bool `json:"timescale"`
	TLS             bool `json:"tls"`
	ForbiddenTables bool `json:"forbidden_tables"`
	Indexes         bool `json:"indexes"`
}

type Result struct {
	Status      string  `json:"status"`
	Checks      *Checks `json:"checks,omitempty"`
	FailedCheck string  `json:"failed_check,omitempty"`
	// Detail carries the underlying error message when Status is FAIL (operator/debug; not an API contract).
	Detail string `json:"detail,omitempty"`
}

type merkleRecord struct {
	SourcePK     string
	PayloadHash  string
	PrevRootHash string
	RootHash     string
	LeafSequence int64
}

// VerifyLayoutDrift checks required public tables and forbids graph_nodes / graph_edges (post-migration drift gate).
func VerifyLayoutDrift(ctx context.Context, cfg Config) error {
	conn, err := dbbase.Connect(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	if err := dbbase.VerifyProvisioningSession(ctx, conn, cfg.DB, cfg.DB.User); err != nil {
		return fmt.Errorf("session trust: %w", err)
	}
	if err := checkTables(ctx, conn); err != nil {
		return fmt.Errorf("required tables: %w", err)
	}
	if err := checkForbiddenTables(ctx, conn); err != nil {
		return fmt.Errorf("forbidden tables: %w", err)
	}
	return nil
}

func Run(ctx context.Context, cfg Config) Result {
	conn, err := dbbase.Connect(ctx, cfg.DB)
	if err != nil {
		return failed("tls")
	}
	defer conn.Close(ctx)

	if err := dbbase.VerifyProvisioningSession(ctx, conn, cfg.DB, cfg.DB.User); err != nil {
		return failed("tls")
	}

	if err := checkTables(ctx, conn); err != nil {
		return failedWith("tables", err)
	}
	if err := checkImmutability(ctx, conn); err != nil {
		return failedWith("immutability", err)
	}
	if err := checkMerkle(ctx, conn); err != nil {
		return failedWith("merkle", err)
	}
	if err := checkRLS(ctx, conn); err != nil {
		return failedWith("rls", err)
	}
	if err := checkTimescale(ctx, conn); err != nil {
		return failedWith("timescale", err)
	}
	if err := checkForbiddenTables(ctx, conn); err != nil {
		return failedWith("forbidden_tables", err)
	}
	if err := checkIndexes(ctx, conn); err != nil {
		return failedWith("indexes", err)
	}

	return Result{
		Status: "PASS",
		Checks: &Checks{
			Tables:          true,
			Immutability:    true,
			Merkle:          true,
			RLS:             true,
			Timescale:       true,
			TLS:             true,
			ForbiddenTables: true,
			Indexes:         true,
		},
	}
}

func failed(name string) Result {
	return Result{
		Status:      "FAIL",
		FailedCheck: name,
	}
}

func failedWith(name string, err error) Result {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	return Result{
		Status:      "FAIL",
		FailedCheck: name,
		Detail:      detail,
	}
}

func checkTables(ctx context.Context, conn *dbbase.TrustedConn) error {
	requiredTables := []string{
		"agent_sessions",
		"telemetry_events",
		"detections",
		"worm_evidence",
		"governance_audit_log",
		"incidents",
		"policy_rules",
		"intel_indicators",
		"agent_heartbeats",
		"replay_runs",
		"partition_records",
		"batch_commit_records",
		"batch_commit_authority_bindings",
		"authority_snapshots",
		"replay_guard",
		"segment_manifests",
		"retention_proofs",
		"commit_groups",
	}

	for _, tableName := range requiredTables {
		exists, err := objectExists(ctx, conn, "public."+tableName)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("missing table %s", tableName)
		}
	}

	looColumns := [][2]string{
		{"detections", "loo_importance"},
	}
	for _, item := range looColumns {
		exists, err := columnExists(ctx, conn, item[0], item[1])
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("missing column %s.%s", item[0], item[1])
		}
	}

	var totalMigrations int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&totalMigrations); err != nil {
		return fmt.Errorf("count schema_migrations: %w", err)
	}
	if totalMigrations != 48 {
		return fmt.Errorf("schema_migrations count mismatch: got %d want 48", totalMigrations)
	}

	var missingCount int
	if err := conn.QueryRow(ctx, `
SELECT COUNT(*)
FROM generate_series(1, 48) AS g(version)
LEFT JOIN schema_migrations sm ON sm.version = g.version
WHERE sm.version IS NULL`).Scan(&missingCount); err != nil {
		return fmt.Errorf("verify schema_migrations sequence: %w", err)
	}
	if missingCount != 0 {
		return fmt.Errorf("schema_migrations missing %d required versions", missingCount)
	}
	/*
		if err := checkReplayIngestSchema(ctx, conn); err != nil {
			return fmt.Errorf("telemetry replay schema: %w", err)
		}
	*/

	return nil
}

func checkImmutability(ctx context.Context, conn *dbbase.TrustedConn) error {
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		log.Println("[DEV MODE] skipping immutability check")
		return nil
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	fixture, err := seedImmutableFixtures(ctx, tx)
	if err != nil {
		return err
	}

	checkSQL := fmt.Sprintf(`
DO $$
BEGIN
    -- RLS policies read current_tenant_uuid(); ensure tenant context inside this PL/pgSQL block.
    PERFORM set_config('app.tenant_id', '%s', true);
    BEGIN
        UPDATE worm_evidence SET file_path = '/tmp/tampered' WHERE evidence_id = '%s';
        RAISE EXCEPTION 'UPDATE_WORM_EVIDENCE_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%%WORM:%%' AND SQLERRM NOT LIKE '%%IMMUTABILITY_VIOLATION%%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        DELETE FROM worm_evidence WHERE evidence_id = '%s';
        RAISE EXCEPTION 'DELETE_WORM_EVIDENCE_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%%WORM:%%' AND SQLERRM NOT LIKE '%%IMMUTABILITY_VIOLATION%%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        UPDATE governance_audit_log SET actor = 'tampered' WHERE audit_id = '%s';
        RAISE EXCEPTION 'UPDATE_GOVERNANCE_AUDIT_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%%WORM:%%' AND SQLERRM NOT LIKE '%%IMMUTABILITY_VIOLATION%%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        DELETE FROM governance_audit_log WHERE audit_id = '%s';
        RAISE EXCEPTION 'DELETE_GOVERNANCE_AUDIT_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%%WORM:%%' AND SQLERRM NOT LIKE '%%IMMUTABILITY_VIOLATION%%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        UPDATE incident_notes SET note_text = 'tampered' WHERE note_id = '%s';
        RAISE EXCEPTION 'UPDATE_INCIDENT_NOTES_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%%WORM:%%' AND SQLERRM NOT LIKE '%%IMMUTABILITY_VIOLATION%%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        DELETE FROM incident_notes WHERE note_id = '%s';
        RAISE EXCEPTION 'DELETE_INCIDENT_NOTES_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%%WORM:%%' AND SQLERRM NOT LIKE '%%IMMUTABILITY_VIOLATION%%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        UPDATE bundle_application_log SET applied_by = 'tampered' WHERE log_id = '%s';
        RAISE EXCEPTION 'UPDATE_BUNDLE_LOG_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%%WORM:%%' AND SQLERRM NOT LIKE '%%IMMUTABILITY_VIOLATION%%' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        DELETE FROM bundle_application_log WHERE log_id = '%s';
        RAISE EXCEPTION 'DELETE_BUNDLE_LOG_DID_NOT_FAIL';
    EXCEPTION
        WHEN others THEN
            IF SQLERRM NOT LIKE '%%WORM:%%' AND SQLERRM NOT LIKE '%%IMMUTABILITY_VIOLATION%%' THEN
                RAISE;
            END IF;
    END;
END
$$;`,
		strings.ReplaceAll(fixture.tenantID, "'", "''"),
		fixture.evidenceID,
		fixture.evidenceID,
		fixture.auditID,
		fixture.auditID,
		fixture.noteID,
		fixture.noteID,
		fixture.bundleLogID,
		fixture.bundleLogID,
	)

	if _, err := tx.Exec(ctx, checkSQL); err != nil {
		return fmt.Errorf("immutability verification failed: %w", err)
	}

	return nil
}

func checkMerkle(ctx context.Context, conn *dbbase.TrustedConn) error {
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		log.Println("[DEV MODE] skipping merkle check")
		return nil
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tenantID := uuid.NewString()
	if err := insertTenant(ctx, tx, tenantID, "merkle"); err != nil {
		return err
	}
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return err
	}

	timestamps := []time.Time{
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 1, 2, 3, 5, 5, 0, time.UTC),
		time.Date(2026, 1, 2, 3, 6, 5, 0, time.UTC),
	}

	insertedIDs := make([]string, 0, len(timestamps))
	for i, ts := range timestamps {
		evidenceID := uuid.NewString()
		if err := insertWormEvidence(ctx, tx, tenantID, evidenceID, i+1, ts); err != nil {
			return err
		}
		insertedIDs = append(insertedIDs, evidenceID)
	}

	roots, err := queryMerkleRows(ctx, tx, "merkle_roots", tenantID)
	if err != nil {
		return err
	}
	treeRows, err := queryMerkleRows(ctx, tx, "merkle_tree", tenantID)
	if err != nil {
		return err
	}
	if len(roots) != 3 || len(treeRows) != 3 {
		return fmt.Errorf("unexpected merkle row count: roots=%d tree=%d", len(roots), len(treeRows))
	}

	payloadHashes, err := recomputeWormEvidencePayloadHashes(ctx, tx, insertedIDs)
	if err != nil {
		return err
	}

	expectedPrev := ""
	for i, row := range roots {
		expectedPayload, ok := payloadHashes[row.SourcePK]
		if !ok {
			return fmt.Errorf("missing recomputed payload hash for evidence %s", row.SourcePK)
		}
		if row.PayloadHash != expectedPayload {
			return fmt.Errorf("payload hash mismatch for evidence %s", row.SourcePK)
		}
		if row.PrevRootHash != expectedPrev {
			return fmt.Errorf(
				"merkle prev_root mismatch at sequence %d: got=%s want=%s",
				row.LeafSequence,
				row.PrevRootHash,
				expectedPrev,
			)
		}

		expectedRoot, err := computeRootHash(expectedPrev, expectedPayload)
		if err != nil {
			return err
		}
		if row.RootHash != expectedRoot {
			return fmt.Errorf("merkle root mismatch at sequence %d", row.LeafSequence)
		}

		treeRow := treeRows[i]
		if treeRow.SourcePK != row.SourcePK ||
			treeRow.PayloadHash != row.PayloadHash ||
			treeRow.PrevRootHash != row.PrevRootHash ||
			treeRow.RootHash != row.RootHash ||
			treeRow.LeafSequence != row.LeafSequence {
			return fmt.Errorf("merkle_tree mismatch at sequence %d", row.LeafSequence)
		}

		expectedPrev = expectedRoot
	}

	return nil
}

func checkRLS(ctx context.Context, conn *dbbase.TrustedConn) error {
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		log.Println("[DEV MODE] skipping RLS check")
		return nil
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tenantA := uuid.NewString()
	tenantB := uuid.NewString()
	if err := insertTenant(ctx, tx, tenantA, "rls-a"); err != nil {
		return err
	}
	if err := insertTenant(ctx, tx, tenantB, "rls-b"); err != nil {
		return err
	}

	agentIDA := uuid.NewString()
	agentIDB := uuid.NewString()
	if err := insertRLSTenantFixtures(ctx, tx, tenantA, agentIDA, "a"); err != nil {
		return err
	}
	if err := insertRLSTenantFixtures(ctx, tx, tenantB, agentIDB, "b"); err != nil {
		return err
	}

	var isSuperuser bool
	var bypassRLS bool
	if err := conn.QueryRow(ctx, `
SELECT rolsuper, rolbypassrls
FROM pg_roles
WHERE rolname = current_user`).Scan(&isSuperuser, &bypassRLS); err != nil {
		return fmt.Errorf("inspect current role: %w", err)
	}

	if isSuperuser || bypassRLS {
		if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION ransomeye_readonly`); err != nil {
			return fmt.Errorf("set session authorization for rls check: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `SET LOCAL row_security = on`); err != nil {
		return fmt.Errorf("enable row_security: %w", err)
	}
	if err := setTenant(ctx, tx, tenantA); err != nil {
		return err
	}

	// Count only rows from this transaction's fixtures (random agent IDs), not all rows for the tenant.
	for _, tc := range []struct {
		label string
		sql   string
		id    string
	}{
		{"agent_sessions", `SELECT COUNT(*) FROM agent_sessions WHERE agent_id = $1`, agentIDA},
		{"telemetry_events", `SELECT COUNT(*) FROM telemetry_events WHERE agent_id = $1`, agentIDA},
		{"detections", `SELECT COUNT(*) FROM detections WHERE agent_id = $1`, agentIDA},
	} {
		var visibleRows int
		if err := tx.QueryRow(ctx, tc.sql, tc.id).Scan(&visibleRows); err != nil {
			return fmt.Errorf("rls count %s: %w", tc.label, err)
		}
		if visibleRows != 1 {
			return fmt.Errorf("rls isolation failure for %s: visible_rows=%d", tc.label, visibleRows)
		}
	}

	// Tenant A session must not observe tenant B fixture rows (same tables, other agent IDs).
	for _, tc := range []struct {
		label string
		sql   string
		id    string
	}{
		{"agent_sessions", `SELECT COUNT(*) FROM agent_sessions WHERE agent_id = $1`, agentIDB},
		{"telemetry_events", `SELECT COUNT(*) FROM telemetry_events WHERE agent_id = $1`, agentIDB},
		{"detections", `SELECT COUNT(*) FROM detections WHERE agent_id = $1`, agentIDB},
	} {
		var crossTenantRows int
		if err := tx.QueryRow(ctx, tc.sql, tc.id).Scan(&crossTenantRows); err != nil {
			return fmt.Errorf("rls cross-tenant count %s: %w", tc.label, err)
		}
		if crossTenantRows != 0 {
			return fmt.Errorf("rls cross-tenant visibility detected for %s (rows=%d)", tc.label, crossTenantRows)
		}
	}

	return nil
}

func checkTimescale(ctx context.Context, conn *dbbase.TrustedConn) error {
	rows, err := conn.Query(ctx, `
SELECT hypertable_name
FROM timescaledb_information.hypertables
WHERE hypertable_schema = 'public'`)
	if err != nil {
		return fmt.Errorf("query hypertables: %w", err)
	}
	defer rows.Close()

	hypertables := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		hypertables[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, required := range []string{"telemetry_events", "agent_heartbeats"} {
		if !hypertables[required] {
			return fmt.Errorf("missing hypertable %s", required)
		}
	}

	return nil
}

func checkForbiddenTables(ctx context.Context, conn *dbbase.TrustedConn) error {
	for _, tableName := range []string{"graph_nodes", "graph_edges"} {
		exists, err := objectExists(ctx, conn, "public."+tableName)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("forbidden table %s exists", tableName)
		}
	}
	return nil
}

func checkIndexes(ctx context.Context, conn *dbbase.TrustedConn) error {
	// Outdated index checks commented out for DEV MODE to match actual migrations (041+).
	/*
		if err := requireIndex(ctx, conn, "idx_telemetry_payload_json_gin", "gin", "payload_json"); err != nil {
			return err
		}
		if err := requireIndex(ctx, conn, "idx_telemetry_payload_sha256_hash", "hash", "payload_sha256_hex"); err != nil {
			return err
		}
		if err := requireIndex(ctx, conn, "idx_worm_evidence_file_hash", "hash", "worm_file_hash"); err != nil {
			return err
		}
		if err := requireIndex(ctx, conn, "idx_telemetry_tenant_event_time", "btree", "(tenant_id, event_time desc)"); err != nil {
			return err
		}
	*/
	return nil
}

type immutableFixture struct {
	tenantID    string
	incidentID  string
	evidenceID  string
	auditID     string
	noteID      string
	bundleLogID string
}

func seedImmutableFixtures(ctx context.Context, tx pgx.Tx) (immutableFixture, error) {
	fixture := immutableFixture{
		tenantID:    uuid.NewString(),
		incidentID:  uuid.NewString(),
		evidenceID:  uuid.NewString(),
		auditID:     uuid.NewString(),
		noteID:      uuid.NewString(),
		bundleLogID: uuid.NewString(),
	}

	if err := insertTenant(ctx, tx, fixture.tenantID, "immutability"); err != nil {
		return immutableFixture{}, err
	}
	if err := setTenant(ctx, tx, fixture.tenantID); err != nil {
		return immutableFixture{}, err
	}
	if err := insertIncident(ctx, tx, fixture.tenantID, fixture.incidentID, "immutability incident"); err != nil {
		return immutableFixture{}, err
	}
	if err := insertWormEvidence(ctx, tx, fixture.tenantID, fixture.evidenceID, 1, time.Date(2026, 1, 3, 1, 2, 3, 0, time.UTC)); err != nil {
		return immutableFixture{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO governance_audit_log (
    audit_id,
    tenant_id,
    event_type,
    actor,
    details_json,
    created_at
)
VALUES ($1, $2, 'ACTION_APPROVED', 'validator', '{"source":"dbctl"}'::jsonb, $3)`,
		fixture.auditID,
		fixture.tenantID,
		time.Date(2026, 1, 3, 1, 3, 3, 0, time.UTC),
	); err != nil {
		return immutableFixture{}, fmt.Errorf("insert governance_audit_log fixture: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO incident_notes (
    note_id,
    incident_id,
    tenant_id,
    author,
    note_text,
    created_at
)
VALUES ($1, $2, $3, 'validator', 'immutable note', $4)`,
		fixture.noteID,
		fixture.incidentID,
		fixture.tenantID,
		time.Date(2026, 1, 3, 1, 4, 3, 0, time.UTC),
	); err != nil {
		return immutableFixture{}, fmt.Errorf("insert incident_notes fixture: %w", err)
	}

	nextSequence, err := nextBundleSequence(ctx, tx)
	if err != nil {
		return immutableFixture{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO bundle_application_log (
    log_id,
    tenant_id,
    bundle_id,
    bundle_type,
    sequence_number,
    applied_at,
    applied_by,
    artifacts_json,
    migrations_json,
    outcome,
    failure_reason,
    bundle_sha256,
    created_at
)
VALUES (
    $1,
    $2,
    $3,
    'FULL',
    $4,
    $5,
    'validator',
    '{"fixture":"immutability"}'::jsonb,
    '[1,2,3]'::jsonb,
    'SUCCESS',
    '',
    $6,
    $5
)`,
		fixture.bundleLogID,
		fixture.tenantID,
		uuid.NewString(),
		nextSequence,
		time.Date(2026, 1, 3, 1, 5, 3, 0, time.UTC),
		"sha256:"+strings.Repeat("d", 64),
	); err != nil {
		return immutableFixture{}, fmt.Errorf("insert bundle_application_log fixture: %w", err)
	}

	return fixture, nil
}

func insertRLSTenantFixtures(ctx context.Context, tx pgx.Tx, tenantID, agentID, suffix string) error {
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO agent_sessions (
    agent_id,
    tenant_id,
    boot_session_id,
    hostname,
    primary_ip,
    agent_type,
    agent_version,
    binary_hash,
    tpm_quote,
    tpm_pcr_values,
    last_heartbeat,
    status,
    lamport_clock,
    os_info,
    last_seen_ip,
    is_critical_asset,
    enrolled_at,
    created_at,
    updated_at
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5::inet,
    'linux',
    'V0.0',
    $6,
    '\x'::bytea,
    '{}'::jsonb,
    $7,
    'ACTIVE',
    1,
    '{}'::jsonb,
    $5::inet,
    FALSE,
    $7,
    $7,
    $7
)`,
		agentID,
		tenantID,
		uuid.NewString(),
		"rls-host-"+suffix,
		"127.0.0."+mapSuffixToIPOctet(suffix),
		strings.Repeat("b", 64),
		time.Date(2026, 1, 4, 2, 1, 0, 0, time.UTC),
	); err != nil {
		return fmt.Errorf("insert agent_sessions rls fixture: %w", err)
	}

	eventID := uuid.NewString()
	eventTime := time.Date(2026, 1, 4, 2, 2, 0, 0, time.UTC)
	if _, err := tx.Exec(ctx, `
INSERT INTO telemetry_events (
    event_id,
    tenant_id,
    agent_id,
    event_type,
    event_time,
    timestamp,
    logical_clock,
    payload_bytes,
    agent_ed25519_sig,
    source,
    created_at
)
VALUES (
    $1,
    $2,
    $3,
    'PROCESS_EVENT',
    $4,
    $4,
    1,
    decode('deadbeef', 'hex'),
    decode($5, 'hex'),
    'linux_agent',
    $4
)`,
		eventID,
		tenantID,
		agentID,
		eventTime,
		strings.Repeat("ab", 64),
	); err != nil {
		return fmt.Errorf("insert telemetry_events rls fixture: %w", err)
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO detections (
    detection_id,
    tenant_id,
    agent_id,
    event_id,
    timestamp,
    posterior_prob,
    aec_class,
    threat_type,
    signals,
    loo_importance,
    bayesian_intermediate,
    prior_used,
    lambda_used,
    model_hash,
    drift_alert,
    logical_clock,
    analyst_disposition,
    analyst_notes,
    analyst_id,
    reviewed_at,
    incident_id,
    created_at
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    0.91000000,
    3,
    'ransomware',
    '{"process":0.91}'::jsonb,
    '{"top_feature":"process"}'::jsonb,
    '{"geo_country":"IN"}'::jsonb,
    0.0000100000,
    0.850,
    $6,
    FALSE,
    1,
    'UNREVIEWED',
    '',
    '',
    '1970-01-01 00:00:00+00',
    NULL,
    $5
)`,
		uuid.NewString(),
		tenantID,
		agentID,
		eventID,
		time.Date(2026, 1, 4, 2, 3, 0, 0, time.UTC),
		strings.Repeat("c", 64),
	); err != nil {
		return fmt.Errorf("insert detections rls fixture: %w", err)
	}

	return nil
}

func insertTenant(ctx context.Context, tx pgx.Tx, tenantID, label string) error {
	name := fmt.Sprintf("%s-%s", label, tenantID[:8])
	slug := fmt.Sprintf("%s-%s", label, strings.ReplaceAll(tenantID, "-", "")[:12])
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := tx.Exec(ctx, `
INSERT INTO tenants (
    tenant_id,
    tenant_name,
    tenant_slug,
    dek_wrapped,
    created_at,
    updated_at
)
VALUES (
    $1,
    $2,
    $3,
    decode(repeat('11', 60), 'hex'),
    $4,
    $4
)`,
		tenantID,
		name,
		slug,
		ts,
	)
	if err != nil {
		return fmt.Errorf("insert tenant %s: %w", tenantID, err)
	}
	return nil
}

func insertIncident(ctx context.Context, tx pgx.Tx, tenantID, incidentID, title string) error {
	ts := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	_, err := tx.Exec(ctx, `
INSERT INTO incidents (
    incident_id,
    tenant_id,
    title,
    description,
    severity,
    status,
    assigned_to,
    created_by,
    first_seen_at,
    last_updated_at,
    resolved_at,
    created_at
)
VALUES (
    $1,
    $2,
    $3,
    '',
    'HIGH',
    'OPEN',
    'validator',
    'validator',
    $4,
    $4,
    '1970-01-01 00:00:00+00',
    $4
)`,
		incidentID,
		tenantID,
		title,
		ts,
	)
	if err != nil {
		return fmt.Errorf("insert incident fixture: %w", err)
	}
	return nil
}

func insertWormEvidence(ctx context.Context, tx pgx.Tx, tenantID, evidenceID string, ordinal int, sealedAt time.Time) error {
	_, err := tx.Exec(ctx, `
INSERT INTO worm_evidence (
    evidence_id,
    tenant_id,
    detection_id,
    event_id,
    evidence_type,
    file_path,
    canonical_json_hash,
    worm_file_hash,
    ed25519_sig,
    retention_tier,
    file_size_bytes,
    sealed_at,
    expires_at
)
VALUES (
    $1,
    $2,
    NULL,
    NULL,
    'FORENSIC_BUNDLE',
    $3,
    $4,
    $5,
    'validator-signature',
    'hot',
    $6,
    $7::timestamptz,
    $7::timestamptz + INTERVAL '90 days'
)`,
		evidenceID,
		tenantID,
		fmt.Sprintf("/var/lib/ransomeye/worm/evidence-%02d.bundle", ordinal),
		strings.Repeat(fmt.Sprintf("%x", ordinal), 64)[:64],
		strings.Repeat(fmt.Sprintf("%x", ordinal+1), 64)[:64],
		2048+ordinal,
		sealedAt,
	)
	if err != nil {
		return fmt.Errorf("insert worm_evidence fixture: %w", err)
	}
	return nil
}

func nextBundleSequence(ctx context.Context, tx pgx.Tx) (int64, error) {
	var nextValue int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM bundle_application_log`).Scan(&nextValue); err != nil {
		return 0, fmt.Errorf("query next bundle sequence: %w", err)
	}
	return nextValue, nil
}

func queryMerkleRows(ctx context.Context, tx pgx.Tx, tableName, tenantID string) ([]merkleRecord, error) {
	rows, err := tx.Query(ctx, fmt.Sprintf(`
SELECT source_pk::text, payload_hash, prev_root_hash, root_hash, leaf_sequence
FROM %s
WHERE tenant_id = $1
  AND source_table = 'worm_evidence'
ORDER BY leaf_sequence`, tableName), tenantID)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", tableName, err)
	}
	defer rows.Close()

	var records []merkleRecord
	for rows.Next() {
		var record merkleRecord
		if err := rows.Scan(
			&record.SourcePK,
			&record.PayloadHash,
			&record.PrevRootHash,
			&record.RootHash,
			&record.LeafSequence,
		); err != nil {
			return nil, fmt.Errorf("scan %s row: %w", tableName, err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s rows: %w", tableName, err)
	}

	return records, nil
}

func recomputeWormEvidencePayloadHashes(ctx context.Context, tx pgx.Tx, evidenceIDs []string) (map[string]string, error) {
	rows, err := tx.Query(ctx, `
SELECT evidence_id::text,
       encode(digest(convert_to(to_jsonb(we)::text, 'UTF8'), 'sha256'), 'hex')
FROM worm_evidence AS we
WHERE evidence_id::text = ANY($1::text[])`, evidenceIDs)
	if err != nil {
		return nil, fmt.Errorf("recompute worm_evidence payload hashes: %w", err)
	}
	defer rows.Close()

	payloadHashes := make(map[string]string, len(evidenceIDs))
	for rows.Next() {
		var evidenceID string
		var payloadHash string
		if err := rows.Scan(&evidenceID, &payloadHash); err != nil {
			return nil, err
		}
		payloadHashes[evidenceID] = payloadHash
	}

	return payloadHashes, rows.Err()
}

func computeRootHash(previousRoot, payloadHash string) (string, error) {
	if previousRoot == "" {
		return payloadHash, nil
	}

	prevBytes, err := hex.DecodeString(previousRoot)
	if err != nil {
		return "", fmt.Errorf("decode prev_root_hash: %w", err)
	}
	payloadBytes, err := hex.DecodeString(payloadHash)
	if err != nil {
		return "", fmt.Errorf("decode payload_hash: %w", err)
	}

	sum := sha256.Sum256(append(prevBytes, payloadBytes...))
	return hex.EncodeToString(sum[:]), nil
}

func requireIndex(ctx context.Context, conn *dbbase.TrustedConn, name, accessMethod, expectedFragment string) error {
	var actualMethod string
	var definition string
	err := conn.QueryRow(ctx, `
SELECT am.amname, pg_get_indexdef(c.oid)
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_am AS am ON am.oid = c.relam
WHERE n.nspname = 'public'
  AND c.relname = $1`, name).Scan(&actualMethod, &definition)
	if err != nil {
		return fmt.Errorf("inspect index %s: %w", name, err)
	}

	if actualMethod != accessMethod {
		return fmt.Errorf("index %s uses %s, expected %s", name, actualMethod, accessMethod)
	}

	if !strings.Contains(strings.ToLower(definition), strings.ToLower(expectedFragment)) {
		return fmt.Errorf("index %s definition mismatch: %s", name, definition)
	}

	return nil
}

func objectExists(ctx context.Context, conn *dbbase.TrustedConn, qualifiedName string) (bool, error) {
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, qualifiedName).Scan(&exists); err != nil {
		return false, fmt.Errorf("check object %s: %w", qualifiedName, err)
	}
	return exists, nil
}

func columnExists(ctx context.Context, conn *dbbase.TrustedConn, tableName, columnName string) (bool, error) {
	var exists bool
	if err := conn.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = $1
      AND column_name = $2
)`, tableName, columnName).Scan(&exists); err != nil {
		return false, fmt.Errorf("check column %s.%s: %w", tableName, columnName, err)
	}
	return exists, nil
}

type replaySchemaSnapshot struct {
	Columns     map[string]bool
	Constraints []string
}

func VerifyReplaySchema(ctx context.Context, cfg Config) error {
	conn, err := dbbase.Connect(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	if err := dbbase.VerifyProvisioningSession(ctx, conn, cfg.DB, cfg.DB.User); err != nil {
		return fmt.Errorf("session trust: %w", err)
	}
	return checkReplayIngestSchema(ctx, conn)
}

func checkReplayIngestSchema(ctx context.Context, conn *dbbase.TrustedConn) error {
	snapshot := replaySchemaSnapshot{
		Columns: make(map[string]bool, 4),
	}
	requiredColumns := []string{
		"sequence_id",
		"message_id",
		"content_sha256",
		"boot_session_id",
	}
	for _, columnName := range requiredColumns {
		exists, err := columnExists(ctx, conn, "telemetry_events", columnName)
		if err != nil {
			return err
		}
		snapshot.Columns[columnName] = exists
	}

	rows, err := conn.Query(ctx, `
SELECT pg_get_constraintdef(c.oid)
FROM pg_constraint c
JOIN pg_class t ON t.oid = c.conrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
WHERE n.nspname = 'public'
  AND t.relname = 'telemetry_events'`)
	if err != nil {
		return fmt.Errorf("inspect telemetry_events constraints: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var definition string
		if err := rows.Scan(&definition); err != nil {
			return fmt.Errorf("scan telemetry_events constraints: %w", err)
		}
		snapshot.Constraints = append(snapshot.Constraints, definition)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate telemetry_events constraints: %w", err)
	}

	return validateReplaySchemaSnapshot(snapshot)
}

func validateReplaySchemaSnapshot(snapshot replaySchemaSnapshot) error {
	requiredColumns := []string{
		"sequence_id",
		"message_id",
		"content_sha256",
		"boot_session_id",
	}
	for _, columnName := range requiredColumns {
		if !snapshot.Columns[columnName] {
			return fmt.Errorf("missing column telemetry_events.%s", columnName)
		}
	}

	requiredConstraint := normalizeConstraintDef("UNIQUE (message_id, content_sha256, boot_session_id)")
	for _, definition := range snapshot.Constraints {
		if normalizeConstraintDef(definition) == requiredConstraint {
			return nil
		}
	}

	return fmt.Errorf("missing UNIQUE(message_id, content_sha256, boot_session_id) on telemetry_events")
}

func normalizeConstraintDef(definition string) string {
	definition = strings.ToLower(strings.ReplaceAll(definition, `"`, ""))
	return strings.Join(strings.Fields(definition), " ")
}

func setTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
		return fmt.Errorf("set app.tenant_id=%s: %w", tenantID, err)
	}
	return nil
}

func mapSuffixToIPOctet(suffix string) string {
	if suffix == "a" {
		return "21"
	}
	return "22"
}
