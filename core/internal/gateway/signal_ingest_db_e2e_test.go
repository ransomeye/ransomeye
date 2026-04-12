package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"ransomeye/core/internal/storage/authority"
	pb "ransomeye/proto/ransomeyepb"
)

func TestSendSignal_DB_E2E_AcceptedCommitCoupling(t *testing.T) {
	pool := requireReplayDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	partitionID := int64(99201)
	logicalShardID := randomBytes(t, 32)
	cleanupPartitionRows(t, ctx, pool, partitionID)

	emitterPub, emitterPriv, _ := ed25519.GenerateKey(rand.Reader)
	emitterIDHex := hex.EncodeToString(truncate16(t, emitterPub))
	setupTrustSnapshotForEmitter(t, ctx, pool, emitterIDHex, emitterPub, emitterPriv, uniqueTrustVersion(t))
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", fmt.Sprintf("%d", partitionID))
	t.Setenv("RANSOMEYE_PRD13_LOGICAL_SHARD_ID", hex.EncodeToString(logicalShardID))

	h := NewHandlers(nil, nil, nil)
	h.SetDBPool(pool)
	commitPub, commitPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.SetPRD13CommitSigner(commitPriv, hex.EncodeToString(commitPub), 1)

	req := validSignalRequest(t)
	setSignalRequestEmitterAndSignature(t, h, &req, emitterIDHex, emitterPriv)

	ack, err := h.SendSignal(ctx, &req)
	if err != nil {
		t.Fatalf("SendSignal: %v", err)
	}
	if !ack.GetAccepted() {
		t.Fatal("accepted=false")
	}

	messageID, err := hex.DecodeString(req.MessageId)
	if err != nil {
		t.Fatalf("decode message_id: %v", err)
	}
	var partitionRecordCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM partition_records WHERE partition_id = $1 AND message_id = $2`, partitionID, messageID).Scan(&partitionRecordCount); err != nil {
		t.Fatalf("partition_records count: %v", err)
	}
	if partitionRecordCount != 1 {
		t.Fatalf("partition_records count=%d want=1", partitionRecordCount)
	}
	var replayGuardCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM replay_guard WHERE partition_id = $1 AND message_id = $2`, partitionID, messageID).Scan(&replayGuardCount); err != nil {
		t.Fatalf("replay_guard count: %v", err)
	}
	if replayGuardCount != 1 {
		t.Fatalf("replay_guard count=%d want=1", replayGuardCount)
	}
	var commitCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&commitCount); err != nil {
		t.Fatalf("batch_commit_records count: %v", err)
	}
	if commitCount != 1 {
		t.Fatalf("batch_commit_records count=%d want=1", commitCount)
	}
	var uncoupledCount int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)
FROM partition_records pr
LEFT JOIN batch_commit_records b
  ON b.partition_id = pr.partition_id
 AND pr.partition_record_seq BETWEEN b.first_partition_record_seq AND b.last_partition_record_seq
WHERE pr.partition_id = $1
  AND pr.message_id = $2
  AND b.partition_id IS NULL`, partitionID, messageID).Scan(&uncoupledCount); err != nil {
		t.Fatalf("commit coupling check: %v", err)
	}
	if uncoupledCount != 0 {
		t.Fatalf("uncoupled partition_records=%d want=0", uncoupledCount)
	}

	var schemaTransformHex string
	var executionContextHex string
	if err := pool.QueryRow(ctx, `
SELECT encode(schema_transform_hash, 'hex'), encode(execution_context_hash, 'hex')
FROM partition_records
WHERE partition_id = $1 AND message_id = $2
LIMIT 1`, partitionID, messageID).Scan(&schemaTransformHex, &executionContextHex); err != nil {
		t.Fatalf("schema/execution hash read: %v", err)
	}
	if schemaTransformHex == "" || schemaTransformHex == strings.Repeat("0", 64) {
		t.Fatalf("schema_transform_hash missing or zero: %q", schemaTransformHex)
	}
	execBytes, err := hex.DecodeString(executionContextHex)
	if err != nil || len(execBytes) != 32 {
		t.Fatalf("execution_context_hash decode: %q err=%v", executionContextHex, err)
	}
	var execHash [32]byte
	copy(execHash[:], execBytes)
	wantSchemaTransform := authority.SchemaTransformHash("signal_schema_v1", execHash)
	if schemaTransformHex != hex.EncodeToString(wantSchemaTransform[:]) {
		t.Fatalf("schema_transform_hash=%s want=%x", schemaTransformHex, wantSchemaTransform)
	}
}

func TestSendSignal_DB_E2E_RejectedDoesNotAdmit(t *testing.T) {
	pool := requireReplayDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	partitionID := int64(99202)
	logicalShardID := randomBytes(t, 32)
	cleanupPartitionRows(t, ctx, pool, partitionID)

	emitterPub, emitterPriv, _ := ed25519.GenerateKey(rand.Reader)
	emitterIDHex := hex.EncodeToString(truncate16(t, emitterPub))
	setupTrustSnapshotForEmitter(t, ctx, pool, emitterIDHex, emitterPub, emitterPriv, uniqueTrustVersion(t))
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", fmt.Sprintf("%d", partitionID))
	t.Setenv("RANSOMEYE_PRD13_LOGICAL_SHARD_ID", hex.EncodeToString(logicalShardID))

	h := NewHandlers(nil, nil, nil)
	h.SetDBPool(pool)
	commitPub, commitPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.SetPRD13CommitSigner(commitPriv, hex.EncodeToString(commitPub), 1)

	base := validSignalRequest(t)
	base.LogicalClock = 0
	setSignalRequestEmitterAndSignature(t, h, &base, emitterIDHex, emitterPriv)
	if _, err := h.SendSignal(ctx, &base); err != nil {
		t.Fatalf("initial accept: %v", err)
	}

	// Do not shallow-copy protos (Mutex in MessageState): clone after use so variants see stable fields.
	baseline := proto.Clone(&base).(*pb.SignalEnvelope)

	before := countPartitionRecordsByPartition(t, ctx, pool, partitionID)

	dup := proto.Clone(baseline).(*pb.SignalEnvelope)
	_, err := h.SendSignal(ctx, dup)
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "REJECT_DUPLICATE") {
		t.Fatalf("duplicate expected REJECT_DUPLICATE, got %v", err)
	}
	if got := countPartitionRecordsByPartition(t, ctx, pool, partitionID); got != before {
		t.Fatalf("duplicate admitted records: got=%d want=%d", got, before)
	}

	gap := proto.Clone(baseline).(*pb.SignalEnvelope)
	gap.LogicalClock = 2
	setSignalRequestEmitterAndSignature(t, h, gap, emitterIDHex, emitterPriv)
	if gap.MessageId == baseline.MessageId {
		t.Fatalf("gap message_id not recomputed")
	}
	_, err = h.SendSignal(ctx, gap)
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "REJECT_GAP") {
		t.Fatalf("gap expected REJECT_GAP, got %v", err)
	}
	if got := countPartitionRecordsByPartition(t, ctx, pool, partitionID); got != before {
		t.Fatalf("gap admitted records: got=%d want=%d", got, before)
	}

	next := proto.Clone(baseline).(*pb.SignalEnvelope)
	next.LogicalClock = 1
	setSignalRequestEmitterAndSignature(t, h, next, emitterIDHex, emitterPriv)
	if next.MessageId == baseline.MessageId {
		t.Fatalf("next message_id not recomputed")
	}
	if _, err := h.SendSignal(ctx, next); err != nil {
		t.Fatalf("logical_clock=1 accept: %v", err)
	}
	before = countPartitionRecordsByPartition(t, ctx, pool, partitionID)

	// Committed cursor is now lc=1; resend the original lc=0 envelope (still cryptographically valid).
	// Replay gate must reject as REJECT_REGRESSION (0 < 1), not hash_mismatch.
	reg := proto.Clone(baseline).(*pb.SignalEnvelope)
	_, err = h.SendSignal(ctx, reg)
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "REJECT_REGRESSION") {
		t.Fatalf("regression expected REJECT_REGRESSION, got %v", err)
	}
	if got := countPartitionRecordsByPartition(t, ctx, pool, partitionID); got != before {
		t.Fatalf("regression admitted records: got=%d want=%d", got, before)
	}
}

func TestSendSignal_DB_E2E_Type2_DBAvailabilityFailure_NoAuthoritativeWrite(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set - skipping DB-backed Type2 test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	mainPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("main pool: %v", err)
	}
	defer mainPool.Close()
	obsPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("observer pool: %v", err)
	}
	defer obsPool.Close()

	partitionID := int64(99203)
	logicalShardID := randomBytes(t, 32)
	cleanupPartitionRows(t, ctx, obsPool, partitionID)

	emitterPub, emitterPriv, _ := ed25519.GenerateKey(rand.Reader)
	emitterIDHex := hex.EncodeToString(truncate16(t, emitterPub))
	setupTrustSnapshotForEmitter(t, ctx, obsPool, emitterIDHex, emitterPub, emitterPriv, uniqueTrustVersion(t))
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", fmt.Sprintf("%d", partitionID))
	t.Setenv("RANSOMEYE_PRD13_LOGICAL_SHARD_ID", hex.EncodeToString(logicalShardID))

	h := NewHandlers(nil, nil, nil)
	h.SetDBPool(mainPool)
	commitPub, commitPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.SetPRD13CommitSigner(commitPriv, hex.EncodeToString(commitPub), 1)

	req := validSignalRequest(t)
	setSignalRequestEmitterAndSignature(t, h, &req, emitterIDHex, emitterPriv)

	before := countPartitionRecordsByPartition(t, ctx, obsPool, partitionID)
	mainPool.Close() // live DB availability failure for runtime pool
	_, err = h.SendSignal(ctx, &req)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Type2/Unavailable, got %v", err)
	}
	after := countPartitionRecordsByPartition(t, ctx, obsPool, partitionID)
	if after != before {
		t.Fatalf("fault path wrote authoritative rows: before=%d after=%d", before, after)
	}
}

func TestSendSignal_DB_E2E_Type3_CorruptCommittedTrustSnapshot_NoAuthoritativeWrite(t *testing.T) {
	pool := requireReplayDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	partitionID := int64(99204)
	logicalShardID := randomBytes(t, 32)
	cleanupPartitionRows(t, ctx, pool, partitionID)

	emitterPub, emitterPriv, _ := ed25519.GenerateKey(rand.Reader)
	emitterIDHex := hex.EncodeToString(truncate16(t, emitterPub))
	setupTrustSnapshotForEmitter(t, ctx, pool, emitterIDHex, emitterPub, emitterPriv, uniqueTrustVersion(t))
	corruptVersion := authority.GatewaySignalE2ECorruptTrustVersionPrefix + hex.EncodeToString(randomBytes(t, 8))
	insertCorruptTrustSnapshot(t, ctx, pool, corruptVersion)

	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", fmt.Sprintf("%d", partitionID))
	t.Setenv("RANSOMEYE_PRD13_LOGICAL_SHARD_ID", hex.EncodeToString(logicalShardID))
	h := NewHandlers(nil, nil, nil)
	h.SetDBPool(pool)
	commitPub, commitPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.SetPRD13CommitSigner(commitPriv, hex.EncodeToString(commitPub), 1)

	req := validSignalRequest(t)
	setSignalRequestEmitterAndSignature(t, h, &req, emitterIDHex, emitterPriv)

	before := countPartitionRecordsByPartition(t, ctx, pool, partitionID)
	_, err := h.SendSignal(ctx, &req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected Type3/PermissionDenied, got %v", err)
	}
	after := countPartitionRecordsByPartition(t, ctx, pool, partitionID)
	if after != before {
		t.Fatalf("fault path wrote authoritative rows: before=%d after=%d", before, after)
	}
}

func TestSendSignal_DB_E2E_Type2_StageWriteTimeout_NoAuthoritativeResidue(t *testing.T) {
	type stageCase struct {
		name        string
		lockTable   string
		skipMessage string
	}
	cases := []stageCase{
		{name: "partition_records", lockTable: "partition_records", skipMessage: "POSTGRES_DSN not set - skipping DB-backed admit-stage Type2 test"},
		{name: "batch_commit_records", lockTable: "batch_commit_records", skipMessage: "POSTGRES_DSN not set - skipping DB-backed batch_commit_records Type2 test"},
		{name: "batch_commit_authority_bindings", lockTable: "batch_commit_authority_bindings", skipMessage: "POSTGRES_DSN not set - skipping DB-backed bindings-stage Type2 test"},
		{name: "replay_guard", lockTable: "replay_guard", skipMessage: "POSTGRES_DSN not set - skipping DB-backed replay_guard Type2 test"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runSendSignalStageTimeoutCase(t, tc.lockTable, int64(99205+i), tc.skipMessage)
		})
	}
}

func runSendSignalStageTimeoutCase(t *testing.T, lockTable string, partitionID int64, skipMessage string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip(skipMessage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mainCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	// Keep timeout tight so a write blocked by table lock fails deterministically.
	mainCfg.ConnConfig.RuntimeParams["statement_timeout"] = "200ms"
	mainPool, err := pgxpool.NewWithConfig(ctx, mainCfg)
	if err != nil {
		t.Fatalf("main pool: %v", err)
	}
	defer mainPool.Close()

	obsPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("observer pool: %v", err)
	}
	defer obsPool.Close()

	logicalShardID := randomBytes(t, 32)
	cleanupPartitionRows(t, ctx, obsPool, partitionID)

	emitterPub, emitterPriv, _ := ed25519.GenerateKey(rand.Reader)
	emitterIDHex := hex.EncodeToString(truncate16(t, emitterPub))
	setupTrustSnapshotForEmitter(t, ctx, obsPool, emitterIDHex, emitterPub, emitterPriv, uniqueTrustVersion(t))
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", fmt.Sprintf("%d", partitionID))
	t.Setenv("RANSOMEYE_PRD13_LOGICAL_SHARD_ID", hex.EncodeToString(logicalShardID))

	h := NewHandlers(nil, nil, nil)
	h.SetDBPool(mainPool)
	commitPub, commitPriv, _ := ed25519.GenerateKey(rand.Reader)
	h.SetPRD13CommitSigner(commitPriv, hex.EncodeToString(commitPub), 1)

	req := validSignalRequest(t)
	setSignalRequestEmitterAndSignature(t, h, &req, emitterIDHex, emitterPriv)

	beforePartition := countPartitionRecordsByPartition(t, ctx, obsPool, partitionID)
	beforeReplay := countReplayGuardByPartition(t, ctx, obsPool, partitionID)
	beforeCommit := countBatchCommitRecordsByPartition(t, ctx, obsPool, partitionID)
	beforeBindings := countBatchCommitAuthorityBindingsByPartition(t, ctx, obsPool, partitionID)

	lockConn, err := obsPool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire lock conn: %v", err)
	}
	releaseLockConn := func() {
		if lockConn == nil {
			return
		}
		_, _ = lockConn.Exec(context.Background(), `ROLLBACK`)
		lockConn.Release()
		lockConn = nil
	}
	defer releaseLockConn()
	if _, err := lockConn.Exec(ctx, `BEGIN`); err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	if _, err := lockConn.Exec(ctx, fmt.Sprintf("LOCK TABLE %s IN ACCESS EXCLUSIVE MODE", lockTable)); err != nil {
		t.Fatalf("lock %s: %v", lockTable, err)
	}

	_, err = h.SendSignal(ctx, &req)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Type2/Unavailable at %s stage, got %v", lockTable, err)
	}
	// ACCESS EXCLUSIVE blocks concurrent reads on the same table; release before residue counts.
	releaseLockConn()

	afterPartition := countPartitionRecordsByPartition(t, ctx, obsPool, partitionID)
	afterReplay := countReplayGuardByPartition(t, ctx, obsPool, partitionID)
	afterCommit := countBatchCommitRecordsByPartition(t, ctx, obsPool, partitionID)
	afterBindings := countBatchCommitAuthorityBindingsByPartition(t, ctx, obsPool, partitionID)
	if afterPartition != beforePartition || afterReplay != beforeReplay || afterCommit != beforeCommit || afterBindings != beforeBindings {
		t.Fatalf(
			"%s fault left authoritative residue: partition %d->%d replay %d->%d commit %d->%d bindings %d->%d",
			lockTable,
			beforePartition, afterPartition,
			beforeReplay, afterReplay,
			beforeCommit, afterCommit,
			beforeBindings, afterBindings,
		)
	}
}

func setupTrustSnapshotForEmitter(t *testing.T, ctx context.Context, pool *pgxpool.Pool, emitterIDHex string, emitterPub ed25519.PublicKey, emitterPriv ed25519.PrivateKey, trustVersion string) {
	t.Helper()
	cleanupSignalE2EPartitionRange(t, ctx, pool)
	if _, err := pool.Exec(ctx, `
DELETE FROM authority_snapshots
WHERE authority_type = 'CONFIG' AND authority_id = 'trust_snapshot'
  AND (authority_version LIKE $1 OR authority_version LIKE $2)`,
		authority.GatewaySignalE2ETrustVersionPrefix+"%",
		authority.GatewaySignalE2ECorruptTrustVersionPrefix+"%",
	); err != nil {
		t.Fatalf("cleanup trust snapshots: %v", err)
	}
	keyEpoch := int64(1)
	keyType := "AGENT"
	keyID := deriveKeyID(t, keyType, emitterIDHex, keyEpoch, emitterPub)
	keyRecordSigningContext := "key_record_v1"
	recordPayload := map[string]any{
		"allowed_signing_contexts": []any{"ransomeye:v1:telemetry:event", "config_snapshot_v1", keyRecordSigningContext},
		"authority_scope":          "emitter",
		"issuer_key_id":            keyID,
		"key_epoch":                keyEpoch,
		"key_id":                   keyID,
		"key_type":                 keyType,
		"public_key":               hex.EncodeToString(emitterPub),
		"scope_id":                 emitterIDHex,
		"signing_context":          keyRecordSigningContext,
		"status":                   "ACTIVE",
	}
	canonicalKeyRecordPayload, err := authority.JCSCanonicalJSONBytes(recordPayload)
	if err != nil {
		t.Fatalf("canonical key record payload: %v", err)
	}
	keyRecordHash := sha256.Sum256(canonicalKeyRecordPayload)
	keyRecordSigningInput := append([]byte(keyRecordSigningContext), keyRecordHash[:]...)
	keyRecordSignature := ed25519.Sign(emitterPriv, keyRecordSigningInput)
	keyRecord := map[string]any{
		"allowed_signing_contexts": []any{"ransomeye:v1:telemetry:event", "config_snapshot_v1", keyRecordSigningContext},
		"authority_scope":          "emitter",
		"issuer_key_id":            keyID,
		"key_epoch":                keyEpoch,
		"key_id":                   keyID,
		"key_type":                 keyType,
		"public_key":               hex.EncodeToString(emitterPub),
		"scope_id":                 emitterIDHex,
		"signing_context":          keyRecordSigningContext,
		"signature":                hex.EncodeToString(keyRecordSignature),
		"status":                   "ACTIVE",
	}
	trustPayload := map[string]any{
		"key_epoch":            keyEpoch,
		"key_id":               keyID,
		"key_records":          []any{keyRecord},
		"signing_context":      "config_snapshot_v1",
		"verification_scope_id": "signal_e2e_scope",
	}
	canonicalTrustPayload, err := authority.JCSCanonicalJSONBytes(trustPayload)
	if err != nil {
		t.Fatalf("canonical trust snapshot payload: %v", err)
	}
	trustPayloadHash := sha256.Sum256(canonicalTrustPayload)
	trustSigningInput := append([]byte("config_snapshot_v1"), trustPayloadHash[:]...)
	trustSignature := ed25519.Sign(emitterPriv, trustSigningInput)
	if _, err := pool.Exec(ctx, `
INSERT INTO authority_snapshots (authority_type, authority_id, authority_version, canonical_payload_text, payload_hash, signature)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT DO NOTHING`,
		"CONFIG",
		"trust_snapshot",
		trustVersion,
		string(canonicalTrustPayload),
		trustPayloadHash[:],
		trustSignature,
	); err != nil {
		t.Fatalf("insert trust_snapshot: %v", err)
	}

	bindings, err := json.Marshal([]map[string]string{{
		"type":    "CONFIG",
		"id":      "trust_snapshot",
		"version": trustVersion,
	}})
	if err != nil {
		t.Fatalf("marshal authority bindings: %v", err)
	}
	snapshots, err := json.Marshal([]map[string]string{{
		"type":                   "CONFIG",
		"id":                     "trust_snapshot",
		"version":                trustVersion,
		"canonical_payload_text": string(canonicalTrustPayload),
		"payload_hash_hex":       hex.EncodeToString(trustPayloadHash[:]),
		"signature_hex":          hex.EncodeToString(trustSignature),
	}})
	if err != nil {
		t.Fatalf("marshal authority snapshots: %v", err)
	}
	t.Setenv("RANSOMEYE_PRD13_AUTHORITY_BINDINGS_JSON", string(bindings))
	t.Setenv("RANSOMEYE_PRD13_AUTHORITY_SNAPSHOTS_JSON", string(snapshots))
}

func insertCorruptTrustSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, version string) {
	t.Helper()
	// valid JSON but deliberately non-canonical and semantically incomplete for trust snapshot parser.
	payload := " {\"broken\":true} "
	sum := sha256.Sum256([]byte(payload))
	sig := randomBytes(t, ed25519.SignatureSize)
	if _, err := pool.Exec(ctx, `
INSERT INTO authority_snapshots (authority_type, authority_id, authority_version, canonical_payload_text, payload_hash, signature)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT DO NOTHING`,
		"CONFIG", "trust_snapshot", version, payload, sum[:], sig,
	); err != nil {
		t.Fatalf("insert corrupt trust snapshot: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authority_snapshots WHERE authority_type='CONFIG' AND authority_id='trust_snapshot' AND authority_version=$1`, version)
	})
}

func deriveKeyID(t *testing.T, keyType, scopeID string, keyEpoch int64, pub ed25519.PublicKey) string {
	t.Helper()
	h := sha256.New()
	_, _ = h.Write([]byte(keyType))
	_, _ = h.Write([]byte(scopeID))
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], uint64(keyEpoch))
	_, _ = h.Write(be[:])
	_, _ = h.Write(pub)
	return hex.EncodeToString(h.Sum(nil))
}

func truncate16(t *testing.T, b []byte) []byte {
	t.Helper()
	if len(b) < 16 {
		t.Fatalf("need >=16 bytes")
	}
	return append([]byte(nil), b[:16]...)
}

func cleanupPartitionRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, partitionID int64) {
	t.Helper()
	_, _ = pool.Exec(ctx, `DELETE FROM replay_guard WHERE partition_id = $1`, partitionID)
	_, _ = pool.Exec(ctx, `DELETE FROM batch_commit_authority_bindings WHERE partition_id = $1`, partitionID)
	_, _ = pool.Exec(ctx, `DELETE FROM batch_commit_records WHERE partition_id = $1`, partitionID)
	_, _ = pool.Exec(ctx, `DELETE FROM partition_records WHERE partition_id = $1`, partitionID)
}

// cleanupSignalE2EPartitionRange removes authoritative residue for all partition IDs used by this file
// so CONFIG/trust_snapshot rows can be reset without FK violations from batch_commit_authority_bindings.
func cleanupSignalE2EPartitionRange(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for pid := int64(99201); pid <= 99210; pid++ {
		cleanupPartitionRows(t, ctx, pool, pid)
	}
}

func countPartitionRecordsByPartition(t *testing.T, ctx context.Context, pool *pgxpool.Pool, partitionID int64) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM partition_records WHERE partition_id = $1`, partitionID).Scan(&count); err != nil {
		t.Fatalf("count partition_records: %v", err)
	}
	return count
}

func countReplayGuardByPartition(t *testing.T, ctx context.Context, pool *pgxpool.Pool, partitionID int64) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM replay_guard WHERE partition_id = $1`, partitionID).Scan(&count); err != nil {
		t.Fatalf("count replay_guard: %v", err)
	}
	return count
}

func countBatchCommitRecordsByPartition(t *testing.T, ctx context.Context, pool *pgxpool.Pool, partitionID int64) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM batch_commit_records WHERE partition_id = $1`, partitionID).Scan(&count); err != nil {
		t.Fatalf("count batch_commit_records: %v", err)
	}
	return count
}

func countBatchCommitAuthorityBindingsByPartition(t *testing.T, ctx context.Context, pool *pgxpool.Pool, partitionID int64) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM batch_commit_authority_bindings WHERE partition_id = $1`, partitionID).Scan(&count); err != nil {
		t.Fatalf("count batch_commit_authority_bindings: %v", err)
	}
	return count
}

func uniqueTrustVersion(t *testing.T) string {
	t.Helper()
	raw := randomBytes(t, 6)
	return fmt.Sprintf("%s%d_%s", authority.GatewaySignalE2ETrustVersionPrefix, time.Now().UnixNano(), hex.EncodeToString(raw))
}

func recomputeSignalPartitionContextHex(t *testing.T, canonicalPayload []byte, systemID string, identityVersion uint32, emitterType pb.EmitterType, emitterIDHex string) string {
	t.Helper()
	systemBytes, err := hex.DecodeString(systemID)
	if err != nil || len(systemBytes) != 32 {
		t.Fatalf("decode system_id: %v", err)
	}
	emitterBytes, err := hex.DecodeString(emitterIDHex)
	if err != nil || len(emitterBytes) != 16 {
		t.Fatalf("decode emitter_id: %v", err)
	}
	identityBytes := buildIdentityBytes(systemBytes, byte(identityVersion), emitterType, emitterBytes)
	pcSum := sha256.Sum256(append(append([]byte(nil), canonicalPayload...), identityBytes...))
	return hex.EncodeToString(pcSum[:16])
}

func setSignalRequestEmitterAndSignature(t *testing.T, h *Handlers, req *pb.SignalEnvelope, emitterIDHex string, emitterPriv ed25519.PrivateKey) {
	t.Helper()
	if h == nil || req == nil {
		t.Fatal("nil handler/request")
	}
	req.EmitterId = emitterIDHex
	req.PartitionContext = recomputeSignalPartitionContextHex(t, req.CanonicalPayloadJson, req.SystemId, req.IdentityVersion, req.EmitterType, emitterIDHex)
	mid, err := h.recomputeMessageID(req)
	if err != nil {
		t.Fatalf("recompute message_id: %v", err)
	}
	req.MessageId = mid
	sigInput, err := h.recomputeSigningInput(req)
	if err != nil {
		t.Fatalf("recompute signing input: %v", err)
	}
	req.Signature = ed25519.Sign(emitterPriv, sigInput)
}
