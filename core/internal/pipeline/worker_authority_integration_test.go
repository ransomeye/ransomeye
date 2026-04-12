// Phase 1 acceptance (authoritative Mishka kernel): run with a reachable Postgres and POSTGRES_DSN set:
//
//	go test ./core/internal/pipeline -run TestPRD13CommitWiredIntoPersistenceHotPath -count=1
//
// This exercises authority.CommitPartitionBatchTx on the real persistence hot path (batch_commit_records,
// replay_guard, execution_context_hash). The in-package zero-loss tests prove queue/durable admission only.
package pipeline

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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"ransomeye/core/internal/ack"
	wormcrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/storage"
	"ransomeye/core/internal/storage/authority"
)

func TestPRD13CommitWiredIntoPersistenceHotPath(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set — skipping DB integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	defer pool.Close()

	_, _ = pool.Exec(ctx, `DELETE FROM replay_guard WHERE partition_id = 1`)
	_, _ = pool.Exec(ctx, `DELETE FROM batch_commit_authority_bindings WHERE partition_id = 1`)
	_, _ = pool.Exec(ctx, `DELETE FROM batch_commit_records WHERE partition_id = 1`)
	_, _ = pool.Exec(ctx, `DELETE FROM partition_records WHERE partition_id = 1`)

	tmp := t.TempDir()
	t.Setenv("WORM_STORAGE_PATH", filepath.Join(tmp, "worm"))
	t.Setenv("RANSOMEYE_REPLAY_GUARD_SOURCE", "committed")
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "1")
	t.Setenv("RANSOMEYE_PRD13_LOGICAL_SHARD_ID", strings.Repeat("00", 32))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	agentID := uuid.New()
	emitterIDHex := hex.EncodeToString(agentID[:])
	trustVersion := fmt.Sprintf("~%d_worker_auth_test_%s", time.Now().UnixNano(), strings.ReplaceAll(agentID.String(), "-", ""))
	seedTrustSnapshotWorkerIntegration(t, ctx, pool, emitterIDHex, pub, priv, trustVersion)
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("aes: %v", err)
	}
	w, err := wormcrypto.NewWORM(priv, aesKey)
	if err != nil {
		t.Fatalf("worm: %v", err)
	}

	systemIdentityHash := "systemhash"
	bootID := uuid.New()
	messageID := uuid.New()

	logicalShardID := make([]byte, 32)

	payload := make([]byte, ingest.CanonicalTelemetryV1Size)
	for i := range payload {
		payload[i] = byte(i)
	}
	contentSHA := sha256.Sum256(payload)

	ev := &ingest.VerifiedTelemetry{
		Payload:        payload,
		AgentSignature: make([]byte, ed25519.SignatureSize),
		AgentIDStr:     agentID.String(),
		EventType:      "USER_EVENT",
		SourceType:     "agent",
		TimestampUnix:  float64(time.Now().Unix()),
		LogicalClock:   1,
	}

	meta := ack.Metadata{
		ReplayKey:     strings.Join([]string{systemIdentityHash, agentID.String(), bootID.String(), messageID.String()}, "|"),
		MessageID:     messageID.String(),
		ContentSHA256: contentSHA,
	}

	worker := &WorkerPool{
		DB:                 &storage.DB{Pool: pool},
		WORM:               w,
		Source:             "linux_agent",
		SourceType:         "agent",
		PRD13CommitKey:      priv,
		PRD13CommitKeyID:    hex.EncodeToString(pub),
		PRD13CommitKeyEpoch: 1,
	}

	_, err = worker.insertTelemetryAndWORM(ctx, 1, meta, ev)
	if err != nil {
		t.Fatalf("persist: %v", err)
	}

	var commitCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM batch_commit_records WHERE partition_id = 1`).Scan(&commitCount); err != nil {
		t.Fatalf("batch_commit_records count: %v", err)
	}
	if commitCount < 1 {
		t.Fatalf("batch_commit_records count=%d want>=1", commitCount)
	}

	// Assert commit-time authority bindings exist for the committed batch.
	var batchSeq int64
	if err := pool.QueryRow(ctx, `SELECT MAX(batch_commit_seq) FROM batch_commit_records WHERE partition_id = 1`).Scan(&batchSeq); err != nil {
		t.Fatalf("load batch_commit_seq: %v", err)
	}
	var bindCount int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)
FROM batch_commit_authority_bindings
WHERE partition_id = 1 AND batch_commit_seq = $1
  AND authority_type = 'CONFIG'
  AND authority_id = 'trust_snapshot'
  AND authority_version = $2`, batchSeq, trustVersion).Scan(&bindCount); err != nil {
		t.Fatalf("bindings count: %v", err)
	}
	if bindCount != 1 {
		t.Fatalf("bindings count=%d want=1", bindCount)
	}
	var storedPH []byte
	if err := pool.QueryRow(ctx, `
SELECT payload_hash
FROM authority_snapshots
WHERE authority_type = 'CONFIG' AND authority_id = 'trust_snapshot' AND authority_version = $1`, trustVersion).Scan(&storedPH); err != nil {
		t.Fatalf("authority snapshot missing: %v", err)
	}
	if len(storedPH) != 32 {
		t.Fatalf("authority payload_hash length")
	}

	// Assert committed execution_context_hash matches deterministic recompute from bound authority inputs.
	if err := authority.VerifyBatchExecutionContextHash(ctx, pool, 1, batchSeq); err != nil {
		t.Fatalf("execution_context_hash verify: %v", err)
	}

	var encTransform string
	if err := pool.QueryRow(ctx, `
SELECT encode(schema_transform_hash, 'hex')
FROM partition_records
WHERE partition_id = 1
ORDER BY partition_record_seq DESC
LIMIT 1`).Scan(&encTransform); err != nil {
		t.Fatalf("schema_transform_hash read: %v", err)
	}
	if encTransform == "" || encTransform == strings.Repeat("0", 64) {
		t.Fatalf("schema_transform_hash missing or zero: %q", encTransform)
	}
	var execHex string
	if err := pool.QueryRow(ctx, `
SELECT encode(execution_context_hash, 'hex')
FROM partition_records
WHERE partition_id = 1
ORDER BY partition_record_seq DESC
LIMIT 1`).Scan(&execHex); err != nil {
		t.Fatalf("execution_context_hash read: %v", err)
	}
	execBytes, err := hex.DecodeString(execHex)
	if err != nil || len(execBytes) != 32 {
		t.Fatalf("execution_context_hash hex: %q err=%v", execHex, err)
	}
	var execHash [32]byte
	copy(execHash[:], execBytes)
	wantST := authority.SchemaTransformHash("telemetry_v1", execHash)
	if encTransform != hex.EncodeToString(wantST[:]) {
		t.Fatalf("schema_transform_hash=%s want=%x", encTransform, wantST)
	}

	var rgCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM replay_guard WHERE partition_id = 1 AND logical_shard_id = $1 AND message_id = $2 AND seen_state = 'ADMITTED'`, logicalShardID, messageID[:]).Scan(&rgCount); err != nil {
		t.Fatalf("replay_guard count: %v", err)
	}
	if rgCount != 1 {
		t.Fatalf("replay_guard count=%d want=1", rgCount)
	}

	recovered, err := authority.LoadCommittedReplaySeen(ctx, pool, 1, logicalShardID, systemIdentityHash)
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	key := strings.Join([]string{systemIdentityHash, agentID.String(), bootID.String(), messageID.String()}, "|")
	got, ok := recovered[key]
	if !ok {
		t.Fatalf("missing recovered replay key")
	}
	if got != contentSHA {
		t.Fatalf("recovered content sha mismatch")
	}
}

func deriveKeyIDWorker(t *testing.T, keyType, scopeID string, keyEpoch int64, pub ed25519.PublicKey) string {
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

// seedTrustSnapshotWorkerIntegration mirrors gateway e2e trust setup: inserts CONFIG/trust_snapshot and sets PRD-13 env bindings.
func seedTrustSnapshotWorkerIntegration(t *testing.T, ctx context.Context, pool *pgxpool.Pool, emitterIDHex string, emitterPub ed25519.PublicKey, emitterPriv ed25519.PrivateKey, trustVersion string) {
	t.Helper()
	keyEpoch := int64(1)
	keyType := "AGENT"
	keyID := deriveKeyIDWorker(t, keyType, emitterIDHex, keyEpoch, emitterPub)
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
		"key_epoch":             keyEpoch,
		"key_id":                keyID,
		"key_records":           []any{keyRecord},
		"signing_context":       "config_snapshot_v1",
		"verification_scope_id": "worker_auth_integration",
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
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authority_snapshots WHERE authority_type='CONFIG' AND authority_id='trust_snapshot' AND authority_version=$1`, trustVersion)
	})

	bindings, err := json.Marshal([]map[string]string{{
		"type":    "CONFIG",
		"id":      "trust_snapshot",
		"version": trustVersion,
	}})
	if err != nil {
		t.Fatalf("marshal authority bindings: %v", err)
	}
	snapshots, err2 := json.Marshal([]map[string]string{{
		"type":                   "CONFIG",
		"id":                     "trust_snapshot",
		"version":                trustVersion,
		"canonical_payload_text": string(canonicalTrustPayload),
		"payload_hash_hex":       hex.EncodeToString(trustPayloadHash[:]),
		"signature_hex":          hex.EncodeToString(trustSignature),
	}})
	if err2 != nil {
		t.Fatalf("marshal authority snapshots: %v", err2)
	}
	t.Setenv("RANSOMEYE_PRD13_AUTHORITY_BINDINGS_JSON", string(bindings))
	t.Setenv("RANSOMEYE_PRD13_AUTHORITY_SNAPSHOTS_JSON", string(snapshots))
}

