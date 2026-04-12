package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"ransomeye/core/internal/storage/authority"
)

// TestReplayPrecheck_DB_UsesCommittedStateOnly verifies ingest ReplayPrecheck consults committed
// replay_guard ∩ partition_records ∩ batch_commit_records, not replaySeen.
func TestReplayPrecheck_DB_UsesCommittedStateOnly(t *testing.T) {
	pool := requireReplayDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	partitionID := int64(99301)
	logicalShardID := randomBytes(t, 32)
	cleanupPartitionRows(t, ctx, pool, partitionID)

	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", fmt.Sprintf("%d", partitionID))
	t.Setenv("RANSOMEYE_PRD13_LOGICAL_SHARD_ID", hex.EncodeToString(logicalShardID))

	emitterPub, emitterPriv, _ := ed25519.GenerateKey(rand.Reader)
	emitterIDHex := hex.EncodeToString(truncate16(t, emitterPub))
	trustVer := uniqueTrustVersion(t)
	setupTrustSnapshotForEmitter(t, ctx, pool, emitterIDHex, emitterPub, emitterPriv, trustVer)

	agentBytes, err := hex.DecodeString(emitterIDHex)
	if err != nil || len(agentBytes) != 16 {
		t.Fatalf("emitter hex: %v", err)
	}
	agentUUID, err := uuid.FromBytes(agentBytes)
	if err != nil {
		t.Fatalf("agent uuid: %v", err)
	}

	bootID := uuid.New()
	msgID := uuid.New()
	payload := []byte(`{"replay_precheck":1}`)
	ph := sha256.Sum256(payload)
	schemaV := "telemetry_v1"

	refs, snaps, execHash, err := resolvePRD13AuthorityAndContextSignal()
	if err != nil {
		t.Fatalf("authority context: %v", err)
	}
	sch := authority.SchemaTransformHash(schemaV, execHash)
	logicalClock := uint64(0)
	commitPub, commitPriv, _ := ed25519.GenerateKey(rand.Reader)
	sig := make([]byte, ed25519.SignatureSize)
	partCtx := make([]byte, 16)

	opts := authority.CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: execHash,
		PrivateKey:           commitPriv,
		KeyID:                hex.EncodeToString(commitPub),
		KeyEpoch:             1,
		AuthorityRefs:        refs,
		AuthoritySnapshots:   snaps,
		Records: []authority.RecordDraft{{
			RecordType:            "SIGNAL",
			RecordVersion:         "v1",
			StageOrder:            1,
			RecordID:              msgID[:],
			MessageID:             msgID[:],
			AgentID:               agentUUID[:],
			BootSessionID:         bootID[:],
			LogicalClock:          &logicalClock,
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadBytes: payload,
			CanonicalPayloadHash:  ph,
			PayloadHash:           &ph,
			Signature:             sig,
			PartitionContext:      partCtx,
			SchemaVersion:         &schemaV,
			SchemaTransformHash:   &sch,
		}},
		ReplayGuard: []authority.ReplayGuardAdmittedRow{{
			LogicalShardID: logicalShardID,
			EmitterID:      agentUUID[:],
			BootSessionID:  bootID[:],
			LogicalClock:   logicalClock,
			MessageID:      msgID[:],
		}},
	}
	if err := authority.CommitPartitionBatch(ctx, pool, opts); err != nil {
		t.Fatalf("CommitPartitionBatch: %v", err)
	}

	h := NewHandlers(nil, nil, nil)
	h.SetDBPool(pool)
	sys := "test_system_identity_hash_64_chars______________________________"
	if len(sys) != 64 {
		t.Fatalf("system identity length")
	}
	h.systemIdentityHash = sys

	// Populate replaySeen with a conflicting hash — must NOT affect DB-backed decision.
	h.replayMu.Lock()
	if h.replaySeen == nil {
		h.replaySeen = make(map[string][32]byte)
	}
	rk, _ := h.replayKey(sys, agentUUID.String(), bootID.String(), msgID.String())
	var wrong [32]byte
	wrong[0] = 0xee
	h.replaySeen[rk] = wrong
	h.replayMu.Unlock()

	ack, err := h.ReplayPrecheck(ctx, sys, agentUUID.String(), bootID.String(), msgID.String(), ph)
	if err != nil {
		t.Fatalf("ReplayPrecheck: %v", err)
	}
	if ack == nil || !ack.GetAccepted() {
		t.Fatalf("expected idempotent ack from committed state, got %+v", ack)
	}

	_, err = h.ReplayPrecheck(ctx, sys, agentUUID.String(), bootID.String(), msgID.String(), wrong)
	if err == nil || !strings.Contains(err.Error(), "message_id reused") {
		t.Fatalf("expected payload mismatch error, got %v", err)
	}
}
