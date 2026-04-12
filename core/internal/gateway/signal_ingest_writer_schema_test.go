package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ransomeye/core/internal/storage/authority"
	pb "ransomeye/proto/ransomeyepb"
)

func TestSendSignal_CommitOptionsCarriesNonZeroSchemaTransformHash(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	h.prd13CommitKey = bytesFilledSignal(ed25519.PrivateKeySize, 0x77)
	h.prd13CommitKeyID = strings.Repeat("a", 64)
	h.prd13CommitEpoch = 1

	execHash := nonZeroExecHashSignal()
	schemaV := signalSchemaVersionFromProtocolVersion(mishkaProtocolVersionV1)
	wantTransform := authority.SchemaTransformHash(schemaV, execHash)

	restoreReplay := signalReplayGate
	restoreResolve := signalResolveAuthority
	restoreCommit := signalCommitBatch
	restoreNeedsPool := signalCommitRequiresDBPool
	restoreResolveKey := signalResolvePublicKey
	t.Cleanup(func() {
		signalReplayGate = restoreReplay
		signalResolveAuthority = restoreResolve
		signalCommitBatch = restoreCommit
		signalCommitRequiresDBPool = restoreNeedsPool
		signalResolvePublicKey = restoreResolveKey
	})
	signalCommitRequiresDBPool = false
	signalReplayGate = func(context.Context, *pgxpool.Pool, int64, []byte, []byte, []byte, uint64, []byte) error {
		return nil
	}
	signalResolveAuthority = func() ([]authority.AuthorityRef, []authority.SnapshotUpsert, [32]byte, error) {
		return []authority.AuthorityRef{{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"}}, nil, execHash, nil
	}
	var gotOpts authority.CommitOptions
	signalCommitBatch = func(_ context.Context, _ *pgxpool.Pool, opts authority.CommitOptions) error {
		gotOpts = opts
		return nil
	}

	req := validSignalRequest(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signalResolvePublicKey = func(context.Context, *Handlers, pb.EmitterType, string, string, uint64) (ed25519.PublicKey, error) {
		return pub, nil
	}
	mid, _ := h.recomputeMessageID(&req)
	req.MessageId = mid
	signingInput, _ := h.recomputeSigningInput(&req)
	req.Signature = ed25519.Sign(priv, signingInput)

	ack, err := h.SendSignal(context.Background(), &req)
	if err != nil {
		t.Fatalf("SendSignal: %v", err)
	}
	if !ack.GetAccepted() {
		t.Fatal("expected accepted")
	}
	if len(gotOpts.Records) != 1 {
		t.Fatalf("records: %d", len(gotOpts.Records))
	}
	rec := gotOpts.Records[0]
	if rec.SchemaTransformHash == nil {
		t.Fatal("nil SchemaTransformHash")
	}
	if *rec.SchemaTransformHash == authority.ZeroHash32 {
		t.Fatal("schema_transform_hash must not be zero")
	}
	if *rec.SchemaTransformHash != wantTransform {
		t.Fatalf("schema_transform_hash=%x want=%x", rec.SchemaTransformHash[:], wantTransform[:])
	}
	if rec.SchemaVersion == nil || *rec.SchemaVersion != schemaV {
		t.Fatalf("schema_version=%v want=%q", rec.SchemaVersion, schemaV)
	}
}
