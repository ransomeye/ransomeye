package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/storage/authority"
	pb "ransomeye/proto/ransomeyepb"
)

func TestSendSignal_RejectsMultipleAuthorityBindings(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	h.prd13CommitKey = bytesFilledSignal(ed25519.PrivateKeySize, 0x77)
	h.prd13CommitKeyID = strings.Repeat("a", 64)
	h.prd13CommitEpoch = 1

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
		return []authority.AuthorityRef{
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"},
			{Type: "CONFIG", ID: "trust_snapshot", Version: "v2"},
		}, nil, nonZeroExecHashSignal(), nil
	}
	committed := false
	signalCommitBatch = func(context.Context, *pgxpool.Pool, authority.CommitOptions) error {
		committed = true
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

	_, err := h.SendSignal(context.Background(), &req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code=%s want InvalidArgument err=%v", status.Code(err), err)
	}
	if committed {
		t.Fatal("commit must not run")
	}
}

func nonZeroExecHashSignal() [32]byte {
	var h [32]byte
	h[0] = 0xab
	return h
}
