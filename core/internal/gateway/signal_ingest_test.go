package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/storage/authority"
	pb "ransomeye/proto/ransomeyepb"
)

func TestSendSignal_AuthoritativeHandoffSuccess(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	h.systemIdentityHash = ""
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
		return []authority.AuthorityRef{{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"}}, nil, authority.ZeroHash32, nil
	}
	committed := false
	signalCommitBatch = func(_ context.Context, _ *pgxpool.Pool, _ authority.CommitOptions) error {
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

	ack, err := h.SendSignal(context.Background(), &req)
	if err != nil {
		t.Fatalf("SendSignal: %v", err)
	}
	if !ack.GetAccepted() {
		t.Fatal("accepted=false")
	}
	if !committed {
		t.Fatal("expected authoritative commit handoff")
	}
}

func TestSendSignal_ReplayRejectBlocksAdmission(t *testing.T) {
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
		return status.Error(codes.PermissionDenied, "REJECT: REJECT_DUPLICATE")
	}
	signalResolveAuthority = func() ([]authority.AuthorityRef, []authority.SnapshotUpsert, [32]byte, error) {
		return []authority.AuthorityRef{{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"}}, nil, authority.ZeroHash32, nil
	}
	committed := false
	signalCommitBatch = func(_ context.Context, _ *pgxpool.Pool, _ authority.CommitOptions) error {
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
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code=%s want=%s err=%v", status.Code(err), codes.PermissionDenied, err)
	}
	if committed {
		t.Fatal("commit must not execute for replay rejection")
	}
}

func TestSendSignal_AuthorityTypedFailurePropagation(t *testing.T) {
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
		return []authority.AuthorityRef{{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"}}, nil, authority.ZeroHash32, nil
	}
	signalCommitBatch = func(_ context.Context, _ *pgxpool.Pool, _ authority.CommitOptions) error {
		return authority.FailType2("STATE_INCONSISTENCY", errors.New("storage unavailable"))
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
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code=%s want=%s err=%v", status.Code(err), codes.Unavailable, err)
	}
}

func TestWorkerUsesRenamedAuthorityPath(t *testing.T) {
	raw, err := os.ReadFile("../pipeline/worker.go")
	if err != nil {
		t.Fatalf("read worker.go: %v", err)
	}
	text := string(raw)
	if strings.Contains(text, "core/internal/storage/prd13") {
		t.Fatal("stale storage/prd13 import path remains")
	}
	if !strings.Contains(text, "core/internal/storage/authority") {
		t.Fatal("expected storage/authority import")
	}
}

func TestSendSignal_TypeFailurePropagationAtRPCBoundary(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	h.prd13CommitKey = bytesFilledSignal(ed25519.PrivateKeySize, 0x77)
	h.prd13CommitKeyID = strings.Repeat("a", 64)
	h.prd13CommitEpoch = 1

	// malformed input class
	if _, err := h.SendSignal(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil request code=%s want=%s err=%v", status.Code(err), codes.InvalidArgument, err)
	}

	restoreResolveKey := signalResolvePublicKey
	restoreResolve := signalResolveAuthority
	restoreReplay := signalReplayGate
	restoreCommit := signalCommitBatch
	restoreNeedsPool := signalCommitRequiresDBPool
	t.Cleanup(func() {
		signalResolvePublicKey = restoreResolveKey
		signalResolveAuthority = restoreResolve
		signalReplayGate = restoreReplay
		signalCommitBatch = restoreCommit
		signalCommitRequiresDBPool = restoreNeedsPool
	})
	signalCommitRequiresDBPool = false
	signalResolveAuthority = func() ([]authority.AuthorityRef, []authority.SnapshotUpsert, [32]byte, error) {
		return []authority.AuthorityRef{{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"}}, nil, authority.ZeroHash32, nil
	}
	signalReplayGate = func(context.Context, *pgxpool.Pool, int64, []byte, []byte, []byte, uint64, []byte) error {
		return nil
	}
	signalCommitBatch = func(context.Context, *pgxpool.Pool, authority.CommitOptions) error {
		return nil
	}

	req := validSignalRequest(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signalResolvePublicKey = func(context.Context, *Handlers, pb.EmitterType, string, string, uint64) (ed25519.PublicKey, error) {
		return pub, authority.FailType1("INPUT_ERROR", errors.New("invalid lookup input"))
	}
	mid, _ := h.recomputeMessageID(&req)
	req.MessageId = mid
	sigInput, _ := h.recomputeSigningInput(&req)
	req.Signature = ed25519.Sign(priv, sigInput)
	_, err := h.SendSignal(context.Background(), &req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("type1 code=%s want=%s err=%v", status.Code(err), codes.InvalidArgument, err)
	}

	signalResolvePublicKey = func(context.Context, *Handlers, pb.EmitterType, string, string, uint64) (ed25519.PublicKey, error) {
		return nil, authority.FailType2("STATE_INCONSISTENCY", errors.New("db lookup failure"))
	}
	_, err = h.SendSignal(context.Background(), &req)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("type2 code=%s want=%s err=%v", status.Code(err), codes.Unavailable, err)
	}

	signalResolvePublicKey = func(context.Context, *Handlers, pb.EmitterType, string, string, uint64) (ed25519.PublicKey, error) {
		return nil, authority.FailType3("INTEGRITY_FAILURE", errors.New("trust chain invalid"))
	}
	_, err = h.SendSignal(context.Background(), &req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("type3 code=%s want=%s err=%v", status.Code(err), codes.PermissionDenied, err)
	}
}

func TestSendSignal_RejectsUUIDLegacyShapes(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	payload := []byte(`{"a":1}`)
	sum := sha256.Sum256(payload)

	req := &pb.SignalEnvelope{
		ProtocolVersion:     mishkaProtocolVersionV1,
		SigningContext:      "ransomeye:v1:telemetry:event",
		SystemId:            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IdentityVersion:     1,
		EmitterType:         pb.EmitterType_EMITTER_TYPE_AGENT,
		EmitterId:           "11111111-1111-4111-8111-111111111111", // forbidden UUID form
		BootSessionId:       "22222222-2222-4222-8222-222222222222", // forbidden UUID form
		LogicalClock:        0,
		PartitionContext:    "33333333-3333-4333-8333-333333333333",
		PayloadHash:         hex.EncodeToString(sum[:]),
		MessageId:           "44444444-4444-4444-8444-444444444444",
		Signature:           bytesFilledSignal(ed25519.SignatureSize, 0x00),
		CanonicalPayloadJson: payload,
	}

	_, err := h.SendSignal(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code=%s want=%s err=%v", status.Code(err), codes.PermissionDenied, err)
	}
}

func TestSendSignal_RejectsNonCanonicalJSON(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	payload := []byte(`{"b":1,"a":2}`)
	sum := sha256.Sum256(payload)

	req := &pb.SignalEnvelope{
		ProtocolVersion:     mishkaProtocolVersionV1,
		SigningContext:      "ransomeye:v1:telemetry:event",
		SystemId:            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IdentityVersion:     1,
		EmitterType:         pb.EmitterType_EMITTER_TYPE_AGENT,
		EmitterId:           hex.EncodeToString(bytesFilledSignal(16, 0x01)),
		BootSessionId:       hex.EncodeToString(bytesFilledSignal(32, 0x02)),
		LogicalClock:        0,
		PartitionContext:    hex.EncodeToString(bytesFilledSignal(16, 0x03)),
		PayloadHash:         hex.EncodeToString(sum[:]),
		MessageId:           hex.EncodeToString(bytesFilledSignal(32, 0x04)),
		Signature:           bytesFilledSignal(ed25519.SignatureSize, 0x05),
		CanonicalPayloadJson: payload,
	}

	_, err := h.SendSignal(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code=%s want=%s err=%v", status.Code(err), codes.PermissionDenied, err)
	}
}

func validSignalRequest(t *testing.T) pb.SignalEnvelope {
	t.Helper()
	payload := []byte(`{"a":1,"b":2}`)
	sum := sha256.Sum256(payload)
	systemID := hex.EncodeToString(bytesFilledSignal(32, 0x11))
	emitterIDHex := hex.EncodeToString(bytesFilledSignal(16, 0x22))
	bootSessionHex := hex.EncodeToString(bytesFilledSignal(32, 0x33))
	messageIDHex := hex.EncodeToString(bytesFilledSignal(32, 0x44))
	identityBytes := buildIdentityBytes(mustDecodeHexSignal(t, systemID), 1, pb.EmitterType_EMITTER_TYPE_AGENT, mustDecodeHexSignal(t, emitterIDHex))
	pcSum := sha256.Sum256(append(append([]byte(nil), payload...), identityBytes...))
	partitionContextHex := hex.EncodeToString(pcSum[:16])
	return pb.SignalEnvelope{
		ProtocolVersion:      mishkaProtocolVersionV1,
		SigningContext:       "ransomeye:v1:telemetry:event",
		SystemId:             systemID,
		IdentityVersion:      1,
		EmitterType:          pb.EmitterType_EMITTER_TYPE_AGENT,
		EmitterId:            emitterIDHex,
		BootSessionId:        bootSessionHex,
		LogicalClock:         0,
		PartitionContext:     partitionContextHex,
		PayloadHash:          hex.EncodeToString(sum[:]),
		MessageId:            messageIDHex,
		Signature:            bytesFilledSignal(ed25519.SignatureSize, 0x55),
		CanonicalPayloadJson: payload,
	}
}


func mustDecodeHexSignal(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return b
}

func bytesFilledSignal(n int, v byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}

