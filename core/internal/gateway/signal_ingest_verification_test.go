package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/storage/authority"
	pb "ransomeye/proto/ransomeyepb"
)

func TestSendSignal_MishkaPRD03_SignatureVerification(t *testing.T) {
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
	signalReplayGate = func(context.Context, *pgxpool.Pool, int64, []byte, []byte, []byte, uint64, []byte) error { return nil }
	signalResolveAuthority = func() ([]authority.AuthorityRef, []authority.SnapshotUpsert, [32]byte, error) {
		return []authority.AuthorityRef{{Type: "CONFIG", ID: "trust_snapshot", Version: "v1"}}, nil, authority.ZeroHash32, nil
	}
	signalCommitBatch = func(context.Context, *pgxpool.Pool, authority.CommitOptions) error { return nil }
	signalCommitRequiresDBPool = false

	// 1. Generate keys for the emitter.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	emitterID := hex.EncodeToString(bytesFilled(16, 0xEE))
	signingContext := "ransomeye:v1:telemetry:event"

	mockResolver := &mockPublicKeyResolver{
		keys: map[string]ed25519.PublicKey{
			strings.Join([]string{emitterID, "1", signingContext}, "|"): pub,
		},
	}
	signalResolvePublicKey = func(ctx context.Context, _ *Handlers, _ pb.EmitterType, keyID string, requiredSigningContext string, _ uint64) (ed25519.PublicKey, error) {
		return mockResolver.ResolveEmitterPublicKey(ctx, keyID, 1, requiredSigningContext)
	}

	h := NewHandlers(nil, nil, nil)
	h.systemIdentityHash = ""
	h.prd13CommitKey = bytesFilled(ed25519.PrivateKeySize, 0x7a)
	h.prd13CommitKeyID = strings.Repeat("a", 64)
	h.prd13CommitEpoch = 1

	payload := []byte(`{"a":1,"b":2}`)
	sum := sha256.Sum256(payload)
	systemID := hex.EncodeToString(bytesFilled(32, 0x11))
	bootSessionHex := hex.EncodeToString(bytesFilled(32, 0x33))

	identityBytes := buildIdentityBytes(mustDecodeHex(t, systemID), 1, pb.EmitterType_EMITTER_TYPE_AGENT, mustDecodeHex(t, emitterID))
	pcSum := sha256.Sum256(append(append([]byte(nil), payload...), identityBytes...))
	partitionContextHex := hex.EncodeToString(pcSum[:16])

	req := &pb.SignalEnvelope{
		ProtocolVersion:      mishkaProtocolVersionV1,
		SigningContext:       signingContext,
		SystemId:             systemID,
		IdentityVersion:      1,
		EmitterType:          pb.EmitterType_EMITTER_TYPE_AGENT,
		EmitterId:            emitterID,
		BootSessionId:        bootSessionHex,
		LogicalClock:         0,
		PartitionContext:     partitionContextHex,
		PayloadHash:          hex.EncodeToString(sum[:]),
		CanonicalPayloadJson: payload,
	}

	mid, _ := h.recomputeMessageID(req)
	req.MessageId = mid

	// Sign the message.
	signingInput, _ := h.recomputeSigningInput(req)
	req.Signature = ed25519.Sign(priv, signingInput)

	t.Run("ValidSignatureAccepted", func(t *testing.T) {
		ack, err := h.SendSignal(context.Background(), req)
		if err != nil {
			t.Fatalf("SendSignal: %v", err)
		}
		if !ack.GetAccepted() {
			t.Fatal("accepted=false")
		}
	})

	t.Run("WrongSignatureRejected", func(t *testing.T) {
		badReq := *req
		badReq.Signature = append([]byte(nil), req.Signature...)
		badReq.Signature[0] ^= 0xFF
		_, err := h.SendSignal(context.Background(), &badReq)
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "auth_failure") {
			t.Fatalf("expected PermissionDenied/auth_failure, got code=%v err=%v", status.Code(err), err)
		}
	})

	t.Run("WrongKeyRejected", func(t *testing.T) {
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		badReq := *req
		badReq.Signature = ed25519.Sign(otherPriv, signingInput)
		_, err := h.SendSignal(context.Background(), &badReq)
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "auth_failure") {
			t.Fatalf("expected PermissionDenied/auth_failure, got code=%v err=%v", status.Code(err), err)
		}
	})

	t.Run("SigningContextMismatchRejected", func(t *testing.T) {
		badReq := *req
		badReq.SigningContext = "wrong:context"
		// recompute mid and signature for the new context so only context applicability check fails
		badMID, _ := h.recomputeMessageID(&badReq)
		badReq.MessageId = badMID
		badInput, _ := h.recomputeSigningInput(&badReq)
		badReq.Signature = ed25519.Sign(priv, badInput)

		_, err := h.SendSignal(context.Background(), &badReq)
		if status.Code(err) != codes.PermissionDenied || !(strings.Contains(err.Error(), "auth_failure") || strings.Contains(err.Error(), "INTEGRITY_FAILURE")) {
			t.Fatalf("expected PermissionDenied auth failure, got code=%v err=%v", status.Code(err), err)
		}
	})

	t.Run("MissingTrustedKeyMaterialRejected", func(t *testing.T) {
		badReq := *req
		badReq.EmitterId = hex.EncodeToString(bytesFilled(16, 0x99))
		// Recompute partition_context for new identity
		idB := buildIdentityBytes(mustDecodeHex(t, systemID), 1, pb.EmitterType_EMITTER_TYPE_AGENT, mustDecodeHex(t, badReq.EmitterId))
		pcS := sha256.Sum256(append(append([]byte(nil), payload...), idB...))
		badReq.PartitionContext = hex.EncodeToString(pcS[:16])

		// recompute to satisfy prior checks
		badMID, _ := h.recomputeMessageID(&badReq)
		badReq.MessageId = badMID
		badInput, _ := h.recomputeSigningInput(&badReq)
		badReq.Signature = ed25519.Sign(priv, badInput)

		_, err := h.SendSignal(context.Background(), &badReq)
		if status.Code(err) != codes.PermissionDenied || !(strings.Contains(err.Error(), "auth_failure") || strings.Contains(err.Error(), "INTEGRITY_FAILURE")) {
			t.Fatalf("expected PermissionDenied auth failure, got code=%v err=%v", status.Code(err), err)
		}
	})
}
