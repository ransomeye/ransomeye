package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/identity"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/pipeline"
	pb "ransomeye/proto/ransomeyepb"
)

const (
	testAgentID           = "11111111-1111-4111-8111-111111111111"
	testBootSessionID     = "22222222-2222-4222-8222-222222222222"
	testMessageID         = "33333333-3333-4333-8333-333333333333"
	testEventID           = "44444444-4444-4444-8444-444444444444"
	testTimestampUnixNano = uint64(1700000000000000000)
)

func TestNonCanonicalJSONRejected(t *testing.T) {
	h, ctx, env, _, _ := validTelemetryFixture(t)
	env.Payload = []byte(`{"b":1,"a":2}`)
	env.Signature = signTelemetryPayload(deterministicPrivateKey(), env.SigningContext, env.Payload)

	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %s, want %s", status.Code(err), codes.PermissionDenied)
	}
	if !strings.Contains(err.Error(), "REJECT_BEFORE_QUEUE: non-canonical JSON payload") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMissingIdentityRejected(t *testing.T) {
	h, ctx, env, _, _ := validTelemetryFixture(t)
	env.AgentId = ""
	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %s, want %s", status.Code(err), codes.PermissionDenied)
	}
	if !strings.Contains(err.Error(), "REJECT_BEFORE_QUEUE: identity missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWrongSigningContextRejected(t *testing.T) {
	h, ctx, env, privateKey, _ := validTelemetryFixture(t)
	env.SigningContext = "ransomeye:v1:telemetry:unknown"
	env.Signature = signTelemetryPayload(privateKey, env.SigningContext, env.Payload)
	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %s, want %s", status.Code(err), codes.PermissionDenied)
	}
	if !strings.Contains(err.Error(), "REJECT_BEFORE_QUEUE: signing_context invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignatureMismatchRejected(t *testing.T) {
	h, ctx, env, _, _ := validTelemetryFixture(t)
	env.Signature[0] ^= 0xFF
	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %s, want %s", status.Code(err), codes.PermissionDenied)
	}
	if !strings.Contains(err.Error(), "REJECT_BEFORE_QUEUE: signature invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReplaySameIDDifferentHashRejects(t *testing.T) {
	h, ctx, env, privateKey, recorder := validTelemetryFixture(t)

	if _, err := h.SendTelemetry(ctx, env); err != nil {
		t.Fatalf("first SendTelemetry: %v", err)
	}

	mutatedPayload := append([]byte(nil), env.Payload...)
	mutatedPayload[45] ^= 0x01
	env.Payload = mutatedPayload
	env.Signature = signTelemetryPayload(privateKey, env.SigningContext, env.Payload)

	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %s, want %s", status.Code(err), codes.PermissionDenied)
	}
	if !strings.Contains(err.Error(), "REJECT: message_id reused with different payload hash") {
		t.Fatalf("unexpected error: %v", err)
	}
	if recorder.enqueueCount != 1 {
		t.Fatalf("enqueue count = %d, want 1", recorder.enqueueCount)
	}
}

func TestReplaySameIDSameHashReturnsIdempotentAck(t *testing.T) {
	h, ctx, env, _, recorder := validTelemetryFixture(t)

	_, err := h.SendTelemetry(ctx, env)
	if err != nil {
		t.Fatalf("first SendTelemetry: %v", err)
	}

	ack, err := h.SendTelemetry(ctx, env)
	if err != nil {
		t.Fatalf("second SendTelemetry: %v", err)
	}
	if !ack.GetAccepted() {
		t.Fatal("idempotent ack not accepted")
	}
	if recorder.enqueueCount != 1 {
		t.Fatalf("enqueue count = %d, want 1", recorder.enqueueCount)
	}
}

func TestCrashBeforeCommitRecoveryBlocksRetryUntilRecoveredCommit(t *testing.T) {
	path := t.TempDir() + "/crash-recovery.log"
	h1, _, env, _ := manualTelemetryFixtureWithPath(t, path)

	canonicalPayload, view, wasJSON, err := ingest.CanonicalizePayloadBytes(env.Payload)
	if err != nil {
		t.Fatalf("CanonicalizePayloadBytes: %v", err)
	}
	if wasJSON {
		t.Fatal("expected canonical telemetry payload")
	}
	payloadHash := h1.ComputePayloadHash(canonicalPayload)
	replayKey, err := h1.replayKey(env.SystemIdentityHash, env.AgentId, env.BootSessionId, env.MessageId)
	if err != nil {
		t.Fatalf("replayKey: %v", err)
	}
	dbType, err := ingest.DBEventType(view.EventTypeCode)
	if err != nil {
		t.Fatalf("DBEventType: %v", err)
	}
	witness := h1.bumpLamport(int64(view.LogicalClock))
	ev := &ingest.VerifiedTelemetry{
		Payload:        append([]byte(nil), canonicalPayload...),
		AgentSignature: append([]byte(nil), env.Signature...),
		AgentIDStr:     view.AgentID.String(),
		EventType:      dbType,
		TimestampUnix:  float64(view.TimestampUnixNano) / 1e9,
		LogicalClock:   witness,
	}
	meta := ack.Metadata{
		ReplayKey:     replayKey,
		MessageID:     env.MessageId,
		ContentSHA256: payloadHash,
	}
	if _, err := h1.ForwardToQueue(ev, meta); err != nil {
		t.Fatalf("ForwardToQueue: %v", err)
	}
	leased, err := h1.ingestQueue.DequeueNext()
	if err != nil {
		t.Fatalf("DequeueNext lease: %v", err)
	}
	if leased == nil {
		t.Fatal("expected leased event before crash simulation")
	}

	h2, ctx2, env2, _ := manualTelemetryFixtureWithPath(t, path)
	done := make(chan error, 1)
	go func() {
		_, err := h2.SendTelemetry(ctx2, env2)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("retry ACK returned before recovered commit: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	recovered, err := h2.ingestQueue.DequeueNext()
	if err != nil {
		t.Fatalf("DequeueNext recovery: %v", err)
	}
	if recovered == nil {
		t.Fatal("expected recovered queue event after restart")
	}
	if recovered.Ack.ReplayKey != replayKey {
		t.Fatalf("recovered replay key = %q, want %q", recovered.Ack.ReplayKey, replayKey)
	}
	h2.ackController.Commit(recovered.Ack)
	if err := h2.ingestQueue.Resolve(recovered.Sequence); err != nil {
		t.Fatalf("Resolve recovery: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("retry SendTelemetry failed after recovery commit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for ACK after recovery commit")
	}
}

func TestCryptoDeterminism(t *testing.T) {
	h, _, env, _, _ := validTelemetryFixture(t)
	canonical1, _, err := h.CanonicalizePayload(env.Payload)
	if err != nil {
		t.Fatalf("CanonicalizePayload(1): %v", err)
	}
	canonical2, _, err := h.CanonicalizePayload(env.Payload)
	if err != nil {
		t.Fatalf("CanonicalizePayload(2): %v", err)
	}
	if !bytes.Equal(canonical1, canonical2) {
		t.Fatal("canonical_payload_bytes drift")
	}
	hash1 := h.ComputePayloadHash(canonical1)
	hash2 := h.ComputePayloadHash(canonical2)
	if hash1 != hash2 {
		t.Fatal("SHA256 drift")
	}
	in1 := h.ConstructSigningInput(env.SigningContext, hash1)
	in2 := h.ConstructSigningInput(env.SigningContext, hash2)
	if !bytes.Equal(in1, in2) {
		t.Fatal("signing_input drift")
	}
}

func validTelemetryFixture(t *testing.T) (*Handlers, context.Context, *pb.TelemetryEnvelope, ed25519.PrivateKey, *recordingTelemetryEnqueuer) {
	t.Helper()

	h, ctx, env, privateKey := manualTelemetryFixture(t)
	recorder := &recordingTelemetryEnqueuer{}
	recorder.start(t, h.ingestQueue, h.ackController)
	return h, ctx, env, privateKey, recorder
}

func manualTelemetryFixture(t *testing.T) (*Handlers, context.Context, *pb.TelemetryEnvelope, ed25519.PrivateKey) {
	return manualTelemetryFixtureWithPath(t, t.TempDir()+"/gateway-fixture.log")
}

func manualTelemetryFixtureWithPath(t *testing.T, durablePath string) (*Handlers, context.Context, *pb.TelemetryEnvelope, ed25519.PrivateKey) {
	t.Helper()
	seedGatewayBackpressureConfig(t)

	agentID := mustParseUUID(t, testAgentID)
	bootSessionID := mustParseUUID(t, testBootSessionID)
	sessions := identity.NewSessionManager()
	t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", durablePath)

	h := NewHandlers(nil, nil, sessions)
	queue := pipeline.NewIngestQueue(2)
	h.SetIngestQueue(queue)
	h.systemIdentityHash = strings.Repeat("a", 64)

	ctx, privateKey := telemetryPeerContext(agentID.String())
	tlsBinding, err := identity.TLSBindingKey(ctx)
	if err != nil {
		t.Fatalf("TLSBindingKey: %v", err)
	}
	sessions.CreateSession(agentID.String(), bootSessionID.String(), tlsBinding)
	payload := telemetryPayload(t, agentID, bootSessionID)
	env := &pb.TelemetryEnvelope{
		MessageId:          testMessageID,
		AgentId:            agentID.String(),
		SigningContext:     telemetrySigningContext,
		Signature:          signTelemetryPayload(privateKey, telemetrySigningContext, payload),
		SystemIdentityHash: h.systemIdentityHash,
		BootSessionId:      bootSessionID.String(),
		Payload:            payload,
	}
	return h, ctx, env, privateKey
}

func telemetryPayload(t *testing.T, agentID, bootSessionID uuid.UUID) []byte {
	t.Helper()

	payload, err := ingest.BuildCanonicalV1(
		42,
		agentID,
		mustParseUUID(t, testEventID),
		ingest.EventTypeCodeProcess,
		17,
		[32]byte{1},
		[32]byte{2},
		[16]byte{3},
		testTimestampUnixNano,
		[16]byte(bootSessionID),
	)
	if err != nil {
		t.Fatalf("BuildCanonicalV1: %v", err)
	}
	return append([]byte(nil), payload[:]...)
}

func telemetryPeerContext(agentID string) (context.Context, ed25519.PrivateKey) {
	privateKey := deterministicPrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	sanURI, _ := url.Parse("urn:ransomeye:agent:" + agentID)
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "forbidden-cn-ignored",
		},
		PublicKey: publicKey,
		URIs:      []*url.URL{sanURI},
		Raw:       []byte("test-cert-raw-" + agentID),
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	})
	return ctx, privateKey
}

func telemetryProbePeerContext(probeID string) (context.Context, ed25519.PrivateKey) {
	privateKey := deterministicPrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	sanURI, _ := url.Parse("urn:ransomeye:probe:" + probeID)
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "forbidden-cn-ignored",
		},
		PublicKey: publicKey,
		URIs:      []*url.URL{sanURI},
		Raw:       []byte("test-probe-cert-raw-" + probeID),
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	})
	return ctx, privateKey
}

func deterministicPrivateKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("gateway-core-ingest-deterministic-test-seed"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func signTelemetryPayload(privateKey ed25519.PrivateKey, signingContext string, payload []byte) []byte {
	hash := sha256.Sum256(payload)
	signingInput := append(append(make([]byte, 0, len(signingContext)+sha256.Size), signingContext...), hash[:]...)
	return ed25519.Sign(privateKey, signingInput)
}

func mustParseUUID(t *testing.T, raw string) uuid.UUID {
	t.Helper()

	value, err := uuid.Parse(raw)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", raw, err)
	}
	return value
}

type recordingTelemetryEnqueuer struct {
	mu           sync.Mutex
	lastPayload  *ingest.VerifiedTelemetry
	enqueueCount int
}

func (r *recordingTelemetryEnqueuer) start(t *testing.T, queue *pipeline.IngestQueue, acker *ack.Controller) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			ev, err := queue.DequeueNext()
			if err != nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if ev == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			r.mu.Lock()
			r.lastPayload = ev.Payload
			r.enqueueCount++
			r.mu.Unlock()
			if acker != nil {
				acker.Commit(ev.Ack)
			}
			_ = queue.Resolve(ev.Sequence)
		}
	}()
}
