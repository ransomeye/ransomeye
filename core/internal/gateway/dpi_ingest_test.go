package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/metrics"
	dpieventpb "ransomeye/proto/dpieventpb"
)

func TestNewDPIIngestRejectsEmptyPrimaryIP(t *testing.T) {
	opts := validDPIIngestOptions(t)
	opts.PrimaryIP = ""

	_, err := NewDPIIngest(opts)
	if err == nil {
		t.Fatal("NewDPIIngest accepted empty PrimaryIP")
	}
}

func TestNewDPIIngestRejectsInvalidPrimaryIP(t *testing.T) {
	opts := validDPIIngestOptions(t)
	opts.PrimaryIP = "invalid"

	_, err := NewDPIIngest(opts)
	if err == nil {
		t.Fatal("NewDPIIngest accepted invalid PrimaryIP")
	}
}

func TestVerifyTransportFrameRejectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ingester := &DPIIngest{publicKey: pub}
	frame := buildSignedDPIFrame(t, priv, &dpieventpb.DpiEvent{
		Seq:              9,
		FlowHash:         11,
		ClassificationId: 13,
		ConfidenceFp:     700_000,
		PayloadHash:      make([]byte, sha256.Size),
	}, 0)

	frame[6] ^= 0x01
	if _, _, _, _, err := ingester.verifyTransportFrame(frame); err == nil {
		t.Fatal("verifyTransportFrame accepted tampered bytes")
	}
}

func TestVerifyTransportFrameRejectsNonCanonicalEncoding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ingester := &DPIIngest{publicKey: pub}
	payload := []byte{
		0x10, 0x0b, // flow_hash
		0x08, 0x09, // seq
		0x18, 0x0d, // classification_id
		0x20, 0xe0, 0xdc, 0x2a, // confidence_fp = 700000
		0x2a, 0x20, // payload_hash length = 32
	}
	payload = append(payload, bytesOfLen(sha256.Size, 0x00)...)
	frame := buildSignedDPIFrameFromPayload(t, priv, 9, payload, 0)

	if _, _, _, _, err := ingester.verifyTransportFrame(frame); err == nil {
		t.Fatal("verifyTransportFrame accepted non-canonical protobuf ordering")
	}
}

func TestVerifiedTelemetryFromEventMapsDeterministically(t *testing.T) {
	event := &dpieventpb.DpiEvent{
		Seq:              42,
		FlowHash:         99,
		ClassificationId: 77,
		ConfidenceFp:     555_000,
		PayloadHash:      bytesOfLen(sha256.Size, 0x5a),
	}
	frameHash := sha256.Sum256([]byte("transport-frame"))
	signature := bytesOfLen(ed25519.SignatureSize, 0x44)
	ingester := &DPIIngest{
		agentID:       uuid.MustParse("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a"),
		tenantID:      uuid.MustParse("b4ef13aa-1510-4e63-8f30-a0a165c4132a"),
		bootSessionID: uuid.MustParse("c41d0b89-0ef9-4e61-a8d3-9db60d5ee914"),
	}

	verified, err := ingester.verifiedTelemetryFromEvent(event, frameHash, signature, 17)
	if err != nil {
		t.Fatalf("verifiedTelemetryFromEvent: %v", err)
	}

	if verified.LogicalClock != 42 {
		t.Fatalf("logical clock = %d, want 42", verified.LogicalClock)
	}
	if verified.EventType != "NETWORK_EVENT" {
		t.Fatalf("event type = %q", verified.EventType)
	}
	if got := binary.LittleEndian.Uint64(verified.Payload[1:9]); got != 42 {
		t.Fatalf("payload logical clock = %d, want 42", got)
	}
	if got := binary.LittleEndian.Uint64(verified.Payload[81:89]); got != binary.LittleEndian.Uint64(frameHash[:8]) {
		t.Fatalf("canonical payload did not carry transport hash")
	}
	if len(verified.AgentSignature) != ed25519.SignatureSize {
		t.Fatalf("signature len = %d, want %d", len(verified.AgentSignature), ed25519.SignatureSize)
	}
	if verified.DroppedCount != 17 {
		t.Fatalf("dropped count = %d, want 17", verified.DroppedCount)
	}
}

func TestHandleFrameEnqueuesVerifiedTelemetry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	scheduler := &recordingEnqueuer{}
	ingester := &DPIIngest{
		publicKey:     pub,
		scheduler:     scheduler,
		agentID:       uuid.MustParse("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a"),
		tenantID:      uuid.MustParse("b4ef13aa-1510-4e63-8f30-a0a165c4132a"),
		bootSessionID: uuid.MustParse("c41d0b89-0ef9-4e61-a8d3-9db60d5ee914"),
	}
	frame := buildSignedDPIFrame(t, priv, &dpieventpb.DpiEvent{
		Seq:              88,
		FlowHash:         0x1122,
		ClassificationId: 0x3344,
		ConfidenceFp:     999_999,
		PayloadHash:      bytesOfLen(sha256.Size, 0x7e),
	}, 0)

	if err := ingester.handleFrame(frame); err != nil {
		t.Fatalf("handleFrame: %v", err)
	}
	if scheduler.payload == nil {
		t.Fatal("handleFrame did not enqueue verified telemetry")
	}
	if scheduler.payload.LogicalClock != 88 {
		t.Fatalf("logical clock = %d, want 88", scheduler.payload.LogicalClock)
	}
	if scheduler.payload.EventType != "NETWORK_EVENT" {
		t.Fatalf("event type = %q", scheduler.payload.EventType)
	}
	if scheduler.payload.DroppedCount != 0 {
		t.Fatalf("dropped count = %d, want 0", scheduler.payload.DroppedCount)
	}
}

func TestHandleFramePropagatesDropAccounting(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	scheduler := &recordingEnqueuer{}
	ingester := &DPIIngest{
		publicKey:     pub,
		scheduler:     scheduler,
		agentID:       uuid.MustParse("5dc099d6-56d4-4e4e-9f59-d0ebf5741d8a"),
		tenantID:      uuid.MustParse("b4ef13aa-1510-4e63-8f30-a0a165c4132a"),
		bootSessionID: uuid.MustParse("c41d0b89-0ef9-4e61-a8d3-9db60d5ee914"),
	}
	beforePacketsTotal := metrics.DPIPacketsTotal()
	beforePacketsDropped := metrics.DPIPacketsDropped()
	beforeEventsDropped := metrics.EventsDropped()
	frame := buildSignedDPIFrame(t, priv, &dpieventpb.DpiEvent{
		Seq:              89,
		FlowHash:         0x1122,
		ClassificationId: 0x3344,
		ConfidenceFp:     999_999,
		PayloadHash:      bytesOfLen(sha256.Size, 0x7e),
	}, 7)

	if err := ingester.handleFrame(frame); err != nil {
		t.Fatalf("handleFrame: %v", err)
	}
	if scheduler.payload == nil {
		t.Fatal("handleFrame did not enqueue verified telemetry")
	}
	if scheduler.payload.DroppedCount != 7 {
		t.Fatalf("dropped count = %d, want 7", scheduler.payload.DroppedCount)
	}
	if ingester.stats.TotalDropped != 7 {
		t.Fatalf("total dropped = %d, want 7", ingester.stats.TotalDropped)
	}
	if delta := metrics.DPIPacketsTotal() - beforePacketsTotal; delta != 8 {
		t.Fatalf("dpi packets total delta = %d, want 8", delta)
	}
	if delta := metrics.DPIPacketsDropped() - beforePacketsDropped; delta != 7 {
		t.Fatalf("dpi packets dropped delta = %d, want 7", delta)
	}
	if delta := metrics.EventsDropped() - beforeEventsDropped; delta != 7 {
		t.Fatalf("events dropped delta = %d, want 7", delta)
	}
}

func buildSignedDPIFrame(t *testing.T, priv ed25519.PrivateKey, event *dpieventpb.DpiEvent, droppedBefore uint64) []byte {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return buildSignedDPIFrameFromPayload(t, priv, event.GetSeq(), payload, droppedBefore)
}

func buildSignedDPIFrameFromPayload(t *testing.T, priv ed25519.PrivateKey, seq uint64, payload []byte, droppedBefore uint64) []byte {
	t.Helper()
	envelopePayload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&dpieventpb.DpiEnvelope{
		Seq:           seq,
		Payload:       payload,
		DroppedBefore: droppedBefore,
	})
	if err != nil {
		t.Fatalf("proto.Marshal envelope: %v", err)
	}

	hash := sha256.Sum256(envelopePayload)
	signature := ed25519.Sign(priv, hash[:])

	frame := make([]byte, 4+len(envelopePayload)+len(hash)+len(signature))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(envelopePayload)))
	copy(frame[4:4+len(envelopePayload)], envelopePayload)
	copy(frame[4+len(envelopePayload):4+len(envelopePayload)+len(hash)], hash[:])
	copy(frame[4+len(envelopePayload)+len(hash):], signature)
	return frame
}

type recordingEnqueuer struct {
	payload *ingest.VerifiedTelemetry
}

func (r *recordingEnqueuer) Enqueue(payload *ingest.VerifiedTelemetry) error {
	if payload == nil {
		return ingest.ErrNilVerifiedTelemetry
	}
	r.payload = payload
	return nil
}

var _ ingest.VerifiedTelemetryEnqueuer = (*recordingEnqueuer)(nil)

func bytesOfLen(n int, fill byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = fill
	}
	return out
}

func validDPIIngestOptions(t *testing.T) DPIIngestOptions {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	keyPath := t.TempDir() + "/dpi.pub"
	if err := os.WriteFile(keyPath, pub, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	return DPIIngestOptions{
		SocketPath:    t.TempDir() + "/dpi.sock",
		PublicKeyPath: keyPath,
		AgentID:       uuid.NewString(),
		TenantID:      uuid.NewString(),
		Hostname:      "dpi-host",
		PrimaryIP:     "192.0.2.10",
		DBPool:        &pgxpool.Pool{},
		Scheduler:     &recordingEnqueuer{},
	}
}
