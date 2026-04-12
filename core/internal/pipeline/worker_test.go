package pipeline

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"ransomeye/core/internal/backpressure"
	wormcrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/health"
	"ransomeye/core/internal/ingest"
)

type stubSINE struct {
	allowed bool
	err     error
	record  func(string)
}

func (s *stubSINE) Filter(_ context.Context, _ []byte) (bool, error) {
	if s.record != nil {
		s.record("sine")
	}
	return s.allowed, s.err
}

type stubReleaser struct {
	released int
}

func (r *stubReleaser) ReleaseTelemetryPayload(_ *ingest.VerifiedTelemetry) {
	r.released++
}

type stubRouter struct {
	calls  int
	record func(string)
}

func (r *stubRouter) TryEnqueue(_ string, _ string, _ []byte, _ int64) {
	r.calls++
	if r.record != nil {
		r.record("route")
	}
}

type stubDetector struct {
	finding DetectionEvent
	err     error
	record  func(string)
}

func (d *stubDetector) Evaluate(_ *ingest.VerifiedTelemetry) (DetectionEvent, error) {
	if d.record != nil {
		d.record("detect")
	}
	if d.err != nil {
		return DetectionEvent{}, d.err
	}
	return d.finding, nil
}

func TestHandleOne_BlockedBySINE_SealsForensicOnlyAndStops(t *testing.T) {
	ev := testVerifiedTelemetry(t)
	var seq []string
	record := func(step string) { seq = append(seq, step) }

	releaser := &stubReleaser{}
	router := &stubRouter{record: record}
	persistCalls := 0

	pool := &WorkerPool{
		Releaser: releaser,
		AIRouter: router,
		SINE:     &stubSINE{allowed: false, record: record},
		persistAllowedFn: func(context.Context, *ingest.VerifiedTelemetry) (string, error) {
			persistCalls++
			record("persist")
			return "event-1", nil
		},
		sealForensicOnlyFn: func(context.Context, *ingest.VerifiedTelemetry) error {
			record("forensic")
			return nil
		},
	}

	if err := pool.handleOne(context.Background(), &Event{Payload: ev}); err != nil {
		t.Fatalf("handleOne: %v", err)
	}

	if persistCalls != 0 {
		t.Fatalf("persist called %d times for blocked event", persistCalls)
	}
	if router.calls != 0 {
		t.Fatalf("blocked event should not reach routing, got %d route calls", router.calls)
	}
	if releaser.released != 1 {
		t.Fatalf("payload release count = %d, want 1", releaser.released)
	}

	want := []string{"sine", "forensic"}
	if !reflect.DeepEqual(seq, want) {
		t.Fatalf("sequence = %v, want %v", seq, want)
	}
}

func TestHandleOne_AllowedPersistsOnlyAfterSINE(t *testing.T) {
	ev := testVerifiedTelemetry(t)
	var seq []string
	record := func(step string) { seq = append(seq, step) }

	releaser := &stubReleaser{}
	router := &stubRouter{record: record}
	persistCalls := 0

	pool := &WorkerPool{
		Releaser: releaser,
		AIRouter: router,
		SINE:     &stubSINE{allowed: true, record: record},
		persistAllowedFn: func(context.Context, *ingest.VerifiedTelemetry) (string, error) {
			persistCalls++
			record("persist")
			return "event-1", nil
		},
	}

	if err := pool.handleOne(context.Background(), &Event{Payload: ev}); err != nil {
		t.Fatalf("handleOne: %v", err)
	}

	if persistCalls != 1 {
		t.Fatalf("persist called %d times, want 1", persistCalls)
	}
	if router.calls != 1 {
		t.Fatalf("route calls = %d, want 1", router.calls)
	}
	if releaser.released != 1 {
		t.Fatalf("payload release count = %d, want 1", releaser.released)
	}

	want := []string{"sine", "persist", "route"}
	if !reflect.DeepEqual(seq, want) {
		t.Fatalf("sequence = %v, want %v", seq, want)
	}
}

func TestHandleOne_SINEUnavailable_DegradesAndStops(t *testing.T) {
	ev := testVerifiedTelemetry(t)
	var seq []string
	record := func(step string) { seq = append(seq, step) }

	health.SetSystemState(&health.SystemState{
		SINEReady:       true,
		PipelineHealthy: true,
	})
	t.Cleanup(func() { health.SetSystemState(&health.SystemState{}) })

	releaser := &stubReleaser{}
	router := &stubRouter{record: record}
	persistCalls := 0

	pool := &WorkerPool{
		Releaser: releaser,
		AIRouter: router,
		SINE:     &stubSINE{err: errors.New("SINE_UNAVAILABLE"), record: record},
		persistAllowedFn: func(context.Context, *ingest.VerifiedTelemetry) (string, error) {
			persistCalls++
			record("persist")
			return "event-1", nil
		},
		sealForensicOnlyFn: func(context.Context, *ingest.VerifiedTelemetry) error {
			record("forensic")
			return nil
		},
	}

	err := pool.handleOne(context.Background(), &Event{Payload: ev})
	if err == nil {
		t.Fatal("expected SINE unavailable error")
	}

	if persistCalls != 0 {
		t.Fatalf("persist called %d times for degraded event", persistCalls)
	}
	if router.calls != 0 {
		t.Fatalf("degraded event should not reach routing, got %d route calls", router.calls)
	}
	if releaser.released != 1 {
		t.Fatalf("payload release count = %d, want 1", releaser.released)
	}

	s := health.GetSystemState()
	if s.SINEReady {
		t.Fatal("expected SINEReady=false after SINE_DOWN degradation")
	}
	if s.PipelineHealthy {
		t.Fatal("expected PipelineHealthy=false after SINE_DOWN degradation")
	}

	want := []string{"sine", "forensic"}
	if !reflect.DeepEqual(seq, want) {
		t.Fatalf("sequence = %v, want %v", seq, want)
	}
}

func TestHandleOne_LowConfidenceSkipsSINEAndAIRouter(t *testing.T) {
	ev := testVerifiedTelemetry(t)
	var seq []string
	record := func(step string) { seq = append(seq, step) }

	releaser := &stubReleaser{}
	router := &stubRouter{record: record}
	sine := &stubSINE{allowed: true, record: record}
	persistCalls := 0

	pool := &WorkerPool{
		Releaser: releaser,
		Detector: &stubDetector{
			record: record,
			finding: DetectionEvent{
				Confidence: 0.2,
				Decision:   "benign",
				SinePass:   false,
			},
		},
		AIRouter: router,
		SINE:     sine,
		persistAllowedFn: func(context.Context, *ingest.VerifiedTelemetry) (string, error) {
			persistCalls++
			record("persist")
			return "event-1", nil
		},
	}

	if err := pool.handleOne(context.Background(), &Event{Payload: ev}); err != nil {
		t.Fatalf("handleOne: %v", err)
	}

	if persistCalls != 1 {
		t.Fatalf("persist called %d times, want 1", persistCalls)
	}
	if router.calls != 0 {
		t.Fatalf("route calls = %d, want 0", router.calls)
	}
	if releaser.released != 1 {
		t.Fatalf("payload release count = %d, want 1", releaser.released)
	}
	want := []string{"detect", "persist"}
	if !reflect.DeepEqual(seq, want) {
		t.Fatalf("sequence = %v, want %v", seq, want)
	}
}

func TestHandleOne_MaliciousDetectionPublishesScoredPayload(t *testing.T) {
	ev := testVerifiedTelemetry(t)
	var seq []string
	record := func(step string) { seq = append(seq, step) }

	releaser := &stubReleaser{}
	router := &stubRouter{record: record}
	sine := &stubSINE{allowed: true, record: record}
	hub := NewHub()
	sub := hub.Subscribe(2)
	persistCalls := 0

	t.Cleanup(func() { health.SetSystemState(&health.SystemState{}) })

	pool := &WorkerPool{
		Releaser: releaser,
		Detector: &stubDetector{
			record: record,
			finding: DetectionEvent{
				Confidence:      0.91,
				Decision:        "malicious",
				ModelPrediction: 0.82,
				EntropyScore:    0.7,
				BurstScore:      1.0,
				ProcessAnomaly:  0.6,
				SinePass:        true,
				Explanation: []DetectionContribution{
					{Feature: "model_prediction", Impact: 0.451, Value: 0.82},
					{Feature: "burst_score", Impact: 0.15, Value: 1.0},
				},
			},
		},
		AIRouter: router,
		SINE:     sine,
		Hub:      hub,
		persistAllowedFn: func(context.Context, *ingest.VerifiedTelemetry) (string, error) {
			persistCalls++
			record("persist")
			return "event-1", nil
		},
		persistDetectionFn: func(context.Context, string, *ingest.VerifiedTelemetry, DetectionEvent) error {
			record("detect-persist")
			return nil
		},
	}

	if err := pool.handleOne(context.Background(), &Event{Payload: ev}); err != nil {
		t.Fatalf("handleOne: %v", err)
	}

	if persistCalls != 1 {
		t.Fatalf("persist called %d times, want 1", persistCalls)
	}
	if router.calls != 1 {
		t.Fatalf("route calls = %d, want 1", router.calls)
	}
	if releaser.released != 1 {
		t.Fatalf("payload release count = %d, want 1", releaser.released)
	}
	wantSeq := []string{"detect", "sine", "persist", "detect-persist", "route"}
	if !reflect.DeepEqual(seq, wantSeq) {
		t.Fatalf("sequence = %v, want %v", seq, wantSeq)
	}

	select {
	case env := <-sub:
		if env == nil {
			t.Fatal("nil detection envelope")
		}
		defer env.Release()
		var payload struct {
			Type            string  `json:"type"`
			Status          string  `json:"status"`
			Decision        string  `json:"decision"`
			Score           float64 `json:"score"`
			ModelPrediction float64 `json:"model_prediction"`
			EntropyScore    float64 `json:"entropy_score"`
			BurstScore      float64 `json:"burst_score"`
			ProcessAnomaly  float64 `json:"process_anomaly"`
			Explanation     []struct {
				Feature string  `json:"feature"`
				Impact  float64 `json:"impact"`
				Value   float64 `json:"value"`
			} `json:"explanation"`
		}
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			t.Fatalf("json.Unmarshal detection payload: %v", err)
		}
		if payload.Type != "detection" {
			t.Fatalf("payload type = %s, want detection", payload.Type)
		}
		if payload.Status != "malicious" || payload.Decision != "malicious" {
			t.Fatalf("payload status/decision = %s/%s, want malicious/malicious", payload.Status, payload.Decision)
		}
		if payload.Score != 0.91 {
			t.Fatalf("payload score = %.8f, want 0.91", payload.Score)
		}
		if payload.ModelPrediction != 0.82 || payload.EntropyScore != 0.7 || payload.BurstScore != 1.0 || payload.ProcessAnomaly != 0.6 {
			t.Fatalf(
				"unexpected signal breakdown: model=%.8f entropy=%.8f burst=%.8f process=%.8f",
				payload.ModelPrediction,
				payload.EntropyScore,
				payload.BurstScore,
				payload.ProcessAnomaly,
			)
		}
		if len(payload.Explanation) != 2 {
			t.Fatalf("explanation length = %d, want 2", len(payload.Explanation))
		}
		if payload.Explanation[0].Feature != "model_prediction" || payload.Explanation[1].Feature != "burst_score" {
			t.Fatalf("unexpected explanation ordering: %+v", payload.Explanation)
		}
	default:
		t.Fatal("expected detection envelope")
	}
}

func TestHandleOne_MaliciousDetectionPersistsWhenAISidecarUnready(t *testing.T) {
	ev := testVerifiedTelemetry(t)
	releaser := &stubReleaser{}
	hub := NewHub()
	sub := hub.Subscribe(1)
	detectPersistCalls := 0

	health.SetSystemState(&health.SystemState{AIReady: false})
	t.Cleanup(func() { health.SetSystemState(&health.SystemState{}) })

	pool := &WorkerPool{
		Releaser: releaser,
		Detector: &stubDetector{
			finding: DetectionEvent{
				Confidence: 0.91,
				Decision:   "malicious",
				SinePass:   true,
			},
		},
		AIRouter: &stubRouter{},
		SINE:     &stubSINE{allowed: true},
		Hub:      hub,
		persistAllowedFn: func(context.Context, *ingest.VerifiedTelemetry) (string, error) {
			return "event-1", nil
		},
		persistDetectionFn: func(context.Context, string, *ingest.VerifiedTelemetry, DetectionEvent) error {
			detectPersistCalls++
			return nil
		},
	}

	if err := pool.handleOne(context.Background(), &Event{Payload: ev}); err != nil {
		t.Fatalf("handleOne: %v", err)
	}
	if detectPersistCalls != 1 {
		t.Fatalf("persistDetection called %d times, want 1", detectPersistCalls)
	}
	if releaser.released != 1 {
		t.Fatalf("payload release count = %d, want 1", releaser.released)
	}
	select {
	case env := <-sub:
		if env == nil {
			t.Fatal("nil detection envelope")
		}
		env.Release()
	default:
		t.Fatal("expected detection envelope on hub (deterministic path, not gated on AI sidecar)")
	}
}

func TestSealForensicOnly_WritesBlockedEvidenceWithoutDB(t *testing.T) {
	root := t.TempDir()
	t.Setenv("WORM_STORAGE_PATH", root)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	w, err := wormcrypto.NewWORM(priv, aesKey)
	if err != nil {
		t.Fatalf("NewWORM: %v", err)
	}

	pool := &WorkerPool{WORM: w}
	ev := testVerifiedTelemetry(t)

	if err := pool.sealForensicOnly(context.Background(), ev); err != nil {
		t.Fatalf("sealForensicOnly: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(root, "blocked", ev.AgentIDStr, "forensic-only", "*.sealed"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("sealed file count = %d, want 1", len(matches))
	}

	st, err := os.Stat(matches[0])
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Mode().Perm() != 0o444 {
		t.Fatalf("sealed file perm = %#o, want 0444", st.Mode().Perm())
	}
}

func TestBuildWORMRecordPayloadIncludesDroppedPacketsBefore(t *testing.T) {
	ev := testVerifiedTelemetry(t)
	ev.DroppedCount = 9

	recordPayload, err := buildWORMRecordPayload(ev)
	if err != nil {
		t.Fatalf("buildWORMRecordPayload: %v", err)
	}

	var record struct {
		DroppedPacketsBefore uint64 `json:"dropped_packets_before"`
		PayloadBytesBase64   string `json:"payload_bytes_base64"`
		PayloadSHA256        string `json:"payload_sha256"`
	}
	if err := json.Unmarshal(recordPayload, &record); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if record.DroppedPacketsBefore != 9 {
		t.Fatalf("dropped_packets_before = %d, want 9", record.DroppedPacketsBefore)
	}
	if record.PayloadBytesBase64 != base64.StdEncoding.EncodeToString(ev.Payload) {
		t.Fatal("payload_bytes_base64 mismatch")
	}
	payloadHash := sha256.Sum256(ev.Payload)
	if record.PayloadSHA256 != hex.EncodeToString(payloadHash[:]) {
		t.Fatal("payload_sha256 mismatch")
	}
}

func testVerifiedTelemetry(t *testing.T) *ingest.VerifiedTelemetry {
	t.Helper()

	agentID := uuid.New()
	eventID := uuid.New()
	var processHash [32]byte
	var fileHash [32]byte
	var networkTuple [16]byte
	var bootSessionID [16]byte

	payload, err := ingest.BuildCanonicalV1(
		42,
		agentID,
		eventID,
		ingest.EventTypeCodeProcess,
		1234,
		processHash,
		fileHash,
		networkTuple,
		1_700_000_000,
		bootSessionID,
	)
	if err != nil {
		t.Fatalf("BuildCanonicalV1: %v", err)
	}

	return &ingest.VerifiedTelemetry{
		Payload:        payload[:],
		AgentSignature: make([]byte, 64),
		AgentIDStr:     agentID.String(),
		EventType:      "PROCESS_EVENT",
		TimestampUnix:  1700000000,
		LogicalClock:   42,
		DroppedCount:   0,
	}
}

// TestBoundedRetryDoesNotLoopInfinitely ensures that hub publication retries
// are strictly bounded by MaxBackpressureRetries and do not loop indefinitely.
// The mandate requires ZERO LOSS but also FAIL-CLOSED behavior: after fixed
// retries the error must propagate upstream to the gateway.
func TestBoundedRetryDoesNotLoopInfinitely(t *testing.T) {
	ev := testVerifiedTelemetry(t)
	hub := NewHub()
	sub := hub.Subscribe(0) // unbuffered, always full
	defer hub.Unsubscribe(sub)

	engine := backpressure.NewEngine()
	pool := &WorkerPool{
		Hub:                hub,
		BackpressureEngine: engine,
		Releaser:           &stubReleaser{},
	}

	start := engine.Snapshot().State
	if start != backpressure.StateNormal {
		t.Fatalf("unexpected start state: %v", start)
	}

	// emitLegacyDetectionEvent must exhaust MaxBackpressureRetries and return ErrBackpressure.
	err := pool.emitLegacyDetectionEvent("event-1", ev)
	if !errors.Is(err, ErrBackpressure) {
		t.Fatalf("expected ErrBackpressure, got: %v", err)
	}

	// Shared backpressure engine must now be in PRESSURE state.
	state := engine.Snapshot().State
	if state != backpressure.StatePressure {
		t.Fatalf("expected PRESSURE state after retry exhaustion, got: %v", state)
	}
}
