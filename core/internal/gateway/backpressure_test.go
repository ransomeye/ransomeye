package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/backpressure"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/pipeline"
	pb "ransomeye/proto/ransomeyepb"
)

func TestPressureModeRejectsNewTelemetryAndPreservesQueuedEvents(t *testing.T) {
	h, ctx, env, _ := manualTelemetryFixture(t)

	for i := 0; i < h.ingestQueue.Capacity(); i++ {
		if _, err := h.ingestQueue.Admit(queueFillTelemetry(t, uint64(i+1))); err != nil {
			t.Fatalf("fill queue item %d: %v", i, err)
		}
	}

	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("status=%s want=%s err=%v", status.Code(err), codes.ResourceExhausted, err)
	}
	if !strings.Contains(err.Error(), "RESOURCE_EXHAUSTED: PRESSURE") {
		t.Fatalf("unexpected error: %v", err)
	}

	ev1, err := h.ingestQueue.DequeueNext()
	if err != nil {
		t.Fatalf("dequeue first queued event: %v", err)
	}
	ev2, err := h.ingestQueue.DequeueNext()
	if err != nil {
		t.Fatalf("dequeue second queued event: %v", err)
	}
	if ev1 == nil || ev2 == nil {
		t.Fatal("expected both pre-existing queued events to remain available")
	}
	if err := h.ingestQueue.Resolve(ev1.Sequence); err != nil {
		t.Fatalf("resolve first queued event: %v", err)
	}
	if err := h.ingestQueue.Resolve(ev2.Sequence); err != nil {
		t.Fatalf("resolve second queued event: %v", err)
	}
}

func TestFailsafeModeHaltsTelemetryIngestion(t *testing.T) {
	h, ctx, env, _ := manualTelemetryFixture(t)

	h.ingestQueue.SetDiskExhaustedForTest(true)

	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("status=%s want=%s err=%v", status.Code(err), codes.ResourceExhausted, err)
	}
	if !strings.Contains(err.Error(), "RESOURCE_EXHAUSTED: FAILSAFE") {
		t.Fatalf("unexpected error: %v", err)
	}
	if depth := h.ingestQueue.Depth(); depth != 0 {
		t.Fatalf("queue depth=%d want=0", depth)
	}
}

func TestFailsafeRecoveryResumesTelemetryIngestion(t *testing.T) {
	h, ctx, env, _, recorder := validTelemetryFixture(t)

	h.ingestQueue.SetDiskExhaustedForTest(true)
	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("status=%s want=%s err=%v", status.Code(err), codes.ResourceExhausted, err)
	}

	h.ingestQueue.SetDiskExhaustedForTest(false)

	ack, err := h.SendTelemetry(ctx, env)
	if err != nil {
		t.Fatalf("SendTelemetry after recovery: %v", err)
	}
	if !ack.GetAccepted() {
		t.Fatal("expected accepted ack after recovery")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		recorder.mu.Lock()
		count := recorder.enqueueCount
		recorder.mu.Unlock()
		if count == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected recorder to observe recovered enqueue")
}

func queueFillTelemetry(t *testing.T, logicalClock uint64) *ingest.VerifiedTelemetry {
	t.Helper()

	agentID := mustParseUUID(t, testAgentID)
	bootSessionID := mustParseUUID(t, testBootSessionID)
	eventID := uuid.NewSHA1(uuid.MustParse(testEventID), []byte{byte(logicalClock)})
	payload, err := ingest.BuildCanonicalV1(
		logicalClock,
		agentID,
		eventID,
		ingest.EventTypeCodeProcess,
		17,
		[32]byte{1},
		[32]byte{2},
		[16]byte{3},
		testTimestampUnixNano+logicalClock,
		[16]byte(bootSessionID),
	)
	if err != nil {
		t.Fatalf("BuildCanonicalV1: %v", err)
	}

	return &ingest.VerifiedTelemetry{
		Payload:        append([]byte(nil), payload[:]...),
		AgentSignature: bytesOfLen(64, byte(logicalClock)),
		AgentIDStr:     agentID.String(),
		EventType:      "PROCESS_EVENT",
		TimestampUnix:  float64(testTimestampUnixNano+logicalClock) / 1e9,
		LogicalClock:   int64(logicalClock),
	}
}

// noopPayloadReleaser satisfies pipeline.PayloadReleaser for tests that do not
// need payload pool tracking.
type noopPayloadReleaser struct{}

func (r *noopPayloadReleaser) ReleaseTelemetryPayload(_ *ingest.VerifiedTelemetry) {}

// TestBackpressureEscalatesToGateway is the end-to-end zero-loss guarantee:
// when the hub fan-out exhausts MaxBackpressureRetries the shared backpressure
// engine is signalled to PRESSURE and the gateway returns RESOURCE_EXHAUSTED for
// any subsequent ingest, preventing new accepted events from being silently
// dropped.
func TestBackpressureEscalatesToGateway(t *testing.T) {
	h, ctx, env, _ := manualTelemetryFixture(t)

	// Hub with a single unbuffered subscriber (always full — no reader).
	// TryPublish will return ErrBackpressure on every attempt.
	hub := pipeline.NewHub()
	sub := hub.Subscribe(0)
	defer hub.Unsubscribe(sub)

	// WorkerPool shares the gateway's backpressure engine so that hub
	// backpressure escalates to the gateway admission boundary.
	pool := &pipeline.WorkerPool{
		Hub:                hub,
		BackpressureEngine: h.BackpressureEngine(),
		Releaser:           &noopPayloadReleaser{},
	}
	pool.SetPersistAllowedFunc(func(_ context.Context, _ *ingest.VerifiedTelemetry) (string, error) {
		return "event-e2e-bp-test", nil
	})

	// ProcessOne persists the event then attempts to emit the detection fan-out
	// to the always-full hub. After MaxBackpressureRetries the engine is
	// signalled to PRESSURE.
	ev := queueFillTelemetry(t, 42)
	_ = pool.ProcessOne(ctx, ev) // ErrBackpressure expected; engine now PRESSURE

	// Gateway must now block new ingress: zero-loss guarantee requires that
	// any event arriving while hub is saturated is rejected at the boundary
	// (RESOURCE_EXHAUSTED) rather than accepted and silently dropped.
	_, err := h.SendTelemetry(ctx, env)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected RESOURCE_EXHAUSTED after hub backpressure escalation, got: %v", err)
	}
	if !strings.Contains(err.Error(), "RESOURCE_EXHAUSTED") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

type gatewayActionStreamMock struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan *pb.ActionCommand
}

func (m *gatewayActionStreamMock) Send(cmd *pb.ActionCommand) error {
	if m.sent != nil {
		m.sent <- cmd
	}
	return nil
}

func (m *gatewayActionStreamMock) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

func TestBackpressureControlStreamPublishesTransitions(t *testing.T) {
	h := NewHandlers(nil, nil, nil)
	stream := &gatewayActionStreamMock{sent: make(chan *pb.ActionCommand, 4)}
	wrapped := newActionStreamWrapper(stream)
	h.registerActionStream("agent-1", wrapped)
	defer h.unregisterActionStream("agent-1")

	h.publishBackpressureState(backpressure.Assessment{
		State:  backpressure.StatePressure,
		Reason: "memory threshold reached",
	})

	select {
	case cmd := <-stream.sent:
		if cmd.GetActionType() != pb.ActionType_ALERT_ONLY {
			t.Fatalf("action_type=%v want=%v", cmd.GetActionType(), pb.ActionType_ALERT_ONLY)
		}
		if !strings.Contains(cmd.GetParametersJson(), `"control":"backpressure"`) {
			t.Fatalf("parameters_json=%s", cmd.GetParametersJson())
		}
		if !strings.Contains(cmd.GetParametersJson(), `"state":"PRESSURE"`) {
			t.Fatalf("parameters_json=%s", cmd.GetParametersJson())
		}
		if !strings.Contains(cmd.GetParametersJson(), `"signal":"RESOURCE_EXHAUSTED"`) {
			t.Fatalf("parameters_json=%s", cmd.GetParametersJson())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pressure control message")
	}

	h.publishBackpressureState(backpressure.Assessment{State: backpressure.StatePressure})
	select {
	case cmd := <-stream.sent:
		t.Fatalf("unexpected duplicate pressure control message: %+v", cmd)
	case <-time.After(200 * time.Millisecond):
	}

	h.publishBackpressureState(backpressure.Assessment{State: backpressure.StateNormal})
	select {
	case cmd := <-stream.sent:
		if !strings.Contains(cmd.GetParametersJson(), `"state":"NORMAL"`) {
			t.Fatalf("parameters_json=%s", cmd.GetParametersJson())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for normal control message")
	}
}
