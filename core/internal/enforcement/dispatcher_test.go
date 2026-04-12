package enforcement

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	"ransomeye/core/internal/contracts"
	"ransomeye/core/internal/forensics"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/policy"
	pb "ransomeye/proto/ransomeyepb"
)

type mockStream struct {
	grpc.ServerStream
	sendErr error
	sent    chan *pb.ActionCommand
}

func (m *mockStream) Send(cmd *pb.ActionCommand) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	if m.sent != nil {
		m.sent <- cmd
	}
	return nil
}

func (m *mockStream) Context() context.Context { return context.Background() }

type capturingBus struct {
	mu     sync.Mutex
	events []contracts.Event
	ch     chan contracts.Event
}

func (c *capturingBus) Publish(e contracts.Event) error {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
	if c.ch != nil {
		c.ch <- e
	}
	return nil
}

func (c *capturingBus) Subscribe(func(contracts.Event))                            {}
func (c *capturingBus) SubscribeEnforcementEvent(func(contracts.EnforcementEvent)) {}
func (c *capturingBus) Run()                                                       {}

type recordingRecorder struct {
	mu     sync.Mutex
	events []forensics.EnforcementEvent
	sig    []byte
}

func (r *recordingRecorder) Record(_ string, _ int64, event forensics.EnforcementEvent) (forensics.StoredEnforcementEvent, error) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
	return forensics.StoredEnforcementEvent{
		Event:     event,
		FilePath:  "/tmp/test.sealed",
		Signature: append([]byte(nil), r.sig...),
	}, nil
}

func TestDispatchEmitsRecordedEventOnSuccess(t *testing.T) {
	bus := &capturingBus{ch: make(chan contracts.Event, 1)}
	recorder := &recordingRecorder{sig: []byte("test-signature")}
	dispatcher := NewActionDispatcher(bus, recorder)
	stream := &mockStream{sent: make(chan *pb.ActionCommand, 1)}
	dispatcher.RegisterStream("agent-1", stream)
	t.Cleanup(func() { dispatcher.UnregisterStream("agent-1") })

	req := mustDispatchRequest(t, policy.EnforcementDecision{
		Action:  policy.ActionKillProcess,
		Allowed: true,
	})
	req.Command.ActionId = "act-1"

	if err := dispatcher.Dispatch(req); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	select {
	case cmd := <-stream.sent:
		if cmd.GetActionId() != "act-1" {
			t.Fatalf("sent action_id = %q, want act-1", cmd.GetActionId())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for streamed action")
	}

	select {
	case raw := <-bus.ch:
		ev, ok := raw.(*contracts.EnforcementEvent)
		if !ok {
			t.Fatalf("published type = %T, want *contracts.EnforcementEvent", raw)
		}
		if ev.Seq != 1 {
			t.Fatalf("seq = %d, want 1", ev.Seq)
		}
		if ev.Action != policy.ActionKillProcess {
			t.Fatalf("action = %q, want %q", ev.Action, policy.ActionKillProcess)
		}
		if ev.Target != "pid:1234" {
			t.Fatalf("target = %q, want pid:1234", ev.Target)
		}
		if string(ev.Signature) != "test-signature" {
			t.Fatalf("signature = %q, want test-signature", string(ev.Signature))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for published enforcement event")
	}
}

func TestDispatchSkipsDeniedDecision(t *testing.T) {
	bus := &capturingBus{ch: make(chan contracts.Event, 1)}
	recorder := &recordingRecorder{sig: []byte("test-signature")}
	dispatcher := NewActionDispatcher(bus, recorder)
	stream := &mockStream{sent: make(chan *pb.ActionCommand, 1)}
	dispatcher.RegisterStream("agent-1", stream)
	t.Cleanup(func() { dispatcher.UnregisterStream("agent-1") })

	req := mustDispatchRequest(t, policy.EnforcementDecision{
		Action:  policy.ActionKillProcess,
		Allowed: false,
	})
	err := dispatcher.Dispatch(req)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	select {
	case <-stream.sent:
		t.Fatal("policy-denied action must not be sent")
	case <-time.After(150 * time.Millisecond):
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.events) != 0 {
		t.Fatalf("recorder calls = %d, want 0", len(recorder.events))
	}
}

func TestBuildDispatchRequestDeterministic(t *testing.T) {
	agentID := mustUUID(t, "00000000-0000-0000-0000-000000000001")
	eventID := mustUUID(t, "00000000-0000-0000-0000-000000000002")
	var processHash [32]byte
	var fileHash [32]byte
	var networkTuple [16]byte
	var bootSessionID [16]byte

	payload, err := ingest.BuildCanonicalV1(
		11,
		agentID,
		eventID,
		ingest.EventTypeCodeProcess,
		4242,
		processHash,
		fileHash,
		networkTuple,
		1_700_000_000_000_000_000,
		bootSessionID,
	)
	if err != nil {
		t.Fatalf("BuildCanonicalV1: %v", err)
	}

	decision := policy.EnforcementDecision{
		Action:  policy.ActionKillProcess,
		Allowed: true,
	}

	req1, err := BuildDispatchRequestWithResolver(agentID.String(), eventID.String(), 11, 1_700_000_000, payload[:], 0.98, decision, testProcessBindingResolver)
	if err != nil {
		t.Fatalf("BuildDispatchRequestWithResolver #1: %v", err)
	}
	req2, err := BuildDispatchRequestWithResolver(agentID.String(), eventID.String(), 11, 1_700_000_000, payload[:], 0.98, decision, testProcessBindingResolver)
	if err != nil {
		t.Fatalf("BuildDispatchRequestWithResolver #2: %v", err)
	}

	if req1.Target != "pid:4242" {
		t.Fatalf("target = %q, want pid:4242", req1.Target)
	}
	if req1.Command.GetActionId() != req2.Command.GetActionId() {
		t.Fatalf("action ids differ: %s vs %s", req1.Command.GetActionId(), req2.Command.GetActionId())
	}
	if req1.Command.GetParametersJson() != req2.Command.GetParametersJson() {
		t.Fatalf("parameters_json differ: %s vs %s", req1.Command.GetParametersJson(), req2.Command.GetParametersJson())
	}
	if req1.Process.ExecutablePath != "/deterministic/pid/4242" {
		t.Fatalf("executable_path = %q, want /deterministic/pid/4242", req1.Process.ExecutablePath)
	}
	if req1.Process.KernelTag != "linux|test|amd64" {
		t.Fatalf("kernel_tag = %q, want linux|test|amd64", req1.Process.KernelTag)
	}
}

func mustUUID(t *testing.T, raw string) uuid.UUID {
	t.Helper()
	u, err := uuid.Parse(raw)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", raw, err)
	}
	return u
}

func mustDispatchRequest(t *testing.T, decision policy.EnforcementDecision) DispatchRequest {
	t.Helper()

	agentID := mustUUID(t, "00000000-0000-0000-0000-000000000001")
	eventID := mustUUID(t, "00000000-0000-0000-0000-000000000002")
	var processHash [32]byte
	var fileHash [32]byte
	var networkTuple [16]byte
	var bootSessionID [16]byte
	processHash[0] = 1

	payload, err := ingest.BuildCanonicalV1(
		7,
		agentID,
		eventID,
		ingest.EventTypeCodeProcess,
		1234,
		processHash,
		fileHash,
		networkTuple,
		1_700_000_000_000_000_000,
		bootSessionID,
	)
	if err != nil {
		t.Fatalf("BuildCanonicalV1: %v", err)
	}

	req, err := BuildDispatchRequestWithResolver(
		"agent-1",
		"det-1",
		7,
		1_700_000_000,
		payload[:],
		0.99,
		decision,
		testProcessBindingResolver,
	)
	if err != nil {
		t.Fatalf("BuildDispatchRequestWithResolver: %v", err)
	}
	return req
}

func testProcessBindingResolver(view ingest.TelemetryV1View) (ProcessBinding, error) {
	return ProcessBinding{
		ProcessHash:    hex.EncodeToString(view.ProcessHash[:]),
		ExecutablePath: fmt.Sprintf("/deterministic/pid/%d", view.AuxPID),
		KernelTag:      "linux|test|amd64",
	}, nil
}
