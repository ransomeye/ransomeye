package pipeline

import (
	"testing"

	"ransomeye/core/internal/backpressure"
)

func TestIngestQueue_PressureAndRecovery(t *testing.T) {
	installIngestQueuePressureTestConfig(t)
	t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", t.TempDir()+"/ingest-queue-pressure.log")

	q := NewIngestQueue(2)
	if q == nil {
		t.Fatal("NewIngestQueue returned nil")
	}

	for i := 0; i < 2; i++ {
		if _, err := q.Admit(makeVerifiedTelemetryForSeq(t, int64(i+1))); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}

	_, err := q.Admit(makeVerifiedTelemetryForSeq(t, 3))
	if !backpressure.IsResourceExhausted(err) {
		t.Fatalf("expected pressure rejection, got %v", err)
	}
	if state, ok := backpressure.StateFromError(err); !ok || state != backpressure.StatePressure {
		t.Fatalf("state=%v ok=%v want=%v", state, ok, backpressure.StatePressure)
	}

	ev, err := q.DequeueNext()
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if ev == nil {
		t.Fatal("expected in-flight event")
	}
	if err := q.Resolve(ev.Sequence); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if _, err := q.Admit(makeVerifiedTelemetryForSeq(t, 4)); err != nil {
		t.Fatalf("admit after recovery: %v", err)
	}
}
