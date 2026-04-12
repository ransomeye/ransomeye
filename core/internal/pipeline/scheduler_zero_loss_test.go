package pipeline

import (
	"testing"

	"ransomeye/core/internal/ingest"
)

func TestScheduler_AdmitsWithinConfiguredCapacity(t *testing.T) {
	installRelaxedBackpressureConfigForTest(t)
	t.Setenv("RANSOMEYE_SCHEDULER_MEM_CAP", "2048")
	t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", t.TempDir()+"/scheduler-durable.log")

	s := &Scheduler{}
	const total = 2000
	for i := 0; i < total; i++ {
		ev := &ingest.VerifiedTelemetry{
			Payload:        []byte{1, 2, 3, 4},
			AgentSignature: make([]byte, 64),
			AgentIDStr:     "11111111-1111-4111-8111-111111111111",
			EventType:      "PROCESS_EVENT",
			TimestampUnix:  float64(i),
			LogicalClock:   int64(i + 1),
		}
		if err := s.Enqueue(ev); err != nil {
			t.Fatalf("enqueue %d failed: %v", i, err)
		}
	}

	got := 0
	for got < total {
		ev, err := s.DequeueNext()
		if err != nil {
			t.Fatalf("dequeue failed: %v", err)
		}
		if ev == nil {
			continue
		}
		got++
	}
	if got != total {
		t.Fatalf("dequeued=%d want=%d", got, total)
	}
}

func TestScheduler_PerAgentOrderingPreserved(t *testing.T) {
	installRelaxedBackpressureConfigForTest(t)
	t.Setenv("RANSOMEYE_SCHEDULER_MEM_CAP", "512")
	t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", t.TempDir()+"/scheduler-order.log")

	s := &Scheduler{}
	const total = 300
	for i := 0; i < total; i++ {
		ev := &ingest.VerifiedTelemetry{
			Payload:        []byte{1, 2, 3, 4},
			AgentSignature: make([]byte, 64),
			AgentIDStr:     "11111111-1111-4111-8111-111111111111",
			EventType:      "PROCESS_EVENT",
			TimestampUnix:  float64(i),
			LogicalClock:   int64(i + 1),
		}
		if err := s.Enqueue(ev); err != nil {
			t.Fatalf("enqueue %d failed: %v", i, err)
		}
	}

	lastClock := int64(0)
	for i := 0; i < total; i++ {
		ev, err := s.DequeueNext()
		if err != nil {
			t.Fatalf("dequeue failed: %v", err)
		}
		if ev == nil {
			i--
			continue
		}
		if ev.Payload.LogicalClock <= lastClock {
			t.Fatalf("ordering violation: got=%d last=%d", ev.Payload.LogicalClock, lastClock)
		}
		lastClock = ev.Payload.LogicalClock
	}
}
