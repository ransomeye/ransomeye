package pipeline

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"testing"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/ingest"
)

func makeVerifiedTelemetryForSeq(t *testing.T, seq int64) *ingest.VerifiedTelemetry {
	t.Helper()
	return &ingest.VerifiedTelemetry{
		Payload:        []byte(fmt.Sprintf("payload-%d", seq)),
		AgentSignature: []byte(fmt.Sprintf("sig-%d", seq)),
		AgentIDStr:     "agent-1",
		EventType:      "TEST_EVENT",
		SourceType:     "syslog",
		// Keep timestamp stable/round-trippable through FormatFloat/ParseFloat in ringbuffer.go
		TimestampUnix: float64(seq),
		LogicalClock:  seq,
		DroppedCount:  0,
	}
}

func TestPersistedTelemetryRoundTripPreservesSourceType(t *testing.T) {
	ev := makeVerifiedTelemetryForSeq(t, 7)
	raw, err := serializeTelemetry(ev, ack.Metadata{}, 1)
	if err != nil {
		t.Fatalf("serializeTelemetry: %v", err)
	}
	_, restored, _, err := deserializeTelemetry(raw)
	if err != nil {
		t.Fatalf("deserializeTelemetry: %v", err)
	}
	if restored.SourceType != ev.SourceType {
		t.Fatalf("SourceType round-trip mismatch: got %q want %q", restored.SourceType, ev.SourceType)
	}
}

func popLogicalClockAll(t *testing.T, rb *RingBuffer, total int) []int64 {
	t.Helper()

	dst := make([]*ingest.VerifiedTelemetry, 1)
	out := make([]int64, 0, total)
	for len(out) < total {
		n, err := rb.Pop(dst)
		if err != nil {
			t.Fatalf("Pop: %v", err)
		}
		if n == 0 {
			// Wait for admission (memory enqueue or durable spill).
			rb.mu.Lock()
			for len(rb.memQ) == 0 {
				if rb.durable != nil && rb.durable.HasPending() {
					break
				}
				rb.cond.Wait()
			}
			rb.mu.Unlock()
			continue
		}
		out = append(out, dst[0].LogicalClock)
	}
	return out
}

func TestQueue_StrictFIFO_ConcurrentProducers(t *testing.T) {
	installRelaxedBackpressureConfigForTest(t)
	dir := t.TempDir()
	t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", dir+"/rb-fifo-concurrent.log")

	const producers = 12
	const perProducer = 50
	total := producers * perProducer

	rb := NewRingBuffer(1024)
	if rb == nil {
		t.Fatal("NewRingBuffer returned nil (invalid capacity or fail-closed)")
	}

	// Deterministic admission gate:
	// even under concurrent producer goroutines, we enforce that ringbuffer.Push is invoked
	// in strict seq-id order so we can prove FIFO = admission order.
	var (
		nextID   = 1
		nextMu   sync.Mutex
		nextCond = sync.NewCond(&nextMu)
		wg       sync.WaitGroup
	)

	wg.Add(producers)
	for p := 0; p < producers; p++ {
		p := p
		go func() {
			defer wg.Done()
			start := p*perProducer + 1
			end := start + perProducer
			for id := start; id < end; id++ {
				nextMu.Lock()
				for nextID != id {
					nextCond.Wait()
				}
				ev := makeVerifiedTelemetryForSeq(t, int64(id))
				if err := rb.Push(ev); err != nil {
					nextMu.Unlock()
					t.Fatalf("Push seq=%d: %v", id, err)
				}
				nextID++
				nextCond.Broadcast()
				nextMu.Unlock()
			}
		}()
	}

	gotCh := make(chan []int64, 1)
	go func() { gotCh <- popLogicalClockAll(t, rb, total) }()

	wg.Wait()
	got := <-gotCh

	if len(got) != total {
		t.Fatalf("received_count=%d sent_count=%d", len(got), total)
	}
	t.Logf("StrictFIFO concurrent: producers=%d perProducer=%d total=%d first=%d last=%d",
		producers, perProducer, total, got[0], got[len(got)-1])
	for i := 1; i <= total; i++ {
		if got[i-1] != int64(i) {
			t.Fatalf("fifo mismatch at pos=%d got=%d want=%d", i-1, got[i-1], i)
		}
	}
}

func TestQueue_FIFO_WithinConfiguredCapacity(t *testing.T) {
	installRelaxedBackpressureConfigForTest(t)
	dir := t.TempDir()
	t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", dir+"/rb-fifo-boundary.log")

	rb := NewRingBuffer(32)
	if rb == nil {
		t.Fatal("NewRingBuffer returned nil (invalid capacity or fail-closed)")
	}

	const total = 24
	expected := make([]int64, total)
	for i := 0; i < total; i++ {
		expected[i] = int64(i + 1)
		// Push in deterministic admission order.
		ev := makeVerifiedTelemetryForSeq(t, expected[i])
		if err := rb.Push(ev); err != nil {
			t.Fatalf("Push seq=%d: %v", expected[i], err)
		}
	}

	got := popLogicalClockAll(t, rb, total)
	if len(got) != total {
		t.Fatalf("received_count=%d sent_count=%d", len(got), total)
	}
	t.Logf("FIFO across boundary: memCap=%d total=%d first=%d last=%d", rb.memCap, total, got[0], got[len(got)-1])
	for i := 0; i < total; i++ {
		if got[i] != expected[i] {
			t.Fatalf("fifo mismatch at pos=%d got=%d want=%d", i, got[i], expected[i])
		}
	}

	// Durable queue stores every admitted event durably; file size > 0 proves persistence.
	st, err := os.Stat(dir + "/rb-fifo-boundary.log")
	if err != nil {
		t.Fatalf("stat durable log: %v", err)
	}
	if st.Size() == 0 {
		t.Fatalf("durable queue file is empty; expected persisted records")
	}
}

func TestQueue_DeterministicExecution(t *testing.T) {
	installRelaxedBackpressureConfigForTest(t)
	const total = 1000

	var firstHash [32]byte
	for run := 0; run < 10; run++ {
		dir := t.TempDir()
		t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", dir+"/rb-deterministic.log")

		rb := NewRingBuffer(1024)
		if rb == nil {
			t.Fatal("NewRingBuffer returned nil")
		}

		// Deterministic admission: single producer, strict seq order.
		for i := 1; i <= total; i++ {
			ev := makeVerifiedTelemetryForSeq(t, int64(i))
			if err := rb.Push(ev); err != nil {
				t.Fatalf("run=%d Push seq=%d: %v", run, i, err)
			}
		}

		got := popLogicalClockAll(t, rb, total)
		h := sha256.New()
		for _, seq := range got {
			// Byte-level determinism via fixed formatting.
			_, _ = h.Write([]byte(fmt.Sprintf("%d,", seq)))
		}
		sum := sha256.Sum256(h.Sum(nil))

		if run == 0 {
			firstHash = sum
			t.Logf("Determinism hash run=%d hash=%x total=%d", run, firstHash, total)
		} else if sum != firstHash {
			t.Fatalf("determinism hash mismatch run=%d got=%x want=%x", run, sum, firstHash)
		}
	}
}
