package gateway

import (
	"testing"
	"time"
)

func TestACKNotReturnedBeforeCommitNotification(t *testing.T) {
	t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", t.TempDir()+"/ack-safety-durable.log")
	h, ctx, env, _ := manualTelemetryFixture(t)

	done := make(chan error, 1)
	go func() {
		_, err := h.SendTelemetry(ctx, env)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("ack returned before commit notification, err=%v", err)
	case <-time.After(150 * time.Millisecond):
	}

	var pending []string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending = h.ackController.PendingReplayKeys()
		if len(pending) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) == 0 {
		t.Fatal("no pending replay key registered")
	}
	ev, err := h.ingestQueue.DequeueNext()
	if err != nil {
		t.Fatalf("DequeueNext: %v", err)
	}
	if ev == nil {
		t.Fatal("expected queued event")
	}
	h.ackController.Commit(ev.Ack)
	if err := h.ingestQueue.Resolve(ev.Sequence); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendTelemetry failed after commit notification: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for ack after commit notification")
	}
}
