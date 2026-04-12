package ai

import (
	"testing"
	"time"
)

func TestTryEnqueueBackpressuresInsteadOfDropping(t *testing.T) {
	// Non-nil client: Mishka disables queuing when sidecar is absent (nil *Client).
	r := NewRouter(&Client{}, nil, 1, nil)

	r.TryEnqueue("event-1", "agent-1", []byte{0x01}, 1)

	done := make(chan struct{})
	go func() {
		r.TryEnqueue("event-2", "agent-1", []byte{0x02}, 2)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("TryEnqueue returned while queue was still full")
	case <-time.After(50 * time.Millisecond):
	}

	first := <-r.ch
	if first == nil || first.eventID != "event-1" {
		t.Fatalf("first queued item = %#v, want event-1", first)
	}
	r.releaseItem(first)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TryEnqueue did not unblock after queue capacity became available")
	}

	second := <-r.ch
	if second == nil || second.eventID != "event-2" {
		t.Fatalf("second queued item = %#v, want event-2", second)
	}
	r.releaseItem(second)

	if got := r.DroppedCount(); got != 0 {
		t.Fatalf("DroppedCount() = %d, want 0", got)
	}
}
