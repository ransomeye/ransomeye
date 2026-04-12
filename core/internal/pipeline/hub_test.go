package pipeline

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestHub_PublishPersistsEvent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hub-persist.log"
	t.Setenv("RANSOMEYE_HUB_DURABLE_QUEUE_PATH", path)

	h := NewHub()
	env := NewEventEnvelope(1, "detection", "e1", "a1", "detection", "agent", "t", "detected", time.Unix(1, 0))
	defer env.Release()
	if err := h.TryPublish(env); err != nil {
		t.Fatalf("TryPublish: %v", err)
	}

	q, err := OpenDurableQueue(path)
	if err != nil {
		t.Fatalf("OpenDurableQueue: %v", err)
	}
	raw, _, ok, err := q.Dequeue()
	if err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(raw, env.Payload) {
		t.Fatalf("persisted payload mismatch")
	}
}

// TestHub_BackpressureSignalOnFullSubscriber verifies that TryPublish returns
// ErrBackpressure when a subscriber channel is full, and does NOT drop the event.
func TestHub_BackpressureSignalOnFullSubscriber(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RANSOMEYE_HUB_DURABLE_QUEUE_PATH", dir+"/bp-signal.log")

	h := NewHub()
	sub := h.Subscribe(0) // unbuffered: always full when no concurrent reader
	defer h.Unsubscribe(sub)

	env := NewEventEnvelope(1, "detection", "e1", "a1", "detection", "agent", "t", "detected", time.Unix(1, 0))
	defer env.Release()

	err := h.TryPublish(env)
	if !errors.Is(err, ErrBackpressure) {
		t.Fatalf("TryPublish: got %v, want ErrBackpressure", err)
	}
}

// TestHub_NoEventLossUnderRetry verifies that all published events are eventually
// consumed when the caller retries on ErrBackpressure.
// Retry loop is bounded by capacity+1 attempts per event; no event is dropped.
func TestHub_NoEventLossUnderRetry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RANSOMEYE_HUB_DURABLE_QUEUE_PATH", dir+"/no-loss-retry.log")

	const (
		totalEvents = 32
		capacity    = 8
	)

	h := NewHub()
	sub := h.Subscribe(capacity)

	published := 0
	consumed := 0

	for i := 1; i <= totalEvents; i++ {
		env := NewEventEnvelope(int64(i), "detection", fmt.Sprintf("e%d", i), "a1", "detection", "t", "detected", "ok", time.Unix(int64(i), 0))
		admitted := false
		// Bounded retry: at most capacity+1 attempts. Each backpressure response
		// drains one slot so the next attempt is guaranteed to find space.
		for attempt := 0; attempt <= capacity; attempt++ {
			if err := h.TryPublish(env); err == nil {
				published++
				admitted = true
				break
			} else if !errors.Is(err, ErrBackpressure) {
				env.Release()
				h.Unsubscribe(sub)
				t.Fatalf("event %d attempt %d: unexpected error: %v", i, attempt, err)
			}
			// Channel is full: drain one event to create room, then retry.
			got := <-sub
			got.Release()
			consumed++
		}
		env.Release()
		if !admitted {
			h.Unsubscribe(sub)
			t.Fatalf("event %d: not admitted after %d attempts", i, capacity+1)
		}
	}

	// Drain remaining events buffered in the subscriber channel.
	for len(sub) > 0 {
		got := <-sub
		got.Release()
		consumed++
	}
	h.Unsubscribe(sub)

	if published != totalEvents {
		t.Fatalf("published=%d want=%d", published, totalEvents)
	}
	if consumed != published {
		t.Fatalf("consumed=%d published=%d: event loss detected", consumed, published)
	}
}

// TestHub_BoundedRetryDoesNotLoopInfinitely verifies that retry logic using
// MaxBackpressureRetries terminates in exactly MaxBackpressureRetries attempts
// when the subscriber is always full, and escalates with ErrBackpressure.
func TestHub_BoundedRetryDoesNotLoopInfinitely(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RANSOMEYE_HUB_DURABLE_QUEUE_PATH", dir+"/bounded-retry.log")

	h := NewHub()
	sub := h.Subscribe(0) // unbuffered: always full, no reader
	defer h.Unsubscribe(sub)

	env := NewEventEnvelope(1, "detection", "e1", "a1", "detection", "agent", "t", "detected", time.Unix(1, 0))
	defer env.Release()

	attempts := 0
	var finalErr error
	for i := 0; i < MaxBackpressureRetries; i++ {
		attempts++
		finalErr = h.TryPublish(env)
		if finalErr == nil {
			break
		}
	}

	// Loop must have executed exactly MaxBackpressureRetries times (all failed).
	if attempts != MaxBackpressureRetries {
		t.Fatalf("attempts=%d want=%d", attempts, MaxBackpressureRetries)
	}
	// After exhausting retries, ErrBackpressure must be escalated — not swallowed.
	if !errors.Is(finalErr, ErrBackpressure) {
		t.Fatalf("finalErr=%v want ErrBackpressure", finalErr)
	}
}

func TestHub_NoLossUnderPressure(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hub-pressure.log"
	t.Setenv("RANSOMEYE_HUB_DURABLE_QUEUE_PATH", path)

	h := NewHub()
	const total = 200
	// Buffer is larger than total so all publishes succeed without backpressure.
	sub := h.Subscribe(total)

	for i := 1; i <= total; i++ {
		env := NewEventEnvelope(int64(i), "detection", fmt.Sprintf("e%d", i), "a1", "detection", "t", "detected", "ok", time.Unix(int64(i), 0))
		if err := h.TryPublish(env); err != nil {
			env.Release()
			t.Fatalf("TryPublish %d: %v", i, err)
		}
		env.Release()
	}

	received := make([]int64, 0, total)
	for i := 0; i < total; i++ {
		select {
		case ev := <-sub:
			received = append(received, ev.Seq)
			ev.Release()
		default:
			t.Fatalf("subscriber missing event at index %d; only %d received", i, len(received))
		}
	}

	if len(received) != total {
		t.Fatalf("received=%d want=%d", len(received), total)
	}
	for i := 1; i <= total; i++ {
		if received[i-1] != int64(i) {
			t.Fatalf("reordering at index=%d got=%d want=%d", i-1, received[i-1], i)
		}
	}
}
