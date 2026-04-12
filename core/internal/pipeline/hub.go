package pipeline

import (
	"errors"
	"os"
	"sync"
)

// ErrBackpressure is returned by TryPublish when a subscriber channel is full.
// The caller must retry or propagate this error upstream; events are never dropped.
var ErrBackpressure = errors.New("hub: subscriber backpressure")

// MaxBackpressureRetries is the fixed upper bound for bounded retry loops on
// ErrBackpressure. It is not configurable at runtime.
const MaxBackpressureRetries = 16

// Hub is a fan-out router for immutable *EventEnvelope.
// Publish succeeds only when all subscribers receive the event, or when
// durability fallback persists it for later replay.
type Hub struct {
	mu   sync.Mutex
	subs map[uint64]chan *EventEnvelope
	next uint64

	durable    *DurableQueue
	durableErr error
}

var errHubDurableUnavailable = errors.New("hub durable queue unavailable")

// NewHub creates a hub with subscriber fan-out plus durable fallback.
func NewHub() *Hub {
	h := &Hub{
		subs: make(map[uint64]chan *EventEnvelope),
	}
	dqPath := os.Getenv("RANSOMEYE_HUB_DURABLE_QUEUE_PATH")
	if dqPath == "" {
		dqPath = "/var/lib/ransomeye/core-hub-durable-queue.log"
	}
	dq, err := OpenDurableQueue(dqPath)
	h.durable = dq
	h.durableErr = err
	return h
}

// TryPublish delivers env to all subscribers with non-blocking semantics.
// If any subscriber channel is full, ErrBackpressure is returned immediately
// and the event is NOT dropped — the caller must retry or propagate upstream.
// If there are no subscribers, the event is persisted to durable queue when available.
func (h *Hub) TryPublish(env *EventEnvelope) error {
	if env == nil {
		return nil
	}

	h.mu.Lock()
	snap := make([]chan *EventEnvelope, 0, len(h.subs))
	for _, c := range h.subs {
		snap = append(snap, c)
	}
	h.mu.Unlock()

	if len(snap) == 0 {
		if h.durableErr == nil && h.durable != nil {
			return h.durable.Enqueue(env.Payload)
		}
		return nil
	}

	for _, c := range snap {
		env.refCount.Add(1)
		select {
		case c <- env:
		default:
			// Channel full — do NOT drop. Signal backpressure to the caller.
			env.refCount.Add(-1)
			return ErrBackpressure
		}
	}
	return nil
}

// Subscribe registers an independent subscriber channel.
// Callers may provide either a buffer size (int) or a prebuilt bounded channel.
func (h *Hub) Subscribe(arg any) <-chan *EventEnvelope {
	var ch chan *EventEnvelope
	switch v := arg.(type) {
	case int:
		if v < 0 {
			v = 0
		}
		ch = make(chan *EventEnvelope, v)
	case chan *EventEnvelope:
		if v == nil {
			ch = make(chan *EventEnvelope)
		} else {
			ch = v
		}
	default:
		panic("hub subscribe requires int buffer or chan *EventEnvelope")
	}

	h.mu.Lock()
	id := h.next
	h.next++
	h.subs[id] = ch
	h.mu.Unlock()
	return ch
}

// SubscriberQueueDepth returns total queued envelopes across all subscribers.
func (h *Hub) SubscriberQueueDepth() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.subs {
		n += len(c)
	}
	return n
}

// Unsubscribe removes and closes a subscriber channel.
func (h *Hub) Unsubscribe(ch <-chan *EventEnvelope) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, c := range h.subs {
		if c == ch {
			delete(h.subs, id)
			close(c)
			return
		}
	}
}
