package events

import (
	"sync"

	"ransomeye/core/internal/contracts"
)

const (
	defaultBuffer = 256
)

// sub is one subscriber; receives unified Event.
type sub struct {
	ch chan contracts.Event
	idx int
	mu  sync.Mutex
}

// InMemoryBus is a fan-out bus for control-plane events only (e.g. enforcement).
// Detection events MUST NOT flow through this bus; they flow exclusively through pipeline.Hub.
type InMemoryBus struct {
	subs []*sub
	mu   sync.Mutex
	buf  int
}

// NewInMemoryBus returns an EventBus. Each subscriber gets a channel of size buffer.
func NewInMemoryBus(buffer int) *InMemoryBus {
	if buffer < 0 {
		buffer = defaultBuffer
	}
	return &InMemoryBus{
		subs: nil,
		buf:  buffer,
	}
}

// Publish delivers to all subscribers with blocking semantics.
// It does not drop or discard events.
func (b *InMemoryBus) Publish(event contracts.Event) error {
	if event == nil {
		return nil
	}
	b.mu.Lock()
	subs := make([]*sub, len(b.subs))
	copy(subs, b.subs)
	b.mu.Unlock()

	for _, s := range subs {
		s.ch <- event
	}
	return nil
}

// Subscribe registers a handler for all event types (detection + enforcement).
func (b *InMemoryBus) Subscribe(handler func(contracts.Event)) {
	if handler == nil {
		return
	}
	b.mu.Lock()
	ch := make(chan contracts.Event, b.buf)
	s := &sub{ch: ch, idx: len(b.subs)}
	b.subs = append(b.subs, s)
	b.mu.Unlock()
	go func() {
		for event := range ch {
			handler(event)
		}
	}()
}

// SubscribeEnforcementEvent registers a handler that receives only enforcement events (backward compat).
func (b *InMemoryBus) SubscribeEnforcementEvent(handler func(contracts.EnforcementEvent)) {
	if handler == nil {
		return
	}
	b.mu.Lock()
	ch := make(chan contracts.Event, b.buf)
	s := &sub{ch: ch, idx: len(b.subs)}
	b.subs = append(b.subs, s)
	b.mu.Unlock()
	go func() {
		for event := range ch {
			switch en := event.(type) {
			case *contracts.EnforcementEvent:
				handler(*en)
			case contracts.EnforcementEvent:
				handler(en)
			}
		}
	}()
}

// Run is a no-op for this design. Kept for interface.
func (b *InMemoryBus) Run() {}

// Close closes all subscriber channels. For tests and shutdown.
func (b *InMemoryBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.subs {
		close(s.ch)
	}
	b.subs = nil
}

// PanicBus is replaced by FailClosedBus.
func PanicBus() EventBus { return &failClosedBus{} }

type failClosedBus struct{}

func (*failClosedBus) Publish(contracts.Event) error       { return nil }
func (*failClosedBus) Subscribe(func(contracts.Event))      {}
func (*failClosedBus) SubscribeEnforcementEvent(func(contracts.EnforcementEvent)) {}
func (*failClosedBus) Run()                                {}
