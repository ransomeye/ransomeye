package events

import (
	"ransomeye/core/internal/contracts"
)

// EventBus is a fan-out bus for control-plane events (e.g. enforcement).
// Publish may block to enforce lossless delivery semantics.
// Detection events must use pipeline.Hub only; do not publish detection events to EventBus.
type EventBus interface {
	// Publish blocks until delivery is admitted to all subscribers.
	Publish(event contracts.Event) error
	// Subscribe registers a handler for all event types; each subscriber gets its own channel.
	Subscribe(handler func(contracts.Event))
	// SubscribeEnforcementEvent registers a handler for backward compatibility; receives only enforcement events.
	SubscribeEnforcementEvent(handler func(contracts.EnforcementEvent))
	// Run must be called after all subscriptions (no-op; kept for interface compatibility).
	Run()
}
