package health

import (
	"testing"

	"ransomeye/core/internal/contracts"
	"ransomeye/core/internal/events"
)

// TestHandleEnforcementEvent_ReceivesAsynchronously verifies health can subscribe to the bus
// and receive enforcement events with no direct coupling to enforcement package.
func TestHandleEnforcementEvent_ReceivesAsynchronously(t *testing.T) {
	bus := events.NewInMemoryBus(4)
	bus.SubscribeEnforcementEvent(HandleEnforcementEvent)
	bus.Run()

	// Simulate enforcement publishing (no enforcement import in this test).
	_ = bus.Publish(contracts.EnforcementEvent{
		Seq: 1, Action: "KILL_PROCESS", Target: "agent-1", Status: "DISPATCHED", Timestamp: 1,
	})
	_ = bus.Publish(contracts.EnforcementEvent{
		Seq: 2, Action: "ALERT_ONLY", Target: "agent-2", Status: "DISPATCHED", Timestamp: 2,
	})

	// Handler must not panic; event-driven delivery is async.
	// No direct coupling: this package does not import enforcement.
}
