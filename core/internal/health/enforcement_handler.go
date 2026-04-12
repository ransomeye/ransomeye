package health

import "ransomeye/core/internal/contracts"

// HandleEnforcementEvent processes enforcement events from the event bus (async subscriber).
// No direct coupling to enforcement package; called by events bus when enforcement publishes.
func HandleEnforcementEvent(event contracts.EnforcementEvent) {
	// Health tracking: update metrics, audit trail, or state as needed.
	// Deterministic: no I/O in hot path; optional metrics can be best-effort.
	_ = event
}
