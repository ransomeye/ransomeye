package contracts

import "time"

// Event is the unified event type for the single pipeline. All events (detection + enforcement) implement Event.
// CanonicalPayload returns a deterministic string: seq|type|event_id|agent_id|action|target|status|timestamp
// (fields must not contain '|'; reproducible across versions).
type Event interface {
	CanonicalPayload() string
}

// EnforcementEvent is the shared payload for enforcement events (PRD-01).
// Seq is assigned by ActionDispatcher before publish (execution order). Signature is set by WORM before Publish.
type EnforcementEvent struct {
	Seq       int64  // Monotonic sequence (assigned by dispatcher)
	EventID   string // Action ID or detection ID
	AgentID   string
	Action    string
	Target    string
	Status    string
	Timestamp int64
	Signature []byte // Ed25519 seal from WORM; required before persistence
}

// CanonicalPayload implements Event. Strict format: seq|type|event_id|agent_id|action|target|status|timestamp
func (e EnforcementEvent) CanonicalPayload() string {
	return CanonicalString("enforcement", e.Seq, e.EventID, e.AgentID, e.Action, e.Target, e.Status, e.Timestamp)
}

// HealthReporter receives enforcement events for health tracking.
// Implemented by health package; used by enforcement via dependency injection.
type HealthReporter interface {
	ReportEnforcementEvent(event EnforcementEvent)
}

// DetectionEvent is the payload for detection events from the pipeline.
type DetectionEvent struct {
	Seq       int64
	EventID   string
	AgentID   string
	Action    string // e.g. "detection"
	Target    string // event_id for display
	Status    string
	Timestamp time.Time
}

// CanonicalPayload implements Event. Strict format: seq|type|event_id|agent_id|action|target|status|timestamp
func (e DetectionEvent) CanonicalPayload() string {
	ts := int64(0)
	if !e.Timestamp.IsZero() {
		ts = e.Timestamp.UTC().Unix()
	}
	return CanonicalString("detection", e.Seq, e.EventID, e.AgentID, e.Action, e.Target, e.Status, ts)
}
