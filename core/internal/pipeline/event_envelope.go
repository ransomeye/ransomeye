package pipeline

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// EventPriority determines drop behavior at hub: Critical (detections) must not be dropped at hub level.
// Per-subscriber full still drops; CriticalPerSubscriberDrops is incremented for alerting.
type EventPriority int

const (
	PriorityNormal   EventPriority = 0
	PriorityCritical EventPriority = 1 // Detections; never dropped at central hub (no central queue). Per-sub drops counted separately.
)

// canonicalPayload is the deterministic JSON payload for PRD-compliant event delivery.
// Field order is fixed by struct field order; payload is marshaled once and never mutated.
type canonicalPayload struct {
	Seq            int64  `json:"seq"`
	Type           string `json:"type"`
	EventID        string `json:"event_id"`
	AgentID        string `json:"agent_id"`
	Action         string `json:"action"`
	SourceType     string `json:"source_type"`
	Target         string `json:"target"`
	Status         string `json:"status"`
	Timestamp      int64  `json:"timestamp"`
	LogicalClock   int64  `json:"logical_clock"`
}

// EventEnvelope is immutable. Payload is created once via json.Marshal and must never be mutated.
// The same *EventEnvelope instance is fanned out to subscribers to preserve determinism.
// refCount is updated by Hub on each successful send; caller and each subscriber must call Release() when done.
type EventEnvelope struct {
	Seq        int64
	Type       string
	EventID    string
	AgentID    string
	Action     string
	SourceType string
	Target     string
	Status     string
	Timestamp  time.Time
	Priority   EventPriority

	// Payload is deterministic JSON bytes (created once at construction).
	Payload []byte

	refCount atomic.Int32
}

var envelopePool = sync.Pool{
	New: func() any { return &EventEnvelope{} },
}

// GetEventEnvelope returns an envelope from the pool (or allocates). Caller must call Release when done.
// Initial refCount is 1 (caller). Hub adds 1 per successful send; each receiver calls Release.
func GetEventEnvelope(seq int64, typ, eventID, agentID, action, sourceType, target, status string, ts time.Time, logicalClock int64, priority EventPriority) *EventEnvelope {
	env := envelopePool.Get().(*EventEnvelope)
	env.refCount.Store(1)
	env.Seq = seq
	env.Type = typ
	env.EventID = eventID
	env.AgentID = agentID
	env.Action = action
	env.SourceType = sourceType
	env.Target = target
	env.Status = status
	env.Timestamp = ts.UTC()
	env.Priority = priority
	p := canonicalPayload{
		Seq:          seq,
		Type:         typ,
		EventID:      eventID,
		AgentID:      agentID,
		Action:       action,
		SourceType:   sourceType,
		Target:       target,
		Status:       status,
		Timestamp:    env.Timestamp.Unix(),
		LogicalClock: logicalClock,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		raw = []byte(`{"seq":0,"type":"error","event_id":"","agent_id":"","action":"","source_type":"","target":"","status":"marshal_error","timestamp":0}`)
	}
	env.Payload = raw
	return env
}

// NewEventEnvelope builds an immutable envelope (uses pool). Payload is JSON-marshaled once.
// Caller and all subscribers must call Release() when done. For detection events use PriorityCritical.
func NewEventEnvelope(seq int64, typ, eventID, agentID, action, sourceType, target, status string, ts time.Time) *EventEnvelope {
	return GetEventEnvelope(seq, typ, eventID, agentID, action, sourceType, target, status, ts, 0, PriorityNormal)
}

// Release decrements the reference count. When it reaches zero, the envelope is returned to the pool.
// Must be called by the producer after TryPublish and by each subscriber when done processing.
func (e *EventEnvelope) Release() {
	if e == nil {
		return
	}
	if e.refCount.Add(-1) == 0 {
		e.Seq = 0
		e.Type = ""
		e.EventID = ""
		e.AgentID = ""
		e.Action = ""
		e.SourceType = ""
		e.Target = ""
		e.Status = ""
		e.Timestamp = time.Time{}
		e.Priority = PriorityNormal
		e.Payload = nil
		envelopePool.Put(e)
	}
}

