package ingest

// VerifiedTelemetry is canonical payload bytes + DB metadata after Ed25519 verification.
// Payload MUST NOT be mutated after construction.
type VerifiedTelemetry struct {
	Payload        []byte
	AgentSignature []byte
	AgentIDStr     string
	EventType      string
	SourceType     string // agent | syslog | netflow | dpi
	TimestampUnix  float64
	LogicalClock   int64
	DroppedCount   uint64
}

