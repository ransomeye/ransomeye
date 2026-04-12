package pipeline

import (
	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/ingest"
)

type Event struct {
	Sequence uint64
	Payload  *ingest.VerifiedTelemetry
	Ack      ack.Metadata
}
