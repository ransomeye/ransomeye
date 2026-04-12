package ingest

import "errors"

var (
	ErrNilVerifiedTelemetryEnqueuer = errors.New("nil verified telemetry enqueuer")
	ErrNilVerifiedTelemetry         = errors.New("nil verified telemetry")
)

type VerifiedTelemetryEnqueuer interface {
	Enqueue(payload *VerifiedTelemetry) error
}

func EnqueueVerifiedTelemetry(q VerifiedTelemetryEnqueuer, payload *VerifiedTelemetry) error {
	if q == nil {
		return ErrNilVerifiedTelemetryEnqueuer
	}
	if payload == nil {
		return ErrNilVerifiedTelemetry
	}
	return q.Enqueue(payload)
}
