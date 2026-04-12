package pipeline

import (
	"errors"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/backpressure"
	"ransomeye/core/internal/ingest"
)

type IngestQueue struct {
	rb *RingBuffer
}

func NewIngestQueue(memoryCapacity int) *IngestQueue {
	return &IngestQueue{rb: NewRingBuffer(memoryCapacity)}
}

func (q *IngestQueue) Admit(payload *ingest.VerifiedTelemetry) (uint64, error) {
	return q.AdmitWithMetadata(payload, ack.Metadata{})
}

func (q *IngestQueue) AdmitWithMetadata(payload *ingest.VerifiedTelemetry, meta ack.Metadata) (uint64, error) {
	if q == nil || q.rb == nil {
		return 0, errors.New("ingest queue not initialized")
	}
	if payload == nil {
		return 0, ErrInvalidEvent
	}
	return q.rb.PushWithMetadata(payload, meta)
}

func (q *IngestQueue) DequeueNext() (*Event, error) {
	if q == nil || q.rb == nil {
		return nil, ErrInvalidEvent
	}
	dst := make([]*ingest.VerifiedTelemetry, 1)
	seq, n, err := q.rb.PopWithSequence(dst)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return q.eventForSequence(seq, dst[0])
}

func (q *IngestQueue) eventForSequence(seq uint64, payload *ingest.VerifiedTelemetry) (*Event, error) {
	if q == nil || q.rb == nil {
		return nil, ErrInvalidEvent
	}
	q.rb.mu.Lock()
	defer q.rb.mu.Unlock()
	for _, item := range q.rb.memQ {
		if item.Sequence == seq {
			return &Event{
				Sequence: seq,
				Payload:  payload,
				Ack:      item.Ack,
			}, nil
		}
	}
	return &Event{
		Sequence: seq,
		Payload:  payload,
	}, nil
}

func (q *IngestQueue) Resolve(sequence uint64) error {
	if q == nil || q.rb == nil {
		return ErrInvalidEvent
	}
	return q.rb.Resolve(sequence)
}

func (q *IngestQueue) PendingByReplayKey(replayKey string) (ack.Metadata, bool, error) {
	if q == nil || q.rb == nil {
		return ack.Metadata{}, false, nil
	}
	return q.rb.PendingByReplayKey(replayKey)
}

func (q *IngestQueue) Depth() int {
	if q == nil || q.rb == nil {
		return 0
	}
	return int(q.rb.Size())
}

func (q *IngestQueue) Capacity() int {
	if q == nil || q.rb == nil {
		return 0
	}
	return int(q.rb.Capacity())
}

func (q *IngestQueue) BackpressureMetrics() backpressure.Metrics {
	if q == nil || q.rb == nil {
		return backpressure.Metrics{QueueUnavailable: true}
	}
	return q.rb.BackpressureMetrics()
}

func (q *IngestQueue) SetDiskExhaustedForTest(enabled bool) {
	if q == nil || q.rb == nil {
		return
	}
	q.rb.SetDiskExhaustedForTest(enabled)
}

func (q *IngestQueue) SetWALLatencyForTest(delayMS int) {
	if q == nil || q.rb == nil {
		return
	}
	q.rb.SetWALLatencyForTest(delayMS)
}

func (q *IngestQueue) Close() error {
	if q == nil || q.rb == nil {
		return nil
	}
	return q.rb.Close()
}
