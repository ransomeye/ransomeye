package pipeline

import (
	"log"
	"os"
	"strconv"
	"sync"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/backpressure"
	"ransomeye/core/internal/ingest"
)

type Priority int

const (
	High Priority = iota
	Medium
	Low
)

const (
	defaultSchedulerMemoryCapacity = 1024
)

type Scheduler struct {
	mu sync.Mutex

	rb      *RingBuffer
	iq      *IngestQueue
	memCap  int
	lastSeq uint64
	acker   *ack.Controller
}

func (s *Scheduler) Enqueue(payload *ingest.VerifiedTelemetry) error {
	if payload == nil {
		return ErrInvalidEvent
	}
	iq := s.ensureIngestQueue()
	if iq == nil {
		return ErrInvalidEvent
	}
	seq, err := iq.Admit(payload)
	if err != nil {
		return err
	}
	log.Printf("[QUEUE] enqueue success sequence=%d depth=%d capacity=%d agent_id=%s logical_clock=%d", seq, iq.Depth(), iq.Capacity(), payload.AgentIDStr, payload.LogicalClock)
	return nil
}

func (s *Scheduler) SetIngestQueue(q *IngestQueue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.iq = q
}

func (s *Scheduler) SetAcker(acker *ack.Controller) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acker = acker
}

func (s *Scheduler) Acker() *ack.Controller {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acker
}

func (s *Scheduler) ensureIngestQueue() *IngestQueue {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.iq != nil {
		return s.iq
	}
	memCap := parseSchedulerMemCapacity()
	s.iq = NewIngestQueue(memCap)
	return s.iq
}

func (s *Scheduler) DequeueNext() (*Event, error) {
	if s == nil {
		return nil, ErrInvalidEvent
	}
	iq := s.ensureIngestQueue()
	if iq == nil {
		return nil, ErrInvalidEvent
	}
	ev, err := iq.DequeueNext()
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Sequence <= s.lastSeq {
		return nil, ErrSequenceViolation
	}
	s.lastSeq = ev.Sequence
	return ev, nil
}

func (s *Scheduler) Resolve(sequence uint64) error {
	if s == nil {
		return ErrInvalidEvent
	}
	iq := s.ensureIngestQueue()
	if iq == nil {
		return ErrInvalidEvent
	}
	return iq.Resolve(sequence)
}

func (s *Scheduler) SnapshotSequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

func (s *Scheduler) QueueDepth() int {
	if s == nil {
		return 0
	}
	iq := s.ensureIngestQueue()
	if iq == nil {
		return 0
	}
	return iq.Depth()
}

func (s *Scheduler) Capacity() int {
	if s == nil {
		return 0
	}
	iq := s.ensureIngestQueue()
	if iq == nil {
		return 0
	}
	return iq.Capacity()
}

func (s *Scheduler) BackpressureMetrics() backpressure.Metrics {
	if s == nil {
		return backpressure.Metrics{QueueUnavailable: true}
	}
	iq := s.ensureIngestQueue()
	if iq == nil {
		return backpressure.Metrics{QueueUnavailable: true}
	}
	return iq.BackpressureMetrics()
}

func parseSchedulerMemCapacity() int {
	raw := os.Getenv("RANSOMEYE_SCHEDULER_MEM_CAP")
	if raw == "" {
		return defaultSchedulerMemoryCapacity
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 2 {
		return defaultSchedulerMemoryCapacity
	}
	// RingBuffer requires power-of-two capacity.
	if v&(v-1) == 0 {
		return v
	}
	p2 := 1
	for p2 < v {
		p2 <<= 1
	}
	return p2
}
