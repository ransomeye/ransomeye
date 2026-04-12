package pipeline

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/backpressure"
	"ransomeye/core/internal/ingest"
)

type persistedTelemetry struct {
	Sequence       uint64 `json:"sequence"`
	ReplayKey      string `json:"replay_key,omitempty"`
	MessageID      string `json:"message_id,omitempty"`
	ContentSHA256  string `json:"content_sha256,omitempty"`
	Payload        string `json:"payload"`
	AgentSignature string `json:"agent_signature"`
	AgentIDStr     string `json:"agent_id_str"`
	EventType      string `json:"event_type"`
	SourceType     string `json:"source_type,omitempty"`
	TimestampUnix  string `json:"timestamp_unix"`
	LogicalClock   int64  `json:"logical_clock"`
	DroppedCount   uint64 `json:"dropped_count"`
}

type Stats struct {
	Pushed  uint64
	Popped  uint64
	Dropped uint64
}

// RingBuffer is a fixed-size, lock-free MPSC ring buffer for telemetry events.
//
// - Multiple producers may call Push concurrently.
// - A single consumer may call Pop concurrently with producers.
// - The hot path does not allocate; Pop is batch-oriented and writes into a caller-provided slice.
//
// Implementation: bounded sequence ring (Vyukov-style) with per-slot sequence numbers.
type RingBuffer struct {
	mu   sync.Mutex
	cond *sync.Cond

	memCap int
	memQ   []queuedEvent
	queued int

	highWM uint32 // (0..1]*2^32
	lowWM  uint32 // (0..1]*2^32

	pushed  uint64
	popped  uint64
	dropped uint64

	durable    *DurableQueue
	durableErr error

	nextSeq uint64
}

type queuedEvent struct {
	Sequence uint64
	Payload  *ingest.VerifiedTelemetry
	Ack      ack.Metadata
	LeaseID  uint64
}

// NewRingBuffer constructs a ring buffer with a fixed capacity.
// Capacity must be a power of two and >= 2.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 2 || (capacity&(capacity-1)) != 0 {
		// Fail-closed without panicking (Phase 1 deterministic core).
		return nil
	}
	rb := &RingBuffer{
		memCap:  capacity,
		memQ:    make([]queuedEvent, 0, capacity),
		highWM:  float01ToU32(0.8),
		lowWM:   float01ToU32(0.5),
		nextSeq: 1,
	}
	rb.cond = sync.NewCond(&rb.mu)
	dqPath := os.Getenv("RANSOMEYE_DURABLE_QUEUE_PATH")
	if dqPath == "" {
		dqPath = "/var/lib/ransomeye/core-durable-queue.log"
	}
	dq, err := OpenDurableQueue(dqPath)
	rb.durable = dq
	rb.durableErr = err
	if dq != nil {
		rb.queued = dq.Metrics().PendingCount
		nextSeq, seqErr := nextSequenceFromDurable(dq)
		if seqErr != nil {
			rb.durableErr = seqErr
			rb.durable = nil
			return rb
		}
		rb.nextSeq = nextSeq
	}
	return rb
}

// SetWatermarks configures high/low watermarks in [0,1].
// ShouldThrottle() becomes true at/above highWM and returns to false at/below lowWM.
func (r *RingBuffer) SetWatermarks(high, low float64) {
	if r == nil {
		return
	}
	h := float01ToU32(high)
	l := float01ToU32(low)
	if l > h {
		l = h
	}
	atomic.StoreUint32(&r.highWM, h)
	atomic.StoreUint32(&r.lowWM, l)
}

func (r *RingBuffer) Capacity() uint64 {
	if r == nil {
		return 0
	}
	return uint64(r.memCap)
}

// IsFull reports whether the buffer is full at this instant.
func (r *RingBuffer) IsFull() bool {
	if r == nil {
		return true
	}
	return r.Size() >= r.Capacity()
}

// Size returns an instantaneous estimate of items present.
func (r *RingBuffer) Size() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return uint64(r.queued)
}

// Utilization returns Size/Capacity in [0,1].
func (r *RingBuffer) Utilization() float64 {
	c := r.Capacity()
	if c == 0 {
		return 0
	}
	sz := r.Size()
	if sz >= c {
		return 1
	}
	return float64(sz) / float64(c)
}

// ShouldThrottle indicates whether queue admission is currently in PRESSURE.
func (r *RingBuffer) ShouldThrottle() bool {
	if r == nil {
		return true
	}
	return backpressure.Evaluate(r.BackpressureMetrics()).State == backpressure.StatePressure
}

func (r *RingBuffer) Stats() Stats {
	if r == nil {
		return Stats{}
	}
	return Stats{
		Pushed:  atomic.LoadUint64(&r.pushed),
		Popped:  atomic.LoadUint64(&r.popped),
		Dropped: atomic.LoadUint64(&r.dropped),
	}
}

// Push enqueues an event through the unified durable path.
// This is safe for multiple concurrent producers.
func (r *RingBuffer) Push(ev *ingest.VerifiedTelemetry) error {
	_, err := r.PushWithMetadata(ev, ack.Metadata{})
	return err
}

func (r *RingBuffer) PushWithSequence(ev *ingest.VerifiedTelemetry) (uint64, error) {
	return r.PushWithMetadata(ev, ack.Metadata{})
}

func (r *RingBuffer) PushWithMetadata(ev *ingest.VerifiedTelemetry, meta ack.Metadata) (uint64, error) {
	if r == nil {
		return 0, ErrInvalidEvent
	}
	if ev == nil {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.durableErr != nil || r.durable == nil {
		return 0, backpressure.NewAdmissionError(backpressure.StateFailsafe, "durable queue unavailable")
	}
	assessment := backpressure.Evaluate(r.backpressureMetricsLocked())
	if !assessment.AdmissionAllowed() {
		return 0, assessment.AdmissionError()
	}
	seq := r.nextSeq
	r.nextSeq++
	if err := r.enqueueDurableLocked(ev, meta, seq); err != nil {
		return 0, normalizeQueueAdmissionError(err)
	}
	r.queued++
	atomic.AddUint64(&r.pushed, 1)
	r.cond.Broadcast()
	return seq, nil
}

// Pop dequeues up to len(dst) events into dst and returns the number written.
// dst is owned by the caller; Pop does not allocate.
//
// Single-consumer only.
func (r *RingBuffer) Pop(dst []*ingest.VerifiedTelemetry) (int, error) {
	_, n, err := r.PopWithSequence(dst)
	return n, err
}

func (r *RingBuffer) PopWithSequence(dst []*ingest.VerifiedTelemetry) (uint64, int, error) {
	if len(dst) == 0 {
		return 0, 0, nil
	}
	if r == nil {
		return 0, 0, ErrInvalidEvent
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.durableErr != nil || r.durable == nil {
		return 0, 0, ErrInvalidEvent
	}
	raw, leaseID, ok, err := r.durable.Dequeue()
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, nil
	}
	seq, ev, meta, err := deserializeTelemetry(raw)
	if err != nil {
		return 0, 0, err
	}
	dst[0] = ev
	r.memQ = append(r.memQ, queuedEvent{
		Sequence: seq,
		Payload:  ev,
		Ack:      meta,
		LeaseID:  leaseID,
	})
	atomic.AddUint64(&r.popped, 1)
	r.cond.Broadcast()
	return seq, 1, nil
}

func (r *RingBuffer) Resolve(sequence uint64) error {
	if r == nil {
		return ErrInvalidEvent
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	found := false
	leaseID := uint64(0)
	for idx, item := range r.memQ {
		if item.Sequence != sequence {
			continue
		}
		leaseID = item.LeaseID
		r.memQ = append(r.memQ[:idx], r.memQ[idx+1:]...)
		found = true
		break
	}
	if r.durableErr != nil || r.durable == nil {
		return ErrInvalidEvent
	}
	if err := r.durable.Resolve(leaseID); err != nil {
		return err
	}
	if found && r.queued > 0 {
		r.queued--
	}
	r.cond.Broadcast()
	return nil
}

func (r *RingBuffer) PendingByReplayKey(replayKey string) (ack.Metadata, bool, error) {
	if r == nil || replayKey == "" {
		return ack.Metadata{}, false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range r.memQ {
		if item.Ack.ReplayKey == replayKey {
			return item.Ack, true, nil
		}
	}
	if r.durableErr != nil || r.durable == nil {
		return ack.Metadata{}, false, nil
	}
	snapshot, err := r.durable.SnapshotPending()
	if err != nil {
		return ack.Metadata{}, false, err
	}
	for _, raw := range snapshot {
		_, _, meta, err := deserializeTelemetry(raw)
		if err != nil {
			return ack.Metadata{}, false, err
		}
		if meta.ReplayKey == replayKey {
			return meta, true, nil
		}
	}
	return ack.Metadata{}, false, nil
}

func (r *RingBuffer) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	dq := r.durable
	r.durable = nil
	r.mu.Unlock()
	if dq == nil {
		return nil
	}
	return dq.Close()
}

func (r *RingBuffer) BackpressureMetrics() backpressure.Metrics {
	if r == nil {
		return backpressure.Metrics{QueueUnavailable: true}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.backpressureMetricsLocked()
}

func (r *RingBuffer) SetDiskExhaustedForTest(enabled bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.durable != nil {
		r.durable.SetDiskExhaustedForTest(enabled)
	}
}

func (r *RingBuffer) SetWALLatencyForTest(delayMS int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.durable != nil {
		r.durable.SetWALLatencyForTest(time.Duration(delayMS) * time.Millisecond)
	}
}

func (r *RingBuffer) backpressureMetricsLocked() backpressure.Metrics {
	metrics := backpressure.Metrics{
		QueueDepth:    r.queued,
		QueueCapacity: r.memCap,
	}
	if r.durableErr != nil || r.durable == nil {
		metrics.QueueUnavailable = true
		return metrics
	}
	durableMetrics := r.durable.Metrics()
	metrics.PendingBytes = durableMetrics.PendingBytes
	if durableMetrics.PendingCount > 0 {
		metrics.WALLatency = durableMetrics.WALLatency
	}
	metrics.DiskExhausted = durableMetrics.State == StateDiskExhausted
	metrics.FailClosed = durableMetrics.State == StateFailClosed
	return metrics
}

func normalizeQueueAdmissionError(err error) error {
	if err == nil {
		return nil
	}
	if backpressure.IsResourceExhausted(err) {
		return err
	}
	if isDiskExhaustedErr(err) {
		return backpressure.NewAdmissionError(backpressure.StateFailsafe, "disk exhaustion detected")
	}
	if isFsyncErr(err) {
		return backpressure.NewAdmissionError(backpressure.StatePressure, "WAL fsync latency threshold reached")
	}
	if err.Error() == "durable queue backpressure" {
		return backpressure.NewAdmissionError(backpressure.StatePressure, "WAL latency threshold reached")
	}
	return backpressure.NewAdmissionError(backpressure.StateFailsafe, "queue admission unavailable")
}

func float01ToU32(v float64) uint32 {
	if v <= 0 {
		return 0
	}
	if v >= 1 {
		return ^uint32(0)
	}
	return uint32(v * float64(^uint32(0)))
}

func u32ToFloat01(v uint32) float64 {
	return float64(v) / float64(^uint32(0))
}

func serializeTelemetry(ev *ingest.VerifiedTelemetry, meta ack.Metadata, sequence uint64) ([]byte, error) {
	p := persistedTelemetry{
		Sequence:       sequence,
		ReplayKey:      meta.ReplayKey,
		MessageID:      meta.MessageID,
		ContentSHA256:  hex.EncodeToString(meta.ContentSHA256[:]),
		Payload:        base64.StdEncoding.EncodeToString(ev.Payload),
		AgentSignature: base64.StdEncoding.EncodeToString(ev.AgentSignature),
		AgentIDStr:     ev.AgentIDStr,
		EventType:      ev.EventType,
		SourceType:     ev.SourceType,
		TimestampUnix:  strconv.FormatFloat(ev.TimestampUnix, 'g', -1, 64),
		LogicalClock:   ev.LogicalClock,
		DroppedCount:   ev.DroppedCount,
	}
	return json.Marshal(p)
}

func deserializeTelemetry(raw []byte) (uint64, *ingest.VerifiedTelemetry, ack.Metadata, error) {
	var p persistedTelemetry
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0, nil, ack.Metadata{}, err
	}
	payload, err := base64.StdEncoding.DecodeString(p.Payload)
	if err != nil {
		return 0, nil, ack.Metadata{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(p.AgentSignature)
	if err != nil {
		return 0, nil, ack.Metadata{}, err
	}
	ts, err := strconv.ParseFloat(p.TimestampUnix, 64)
	if err != nil {
		return 0, nil, ack.Metadata{}, err
	}
	var contentSHA [32]byte
	if p.ContentSHA256 != "" {
		shaBytes, err := hex.DecodeString(p.ContentSHA256)
		if err != nil {
			return 0, nil, ack.Metadata{}, err
		}
		if len(shaBytes) != len(contentSHA) {
			return 0, nil, ack.Metadata{}, ErrInvalidEvent
		}
		copy(contentSHA[:], shaBytes)
	}
	return p.Sequence, &ingest.VerifiedTelemetry{
			Payload:        payload,
			AgentSignature: sig,
			AgentIDStr:     p.AgentIDStr,
			EventType:      p.EventType,
			SourceType:     p.SourceType,
			TimestampUnix:  ts,
			LogicalClock:   p.LogicalClock,
			DroppedCount:   p.DroppedCount,
		}, ack.Metadata{
			ReplayKey:     p.ReplayKey,
			MessageID:     p.MessageID,
			ContentSHA256: contentSHA,
		}, nil
}

func (r *RingBuffer) enqueueDurableLocked(ev *ingest.VerifiedTelemetry, meta ack.Metadata, sequence uint64) error {
	raw, err := serializeTelemetry(ev, meta, sequence)
	if err != nil {
		return err
	}
	return r.durable.Enqueue(raw)
}

func nextSequenceFromDurable(dq *DurableQueue) (uint64, error) {
	if dq == nil {
		return 1, nil
	}
	snapshot, err := dq.SnapshotPending()
	if err != nil {
		return 0, err
	}
	maxSeq := uint64(0)
	for _, raw := range snapshot {
		seq, _, _, err := deserializeTelemetry(raw)
		if err != nil {
			return 0, err
		}
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	if maxSeq == ^uint64(0) {
		return 0, ErrSequenceViolation
	}
	return maxSeq + 1, nil
}
