package pipeline

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrDurableQueueCorrupt = errors.New("durable queue corrupt")
	errChecksumMismatch    = errors.New("durable queue checksum mismatch")
)

// DurableQueue is an append-only fsync-backed queue with per-record SHA-256.
// Record wire format: uint32(len(payload)) || payload || sha256(payload)
type DurableQueue struct {
	mu              sync.Mutex
	f               *os.File
	path            string
	ackPath         string
	committedOffset int64
	readOffset      int64
	writeOffset     int64
	state           QueueState
	fsyncFails      uint32
	nextLeaseID     uint64
	leases          map[uint64]lease
	pendingCount    int
	lastWALLatency  time.Duration
	syncFile        func(*os.File) error
	syncDir         func(string) error

	testDiskExhausted bool
	testWALLatency    time.Duration
}

type lease struct {
	ID       uint64
	Start    int64
	End      int64
	Resolved bool
}

type QueueState uint8

const (
	StateNormal QueueState = iota
	StateBackpressure
	StateDiskExhausted
	StateFailClosed
)

func OpenDurableQueue(path string) (*DurableQueue, error) {
	if path == "" {
		return nil, errors.New("durable queue path missing")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	q := &DurableQueue{
		f:        f,
		path:     path,
		ackPath:  path + ".ack",
		state:    StateNormal,
		leases:   make(map[uint64]lease),
		syncFile: defaultFileSync,
		syncDir:  defaultDirSync,
	}
	if err := q.scanAndRepairLocked(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := q.loadCommittedOffsetLocked(); err != nil {
		_ = f.Close()
		return nil, err
	}
	q.readOffset = q.committedOffset
	if err := q.recountPendingLocked(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return q, nil
}

func (q *DurableQueue) Enqueue(payload []byte) error {
	if q == nil {
		return errors.New("durable queue nil")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.refreshStateLocked()
	switch q.state {
	case StateFailClosed:
		return errors.New("durable queue fail-closed")
	case StateDiskExhausted:
		return q.diskExhaustedErrLocked()
	case StateBackpressure:
		return errors.New("durable queue backpressure")
	}

	start := time.Now()
	err := q.enqueueLocked(payload)
	q.lastWALLatency = time.Since(start)
	if err == nil {
		q.pendingCount++
		q.state = StateNormal
		q.fsyncFails = 0
		return nil
	}

	if isDiskExhaustedErr(err) {
		q.state = StateDiskExhausted
		return err
	}
	if isFsyncErr(err) {
		q.fsyncFails++
		if q.fsyncFails >= 8 {
			q.state = StateFailClosed
			return errors.New("durable queue fail-closed")
		}
		q.state = StateBackpressure
		return err
	}

	q.state = StateBackpressure
	return err
}

func (q *DurableQueue) enqueueLocked(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("durable queue empty payload")
	}
	if len(payload) > int(^uint32(0)) {
		return errors.New("durable queue payload too large")
	}
	if q.testDiskExhausted {
		return q.diskExhaustedErrLocked()
	}
	startOffset := q.writeOffset
	if _, err := q.f.Seek(startOffset, io.SeekStart); err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := q.f.Write(lenBuf[:]); err != nil {
		_ = q.truncateLocked(startOffset)
		return err
	}
	if _, err := q.f.Write(payload); err != nil {
		_ = q.truncateLocked(startOffset)
		return err
	}
	sum := sha256.Sum256(payload)
	if _, err := q.f.Write(sum[:]); err != nil {
		_ = q.truncateLocked(startOffset)
		return err
	}
	if q.testWALLatency > 0 {
		time.Sleep(q.testWALLatency)
	}
	if err := q.syncFileLocked(q.f); err != nil {
		_ = q.truncateLocked(startOffset)
		return fmt.Errorf("fsync: %w", err)
	}
	q.writeOffset = startOffset + int64(4+len(payload)+sha256.Size)
	return nil
}

func (q *DurableQueue) Dequeue() ([]byte, uint64, bool, error) {
	if q == nil {
		return nil, 0, false, errors.New("durable queue nil")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.readOffset >= q.writeOffset {
		return nil, 0, false, nil
	}
	start := q.readOffset
	payload, next, err := q.readPayloadAtLocked(start)
	if err != nil {
		if errors.Is(err, errChecksumMismatch) {
			q.state = StateFailClosed
			panic("durable queue checksum mismatch; fail-closed")
		}
		return nil, 0, false, err
	}
	q.nextLeaseID++
	leaseID := q.nextLeaseID
	q.leases[leaseID] = lease{
		ID:    leaseID,
		Start: start,
		End:   next,
	}
	q.readOffset = next
	return payload, leaseID, true, nil
}

func (q *DurableQueue) Resolve(leaseID uint64) error {
	if q == nil {
		return errors.New("durable queue nil")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	lease, ok := q.leases[leaseID]
	if !ok {
		return nil
	}
	lease.Resolved = true
	q.leases[leaseID] = lease

	advanced := false
	for {
		nextLeaseID, nextLease, ok := q.findLeaseAtOffsetLocked(q.committedOffset)
		if !ok || !nextLease.Resolved {
			break
		}
		delete(q.leases, nextLeaseID)
		q.committedOffset = nextLease.End
		if q.pendingCount > 0 {
			q.pendingCount--
		}
		advanced = true
	}
	if advanced {
		if q.committedOffset == q.writeOffset && len(q.leases) == 0 {
			if err := q.truncateLocked(0); err != nil {
				return err
			}
			q.committedOffset = 0
			q.readOffset = 0
			q.writeOffset = 0
		}
		if err := q.persistCommittedOffsetLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (q *DurableQueue) SnapshotPending() ([][]byte, error) {
	if q == nil {
		return nil, errors.New("durable queue nil")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([][]byte, 0)
	for off := q.committedOffset; off < q.writeOffset; {
		payload, next, err := q.readPayloadAtLocked(off)
		if err != nil {
			return nil, err
		}
		out = append(out, append([]byte(nil), payload...))
		off = next
	}
	return out, nil
}

func (q *DurableQueue) readPayloadAtLocked(off int64) ([]byte, int64, error) {
	if _, err := q.f.Seek(off, io.SeekStart); err != nil {
		return nil, 0, err
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(q.f, lenBuf[:]); err != nil {
		return nil, 0, err
	}
	n := int(binary.BigEndian.Uint32(lenBuf[:]))
	payload := make([]byte, n)
	if _, err := io.ReadFull(q.f, payload); err != nil {
		return nil, 0, err
	}
	var got [sha256.Size]byte
	if _, err := io.ReadFull(q.f, got[:]); err != nil {
		return nil, 0, err
	}
	want := sha256.Sum256(payload)
	if got != want {
		return nil, 0, errChecksumMismatch
	}
	return payload, off + int64(4+n+sha256.Size), nil
}

func (q *DurableQueue) scanAndRepairLocked() error {
	info, err := q.f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	var off int64
	for off < size {
		payload, next, err := q.readPayloadAtLocked(off)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF || errors.Is(err, errChecksumMismatch) {
				if trErr := q.truncateLocked(off); trErr != nil {
					return trErr
				}
				q.state = StateFailClosed
				panic(fmt.Errorf("%w: truncated record", ErrDurableQueueCorrupt))
			}
			return err
		}
		if len(payload) == 0 || next > size {
			if trErr := q.truncateLocked(off); trErr != nil {
				return trErr
			}
			q.state = StateFailClosed
			panic(fmt.Errorf("%w: invalid record size", ErrDurableQueueCorrupt))
		}
		off = next
	}
	q.writeOffset = off
	return nil
}

func (q *DurableQueue) loadCommittedOffsetLocked() error {
	raw, err := os.ReadFile(q.ackPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			q.committedOffset = 0
			return nil
		}
		return err
	}
	if len(raw) != 8 {
		return errors.New("durable queue ack offset invalid")
	}
	offset := int64(binary.BigEndian.Uint64(raw))
	if offset < 0 || offset > q.writeOffset {
		return errors.New("durable queue ack offset out of range")
	}
	q.committedOffset = offset
	return nil
}

func (q *DurableQueue) persistCommittedOffsetLocked() error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(q.committedOffset))
	tmp := q.ackPath + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(buf[:]); err != nil {
		_ = file.Close()
		return err
	}
	if err := q.syncFileLocked(file); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, q.ackPath); err != nil {
		return err
	}
	return q.syncDirLocked(filepath.Dir(q.ackPath))
}

func (q *DurableQueue) recountPendingLocked() error {
	count := 0
	for off := q.committedOffset; off < q.writeOffset; {
		_, next, err := q.readPayloadAtLocked(off)
		if err != nil {
			return err
		}
		count++
		off = next
	}
	q.pendingCount = count
	return nil
}

type DurableMetrics struct {
	PendingCount int
	PendingBytes int64
	WALLatency   time.Duration
	State        QueueState
}

func (q *DurableQueue) Metrics() DurableMetrics {
	if q == nil {
		return DurableMetrics{State: StateFailClosed}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.refreshStateLocked()
	return DurableMetrics{
		PendingCount: q.pendingCount,
		PendingBytes: q.writeOffset - q.committedOffset,
		WALLatency:   q.lastWALLatency,
		State:        q.state,
	}
}

func (q *DurableQueue) SetDiskExhaustedForTest(enabled bool) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.testDiskExhausted = enabled
	q.refreshStateLocked()
}

func (q *DurableQueue) SetWALLatencyForTest(delay time.Duration) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.testWALLatency = delay
}

func (q *DurableQueue) refreshStateLocked() {
	if q.testDiskExhausted {
		q.state = StateDiskExhausted
		return
	}
	switch q.state {
	case StateDiskExhausted, StateBackpressure:
		if err := q.probeWritableLocked(); err != nil {
			if isDiskExhaustedErr(err) {
				q.state = StateDiskExhausted
				return
			}
			q.state = StateBackpressure
			return
		}
		q.state = StateNormal
		q.fsyncFails = 0
	}
}

func (q *DurableQueue) probeWritableLocked() error {
	if q.testDiskExhausted {
		return q.diskExhaustedErrLocked()
	}
	tmp := q.path + ".healthcheck"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte{0}); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := q.syncFileLocked(file); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return q.syncDirLocked(filepath.Dir(q.path))
}

func (q *DurableQueue) diskExhaustedErrLocked() error {
	return &os.PathError{
		Op:   "write",
		Path: q.path,
		Err:  errors.New("no space left on device"),
	}
}

func (q *DurableQueue) findLeaseAtOffsetLocked(offset int64) (uint64, lease, bool) {
	for leaseID, lease := range q.leases {
		if lease.Start == offset {
			return leaseID, lease, true
		}
	}
	return 0, lease{}, false
}

func (q *DurableQueue) HasPending() bool {
	if q == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.committedOffset < q.writeOffset
}

func (q *DurableQueue) WaitWritable() {
	if q == nil {
		select {}
	}
	for {
		q.mu.Lock()
		q.refreshStateLocked()
		state := q.state
		q.mu.Unlock()
		if state == StateNormal {
			return
		}
		if state == StateFailClosed {
			panic("durable queue fail-closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (q *DurableQueue) Close() error {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.f == nil {
		return nil
	}
	err := q.f.Close()
	q.f = nil
	return err
}

func (q *DurableQueue) syncFileLocked(file *os.File) error {
	if q == nil || file == nil {
		return nil
	}
	if q.syncFile != nil {
		return q.syncFile(file)
	}
	return defaultFileSync(file)
}

func (q *DurableQueue) syncDirLocked(path string) error {
	if q == nil {
		return nil
	}
	if q.syncDir != nil {
		return q.syncDir(path)
	}
	return defaultDirSync(path)
}

func defaultFileSync(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Sync()
}

func defaultDirSync(path string) error {
	dirFD, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dirFD.Close()
	return dirFD.Sync()
}

func (q *DurableQueue) truncateLocked(sz int64) error {
	if err := q.f.Truncate(sz); err != nil {
		return err
	}
	if _, err := q.f.Seek(sz, io.SeekStart); err != nil {
		return err
	}
	if err := q.f.Sync(); err != nil {
		return err
	}
	q.writeOffset = sz
	if q.readOffset > sz {
		q.readOffset = sz
	}
	if q.committedOffset > sz {
		q.committedOffset = sz
	}
	return nil
}

func isFsyncErr(err error) bool {
	return err != nil && len(err.Error()) >= 6 && err.Error()[:6] == "fsync:"
}

func isDiskExhaustedErr(err error) bool {
	if err == nil {
		return false
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		if errors.Is(pe.Err, os.ErrPermission) {
			return false
		}
	}
	msg := err.Error()
	return containsDiskFull(msg)
}

func containsDiskFull(s string) bool {
	if len(s) == 0 {
		return false
	}
	return indexOf(s, "no space left on device") >= 0 || indexOf(s, "disk full") >= 0 || indexOf(s, "ENOSPC") >= 0
}

func indexOf(s, sub string) int {
	n := len(s)
	m := len(sub)
	if m == 0 {
		return 0
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}
