package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"
)

func durableRecord(payload []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	sum := sha256.Sum256(payload)
	var b bytes.Buffer
	_, _ = b.Write(lenBuf[:])
	_, _ = b.Write(payload)
	_, _ = b.Write(sum[:])
	return b.Bytes()
}

func TestQueue_CrashReplay_OrderIntegrity(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/durable-crash-replay.log"

	p1 := []byte("payload-1")
	p2 := []byte("payload-2")
	p3 := []byte("payload-3")

	// Case A: crash after fsync => complete records persist and dequeue order is preserved.
	{
		if err := os.WriteFile(path, append(durableRecord(p1), durableRecord(p2)...), 0o600); err != nil {
			t.Fatalf("write case A: %v", err)
		}

		q, err := OpenDurableQueue(path)
		if err != nil {
			t.Fatalf("OpenDurableQueue case A: %v", err)
		}

		raw1, _, ok, err := q.Dequeue()
		if err != nil || !ok {
			t.Fatalf("Dequeue case A #1: ok=%v err=%v", ok, err)
		}
		raw2, _, ok, err := q.Dequeue()
		if err != nil || !ok {
			t.Fatalf("Dequeue case A #2: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(raw1, p1) || !bytes.Equal(raw2, p2) {
			t.Fatalf("case A ordering mismatch got=(%s,%s) want=(%s,%s)", raw1, raw2, p1, p2)
		}
	}

	// Case B: crash after write before fsync => truncated tail should fail-closed and be removed.
	{
		var buf bytes.Buffer
		buf.Write(durableRecord(p1))

		rec3 := durableRecord(p2)
		// Truncate mid-record (omit checksum entirely).
		// record layout is: 4 + payload + 32; we keep 4+len(payload) bytes.
		truncAt := 4 + len(p2)
		buf.Write(rec3[:truncAt])

		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatalf("write case B: %v", err)
		}

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expected panic on truncated record (fail-closed)")
				}
			}()

			_, _ = OpenDurableQueue(path) // should panic
		}()

		// After scan+truncate, reopen should succeed and only the last valid record must remain.
		q, err := OpenDurableQueue(path)
		if err != nil {
			t.Fatalf("OpenDurableQueue case B reopen: %v", err)
		}

		raw1, _, ok, err := q.Dequeue()
		if err != nil || !ok {
			t.Fatalf("Dequeue case B #1: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(raw1, p1) {
			t.Fatalf("case B ordering mismatch got=%s want=%s", raw1, p1)
		}

		_, _, ok, err = q.Dequeue()
		if err != nil {
			t.Fatalf("Dequeue case B #2 err=%v", err)
		}
		if ok {
			t.Fatalf("case B expected no second valid record after truncation")
		}
	}

	// Case C: corruption injection => corruption must trigger fail-closed, and valid prefix must remain.
	{
		var buf bytes.Buffer
		buf.Write(durableRecord(p1))
		buf.Write(durableRecord(p2))

		// Append record for p3 but flip one checksum byte.
		rec := durableRecord(p3)
		if len(rec) < 4+len(p3)+sha256.Size {
			t.Fatalf("sanity: record length too small")
		}
		rec[len(rec)-1] ^= 0xFF
		buf.Write(rec)

		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatalf("write case C: %v", err)
		}

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expected panic on checksum mismatch (fail-closed)")
				}
			}()
			_, _ = OpenDurableQueue(path) // should panic
		}()

		q, err := OpenDurableQueue(path)
		if err != nil {
			t.Fatalf("OpenDurableQueue case C reopen: %v", err)
		}

		raw1, _, ok, err := q.Dequeue()
		if err != nil || !ok {
			t.Fatalf("Dequeue case C #1: ok=%v err=%v", ok, err)
		}
		raw2, _, ok, err := q.Dequeue()
		if err != nil || !ok {
			t.Fatalf("Dequeue case C #2: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(raw1, p1) || !bytes.Equal(raw2, p2) {
			t.Fatalf("case C ordering mismatch got=(%s,%s) want=(%s,%s)", raw1, raw2, p1, p2)
		}
		_, _, ok, err = q.Dequeue()
		if err != nil {
			t.Fatalf("Dequeue case C #3 err=%v", err)
		}
		if ok {
			t.Fatalf("case C expected no further valid record after corruption truncation")
		}
	}
}

func TestQueue_DiskExhaustion_FailsafeAndRecovery(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/durable-disk-exhaust.log"

	// Use a valid queue file so OpenDurableQueue succeeds deterministically.
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	q, err := OpenDurableQueue(path)
	if err != nil {
		t.Fatalf("OpenDurableQueue: %v", err)
	}
	defer func() {
		// DurableQueue can panic internally; ignore here because the test covers it explicitly.
		_ = q
	}()

	if q.state != StateNormal {
		t.Fatalf("initial state=%v want=%v", q.state, StateNormal)
	}

	q.SetDiskExhaustedForTest(true)
	if err := q.Enqueue([]byte("x")); err == nil {
		t.Fatal("expected enqueue rejection under disk exhaustion")
	}
	metrics := q.Metrics()
	if metrics.State != StateDiskExhausted {
		t.Fatalf("state=%v want=%v", metrics.State, StateDiskExhausted)
	}
	if metrics.PendingCount != 0 {
		t.Fatalf("pending count=%d want=0", metrics.PendingCount)
	}

	q.SetDiskExhaustedForTest(false)
	if err := q.Enqueue([]byte("x")); err != nil {
		t.Fatalf("enqueue after recovery: %v", err)
	}
	metrics = q.Metrics()
	if metrics.State != StateNormal {
		t.Fatalf("recovered state=%v want=%v", metrics.State, StateNormal)
	}
	if metrics.PendingCount != 1 {
		t.Fatalf("pending count after recovery=%d want=1", metrics.PendingCount)
	}
}

// (intentionally no exported helpers in test)
