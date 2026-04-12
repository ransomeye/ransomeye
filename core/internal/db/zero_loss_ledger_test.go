package db

import (
	"strconv"
	"testing"
)

func TestZeroLossLedger_DeduplicatesReplayAndPreservesOrder(t *testing.T) {
	ledger := NewZeroLossLedger(3)

	for i := uint64(1); i <= 3; i++ {
		if err := ledger.Accept(keyForClock(i), i); err != nil {
			t.Fatalf("Accept(%d): %v", i, err)
		}
	}

	if first, err := ledger.Persist(keyForClock(1), 1); err != nil || !first {
		t.Fatalf("Persist first event: first=%v err=%v", first, err)
	}
	if first, err := ledger.Persist(keyForClock(1), 1); err != nil || first {
		t.Fatalf("Persist replayed event: first=%v err=%v", first, err)
	}
	if first, err := ledger.Persist(keyForClock(2), 2); err != nil || !first {
		t.Fatalf("Persist second event: first=%v err=%v", first, err)
	}
	if first, err := ledger.Persist(keyForClock(3), 3); err != nil || !first {
		t.Fatalf("Persist third event: first=%v err=%v", first, err)
	}

	proof := ledger.Proof()
	if proof.AcceptedCount != 3 {
		t.Fatalf("accepted_count=%d want=3", proof.AcceptedCount)
	}
	if proof.PersistedCount != 3 {
		t.Fatalf("persisted_count=%d want=3", proof.PersistedCount)
	}
	if proof.DuplicatePersistCount != 1 {
		t.Fatalf("duplicate_persist_count=%d want=1", proof.DuplicatePersistCount)
	}
	if err := proof.Validate(3); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestZeroLossLedger_RejectsOutOfOrderPersistence(t *testing.T) {
	ledger := NewZeroLossLedger(2)
	if err := ledger.Accept(keyForClock(1), 1); err != nil {
		t.Fatalf("Accept(1): %v", err)
	}
	if err := ledger.Accept(keyForClock(2), 2); err != nil {
		t.Fatalf("Accept(2): %v", err)
	}
	if _, err := ledger.Persist(keyForClock(2), 2); err == nil {
		t.Fatal("expected out-of-order persist rejection")
	}
}

func keyForClock(clock uint64) string {
	return "clock-" + strconv.FormatUint(clock, 10)
}
