package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
)

type ZeroLossProof struct {
	AcceptedCount          uint64 `json:"accepted_count"`
	PersistedCount         uint64 `json:"persisted_count"`
	DuplicatePersistCount  uint64 `json:"duplicate_persist_count"`
	MissingCount           uint64 `json:"missing_count"`
	OrderingViolations     uint64 `json:"ordering_violations"`
	FirstLogicalClock      uint64 `json:"first_logical_clock"`
	LastLogicalClock       uint64 `json:"last_logical_clock"`
	OrderedPersistenceHash string `json:"ordered_persistence_hash"`
}

func (p ZeroLossProof) Validate(expected uint64) error {
	if p.AcceptedCount != expected {
		return fmt.Errorf("accepted_count=%d want=%d", p.AcceptedCount, expected)
	}
	if p.PersistedCount != expected {
		return fmt.Errorf("persisted_count=%d want=%d", p.PersistedCount, expected)
	}
	if p.AcceptedCount != p.PersistedCount {
		return fmt.Errorf("accepted_count=%d persisted_count=%d", p.AcceptedCount, p.PersistedCount)
	}
	if p.MissingCount != 0 {
		return fmt.Errorf("missing_count=%d", p.MissingCount)
	}
	if p.OrderingViolations != 0 {
		return fmt.Errorf("ordering_violations=%d", p.OrderingViolations)
	}
	if expected > 0 {
		if p.FirstLogicalClock != 1 {
			return fmt.Errorf("first_logical_clock=%d want=1", p.FirstLogicalClock)
		}
		if p.LastLogicalClock != expected {
			return fmt.Errorf("last_logical_clock=%d want=%d", p.LastLogicalClock, expected)
		}
	}
	if p.OrderedPersistenceHash == "" {
		return fmt.Errorf("ordered_persistence_hash missing")
	}
	return nil
}

func (p ZeroLossProof) JSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

type ZeroLossLedger struct {
	mu sync.Mutex

	accepted  map[string]uint64
	persisted map[string]uint64
	ordered   []uint64

	duplicatePersistCount uint64
	orderingViolations    uint64
}

func NewZeroLossLedger(expected uint64) *ZeroLossLedger {
	capHint := 0
	if expected > 0 {
		if expected > uint64(^uint(0)>>1) {
			capHint = int(^uint(0) >> 1)
		} else {
			capHint = int(expected)
		}
	}
	return &ZeroLossLedger{
		accepted:  make(map[string]uint64, capHint),
		persisted: make(map[string]uint64, capHint),
		ordered:   make([]uint64, 0, capHint),
	}
}

func (l *ZeroLossLedger) Accept(key string, logicalClock uint64) error {
	if key == "" {
		return fmt.Errorf("accept key missing")
	}
	if logicalClock == 0 {
		return fmt.Errorf("accept logical clock missing")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if prev, exists := l.accepted[key]; exists {
		return fmt.Errorf("duplicate acceptance key=%s logical_clock=%d prev=%d", key, logicalClock, prev)
	}
	wantClock := uint64(len(l.accepted) + 1)
	if logicalClock != wantClock {
		return fmt.Errorf("accept ordering violation got=%d want=%d", logicalClock, wantClock)
	}
	l.accepted[key] = logicalClock
	return nil
}

func (l *ZeroLossLedger) Persist(key string, logicalClock uint64) (bool, error) {
	if key == "" {
		return false, fmt.Errorf("persist key missing")
	}
	if logicalClock == 0 {
		return false, fmt.Errorf("persist logical clock missing")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	acceptedClock, accepted := l.accepted[key]
	if !accepted {
		return false, fmt.Errorf("persist before accept key=%s logical_clock=%d", key, logicalClock)
	}
	if acceptedClock != logicalClock {
		return false, fmt.Errorf("persist logical clock mismatch got=%d want=%d", logicalClock, acceptedClock)
	}
	if prev, exists := l.persisted[key]; exists {
		if prev != logicalClock {
			return false, fmt.Errorf("persist duplicate mismatch key=%s got=%d prev=%d", key, logicalClock, prev)
		}
		l.duplicatePersistCount++
		return false, nil
	}

	wantClock := uint64(len(l.ordered) + 1)
	if logicalClock != wantClock {
		l.orderingViolations++
		return false, fmt.Errorf("persist ordering violation got=%d want=%d", logicalClock, wantClock)
	}

	l.persisted[key] = logicalClock
	l.ordered = append(l.ordered, logicalClock)
	return true, nil
}

func (l *ZeroLossLedger) PersistedCount() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.persisted))
}

func (l *ZeroLossLedger) Proof() ZeroLossProof {
	l.mu.Lock()
	defer l.mu.Unlock()

	acceptedCount := uint64(len(l.accepted))
	persistedCount := uint64(len(l.persisted))
	missing := uint64(0)
	if acceptedCount > persistedCount {
		missing = acceptedCount - persistedCount
	}

	firstClock := uint64(0)
	lastClock := uint64(0)
	if len(l.ordered) > 0 {
		firstClock = l.ordered[0]
		lastClock = l.ordered[len(l.ordered)-1]
	}

	hash := sha256.New()
	for _, logicalClock := range l.ordered {
		_, _ = hash.Write([]byte(strconv.FormatUint(logicalClock, 10)))
		_, _ = hash.Write([]byte{'\n'})
	}
	return ZeroLossProof{
		AcceptedCount:          acceptedCount,
		PersistedCount:         persistedCount,
		DuplicatePersistCount:  l.duplicatePersistCount,
		MissingCount:           missing,
		OrderingViolations:     l.orderingViolations,
		FirstLogicalClock:      firstClock,
		LastLogicalClock:       lastClock,
		OrderedPersistenceHash: hex.EncodeToString(hash.Sum(nil)),
	}
}
