package storage

import "testing"

func TestAuthoritySnapshotValidate(t *testing.T) {
	snapshot := AuthoritySnapshot{
		AuthorityType:        "CONFIG",
		AuthorityID:          "chaos_validation_matrix",
		AuthorityVersion:     "v1",
		CanonicalPayloadText: "{\"mode\":\"strict\"}",
		PayloadHash:          bytesOfLen(32),
		Signature:            []byte{0x01},
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestAuthoritySnapshotValidateRejectsUnknownType(t *testing.T) {
	snapshot := AuthoritySnapshot{
		AuthorityType:        "UNKNOWN",
		AuthorityID:          "x",
		AuthorityVersion:     "v1",
		CanonicalPayloadText: "{}",
		PayloadHash:          bytesOfLen(32),
		Signature:            []byte{0x01},
	}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("Validate() expected error for unknown authority type")
	}
}

func TestReplayGuardEntryValidate(t *testing.T) {
	entry := ReplayGuardEntry{
		PartitionID:    7,
		LogicalShardID: []byte{0x01},
		EmitterID:      []byte{0x02},
		BootSessionID:  []byte{0x03},
		LogicalClock:   "42",
		MessageID:      []byte{0x04},
		SeenState:      ReplayGuardStateAdmitted,
	}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestReplayGuardEntryValidateRejectsBadClock(t *testing.T) {
	entry := ReplayGuardEntry{
		PartitionID:    7,
		LogicalShardID: []byte{0x01},
		EmitterID:      []byte{0x02},
		BootSessionID:  []byte{0x03},
		LogicalClock:   "4x2",
		MessageID:      []byte{0x04},
		SeenState:      ReplayGuardStateAdmitted,
	}
	if err := entry.Validate(); err == nil {
		t.Fatal("Validate() expected error for non-decimal logical_clock")
	}
}

func bytesOfLen(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i + 1)
	}
	return out
}
