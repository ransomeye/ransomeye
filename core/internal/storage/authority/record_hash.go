package authority

import (
	"crypto/sha256"
)

// RecordHash is PRD-13 §6.2.1: SHA256(previous_record_hash || canonical_record_bytes).
func RecordHash(previousRecordHash [32]byte, canonicalRecordBytes []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write(previousRecordHash[:])
	_, _ = h.Write(canonicalRecordBytes)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
