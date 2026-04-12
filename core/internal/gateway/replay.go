package gateway

import (
	"crypto/sha256"

	"github.com/google/uuid"
)

// ReplayKey is deterministic: SHA-256(identity_id || boot_session_id || message_id)
// over fixed 16-byte UUID segments.
//
// Domain-separation tags are intentionally not applied here because they are
// currently unspecified by normative PRD text.
func ReplayKey(identityUUID uuid.UUID, bootSessionID uuid.UUID, messageID uuid.UUID) [32]byte {
	identity := [16]byte(identityUUID)
	boot := [16]byte(bootSessionID)
	message := [16]byte(messageID)
	buf := make([]byte, 48)
	copy(buf[0:16], identity[:])
	copy(buf[16:32], boot[:])
	copy(buf[32:48], message[:])
	return sha256.Sum256(buf)
}
