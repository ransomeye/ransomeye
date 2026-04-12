package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Status string

const (
	StatusStaged           Status = "staged"
	StatusActive           Status = "active"
	StatusVerificationOnly Status = "verification_only"
	StatusExpired          Status = "expired"
	StatusRevoked          Status = "revoked"
	StatusDecommissioned   Status = "decommissioned"
)

type Metadata struct {
	KeyEpoch     int
	KeyID        string
	Status       Status
	NotBeforeUTC time.Time
	NotAfterUTC  time.Time
}

func ComputeKeyIDSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func NormalizeKeyID(keyID string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(keyID))
	if len(value) != sha256.Size*2 {
		return "", fmt.Errorf("key_id must be %d hex characters", sha256.Size*2)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("key_id invalid: %w", err)
	}
	return value, nil
}

func ValidateMetadata(meta Metadata) error {
	if meta.KeyEpoch <= 0 {
		return fmt.Errorf("key_epoch must be positive")
	}
	keyID, err := NormalizeKeyID(meta.KeyID)
	if err != nil {
		return err
	}
	meta.KeyID = keyID
	switch meta.Status {
	case StatusStaged, StatusActive, StatusVerificationOnly, StatusExpired, StatusRevoked, StatusDecommissioned:
	default:
		return fmt.Errorf("status unsupported")
	}
	if meta.NotBeforeUTC.IsZero() || meta.NotAfterUTC.IsZero() {
		return fmt.Errorf("validity window missing")
	}
	if !meta.NotAfterUTC.After(meta.NotBeforeUTC) {
		return fmt.Errorf("validity window invalid")
	}
	return nil
}
