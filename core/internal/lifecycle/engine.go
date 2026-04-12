package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"ransomeye/core/internal/keys"
)

type Engine struct{}

func NewEngine() *Engine { return &Engine{} }

func (e *Engine) ValidateTransition(from, to keys.Status) error {
	order := map[keys.Status]int{
		keys.StatusStaged:           0,
		keys.StatusActive:           1,
		keys.StatusVerificationOnly: 2,
		keys.StatusExpired:          3,
		keys.StatusRevoked:          4,
		keys.StatusDecommissioned:   5,
	}
	fromRank, ok := order[from]
	if !ok {
		return fmt.Errorf("invalid from status")
	}
	toRank, ok := order[to]
	if !ok {
		return fmt.Errorf("invalid to status")
	}
	if toRank < fromRank {
		return fmt.Errorf("reverse transition forbidden")
	}
	if from == keys.StatusRevoked && to == keys.StatusActive {
		return fmt.Errorf("reactivation of revoked key forbidden")
	}
	return nil
}

func (e *Engine) ValidateRotation(fromEpoch, toEpoch int) error {
	if fromEpoch <= 0 || toEpoch <= 0 {
		return fmt.Errorf("key_epoch must be positive")
	}
	if toEpoch != fromEpoch+1 {
		return fmt.Errorf("rotation must be n->n+1")
	}
	return nil
}

func (e *Engine) ValidateActivation(meta keys.Metadata, signatureVerified bool, expectedIdentityHash, computedIdentityHash string, now time.Time) error {
	if err := keys.ValidateMetadata(meta); err != nil {
		return err
	}
	if !signatureVerified {
		return fmt.Errorf("signature verification required")
	}
	if expectedIdentityHash == "" || computedIdentityHash == "" || expectedIdentityHash != computedIdentityHash {
		return fmt.Errorf("system_identity_hash mismatch")
	}
	if now.Before(meta.NotBeforeUTC) || !now.Before(meta.NotAfterUTC) {
		return fmt.Errorf("validity window invalid for activation")
	}
	return nil
}

func (e *Engine) ValidateRuntimeOperation(meta keys.Metadata, operation string, now time.Time) error {
	if err := keys.ValidateMetadata(meta); err != nil {
		return err
	}
	if !now.Before(meta.NotAfterUTC) {
		return fmt.Errorf("expired key usage rejected")
	}
	if meta.Status == keys.StatusRevoked {
		return fmt.Errorf("revoked key usage rejected")
	}
	switch operation {
	case "sign":
		if meta.Status != keys.StatusActive {
			return fmt.Errorf("signing requires active status")
		}
	case "verify":
		if meta.Status == keys.StatusDecommissioned {
			return fmt.Errorf("verify forbidden for decommissioned status")
		}
	case "activate":
		if meta.Status != keys.StatusStaged {
			return fmt.Errorf("activate requires staged status")
		}
	default:
		return fmt.Errorf("unknown operation")
	}
	if meta.Status == keys.StatusVerificationOnly && operation == "sign" {
		return fmt.Errorf("verification_only cannot sign")
	}
	return nil
}

func (e *Engine) BindSystemIdentity(previousIdentityHash string, meta keys.Metadata) (string, error) {
	if err := keys.ValidateMetadata(meta); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(previousIdentityHash + "|" + meta.KeyID + "|" + fmt.Sprintf("%d|%s", meta.KeyEpoch, meta.Status)))
	next := hex.EncodeToString(sum[:])
	if next == previousIdentityHash {
		return "", fmt.Errorf("system_identity_hash must change on key change")
	}
	return next, nil
}

func (e *Engine) ValidateDistribution(runtimeKeyGeneration bool, updateSource string) error {
	if runtimeKeyGeneration {
		return fmt.Errorf("runtime key generation forbidden")
	}
	if updateSource != "airgap" {
		return fmt.Errorf("airgap-only distribution required")
	}
	return nil
}
