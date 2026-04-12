package signature

import (
	"strings"
	"testing"
	"time"

	"ransomeye/core/internal/keys"
)

func meta(status keys.Status) keys.Metadata {
	now := time.Now().UTC()
	return keys.Metadata{
		KeyEpoch:     1,
		KeyID:        strings.Repeat("a", 64),
		Status:       status,
		NotBeforeUTC: now.Add(-time.Hour),
		NotAfterUTC:  now.Add(time.Hour),
	}
}

func TestVerifyRejectsRevokedExpired(t *testing.T) {
	if err := VerifyWithLifecycle(meta(keys.StatusRevoked), func() bool { return true }, time.Now().UTC()); err == nil {
		t.Fatal("expected revoked verification reject")
	}
	expired := meta(keys.StatusActive)
	expired.NotAfterUTC = time.Now().UTC().Add(-time.Minute)
	if err := VerifyWithLifecycle(expired, func() bool { return true }, time.Now().UTC()); err == nil {
		t.Fatal("expected expired verification reject")
	}
}

func TestVerifyAllowsVerificationOnly(t *testing.T) {
	if err := VerifyWithLifecycle(meta(keys.StatusVerificationOnly), func() bool { return true }, time.Now().UTC()); err != nil {
		t.Fatalf("verification_only should verify: %v", err)
	}
}
