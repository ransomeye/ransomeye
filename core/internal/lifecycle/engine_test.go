package lifecycle

import (
	"strings"
	"testing"
	"time"

	"ransomeye/core/internal/keys"
)

func baseMeta() keys.Metadata {
	return keys.Metadata{
		KeyEpoch:     1,
		KeyID:        strings.Repeat("a", 64),
		Status:       keys.StatusStaged,
		NotBeforeUTC: time.Unix(1000, 0).UTC(),
		NotAfterUTC:  time.Unix(2000, 0).UTC(),
	}
}

func TestTransition_DowngradeRejected(t *testing.T) {
	e := NewEngine()
	if err := e.ValidateTransition(keys.StatusActive, keys.StatusStaged); err == nil {
		t.Fatal("expected downgrade rejection")
	}
}

func TestTransition_RevokedReactivationRejected(t *testing.T) {
	e := NewEngine()
	if err := e.ValidateTransition(keys.StatusRevoked, keys.StatusActive); err == nil {
		t.Fatal("expected revoked reactivation rejection")
	}
}

func TestRotationSkipRejected(t *testing.T) {
	e := NewEngine()
	if err := e.ValidateRotation(1, 3); err == nil {
		t.Fatal("expected rotation skip rejection")
	}
}

func TestActivationRequiresSignatureIdentityAndWindow(t *testing.T) {
	e := NewEngine()
	meta := baseMeta()
	now := time.Unix(1500, 0).UTC()
	if err := e.ValidateActivation(meta, true, "id1", "id1", now); err != nil {
		t.Fatalf("activation should pass: %v", err)
	}
	if err := e.ValidateActivation(meta, false, "id1", "id1", now); err == nil {
		t.Fatal("expected signature verification rejection")
	}
	if err := e.ValidateActivation(meta, true, "id1", "id2", now); err == nil {
		t.Fatal("expected identity hash mismatch rejection")
	}
	if err := e.ValidateActivation(meta, true, "id1", "id1", time.Unix(2500, 0).UTC()); err == nil {
		t.Fatal("expected validity window rejection")
	}
}

func TestRuntimeExpiredAndRevokedRejected(t *testing.T) {
	e := NewEngine()
	meta := baseMeta()
	meta.Status = keys.StatusActive
	if err := e.ValidateRuntimeOperation(meta, "sign", time.Unix(2500, 0).UTC()); err == nil {
		t.Fatal("expected expired key rejection")
	}
	meta = baseMeta()
	meta.Status = keys.StatusRevoked
	if err := e.ValidateRuntimeOperation(meta, "verify", time.Unix(1500, 0).UTC()); err == nil {
		t.Fatal("expected revoked key rejection")
	}
}

func TestVerificationOnlyCannotSign(t *testing.T) {
	e := NewEngine()
	meta := baseMeta()
	meta.Status = keys.StatusVerificationOnly
	if err := e.ValidateRuntimeOperation(meta, "sign", time.Unix(1500, 0).UTC()); err == nil {
		t.Fatal("expected verification_only sign rejection")
	}
}

func TestSystemIdentityMustChangeOnKeyChange(t *testing.T) {
	e := NewEngine()
	meta := baseMeta()
	next, err := e.BindSystemIdentity(strings.Repeat("0", 64), meta)
	if err != nil {
		t.Fatalf("BindSystemIdentity failed: %v", err)
	}
	if next == strings.Repeat("0", 64) {
		t.Fatal("identity hash did not change")
	}
}

func TestDistributionAirgapOnly(t *testing.T) {
	e := NewEngine()
	if err := e.ValidateDistribution(false, "airgap"); err != nil {
		t.Fatalf("airgap distribution should pass: %v", err)
	}
	if err := e.ValidateDistribution(true, "airgap"); err == nil {
		t.Fatal("expected runtime key generation rejection")
	}
	if err := e.ValidateDistribution(false, "internet"); err == nil {
		t.Fatal("expected internet update rejection")
	}
}
