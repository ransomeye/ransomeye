package replay

import (
	"context"
	"testing"
)

func TestReplayEnforcementProducesIdenticalActions(t *testing.T) {
	envelope, _ := deterministicReplayEnvelope(t)
	setMatchingReplayEnv(t, envelope)

	run1, run2, err := VerifyEnvelope(context.Background(), envelope)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if run1.StageHashes.Enforcement != run2.StageHashes.Enforcement {
		t.Fatalf(
			"enforcement stage hash mismatch\nrun1=%s\nrun2=%s",
			run1.StageHashes.Enforcement,
			run2.StageHashes.Enforcement,
		)
	}
	if run1.StageHashes.Enforcement == "" {
		t.Fatal("expected non-empty enforcement stage hash")
	}
}
