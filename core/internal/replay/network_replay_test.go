package replay

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"ransomeye/core/internal/ingest"
)

func TestReplayNetworkEventsDeterministic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network.rre")
	runtimeModel := replayRuntimeModel(t)
	capture, err := NewInputCapture(path, Metadata{
		ConfigHash:     strings64("1"),
		ModelHash:      runtimeModel.Identity.ModelHash,
		FeatureVersion: runtimeModel.Identity.FeatureVersion,
		PRDHash:        strings64("3"),
	})
	if err != nil {
		t.Fatalf("NewInputCapture: %v", err)
	}

	ev1 := deterministicReplayEvent(
		t,
		31,
		uuid.MustParse("00000000-0000-0000-0000-000000000031"),
		1_700_000_000_000_000_031,
		ingest.EventTypeCodeNetwork,
		0,
		0x10,
		0x11,
		0x12,
		0,
		"NETWORK_EVENT",
	)
	ev2 := deterministicReplayEvent(
		t,
		32,
		uuid.MustParse("00000000-0000-0000-0000-000000000032"),
		1_700_000_000_000_000_032,
		ingest.EventTypeCodeNetwork,
		0,
		0x20,
		0x21,
		0x22,
		0,
		"NETWORK_EVENT",
	)

	if err := capture.CaptureVerifiedDPIEvent(ev1); err != nil {
		t.Fatalf("CaptureVerifiedDPIEvent ev1: %v", err)
	}
	if err := capture.CaptureVerifiedDPIEvent(ev2); err != nil {
		t.Fatalf("CaptureVerifiedDPIEvent ev2: %v", err)
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("InputCapture.Close: %v", err)
	}

	envelope, err := LoadEnvelope(path)
	if err != nil {
		t.Fatalf("LoadEnvelope: %v", err)
	}
	setMatchingReplayEnv(t, envelope)

	run1, run2, err := VerifyEnvelope(context.Background(), envelope)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if run1.OutputHash != run2.OutputHash {
		t.Fatalf("output hash mismatch: %s vs %s", run1.OutputHash, run2.OutputHash)
	}
	if run1.StageHashes != run2.StageHashes {
		t.Fatalf("stage hash mismatch:\n%s", DiffStageHashes(run1.StageHashes, run2.StageHashes))
	}
	if run1.StageHashes.Feature != run2.StageHashes.Feature {
		t.Fatalf("feature stage hash mismatch: %s vs %s", run1.StageHashes.Feature, run2.StageHashes.Feature)
	}
	if run1.StageHashes.Model != run2.StageHashes.Model {
		t.Fatalf("model stage hash mismatch: %s vs %s", run1.StageHashes.Model, run2.StageHashes.Model)
	}
}

func strings64(fill string) string {
	out := make([]byte, 64)
	copyByte := byte(fill[0])
	for idx := range out {
		out[idx] = copyByte
	}
	return string(out)
}
