package pipeline

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/ingest"
)

func TestPRD13PartitionID_MissingEnvFailsClosed(t *testing.T) {
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "")
	if got := prd13PartitionID(); got != 0 {
		t.Fatalf("prd13PartitionID() = %d, want 0", got)
	}
}

func TestPRD13PartitionID_MalformedEnvFailsClosed(t *testing.T) {
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "not-an-int")
	if got := prd13PartitionID(); got != 0 {
		t.Fatalf("prd13PartitionID() = %d, want 0", got)
	}
}

func TestPRD13PartitionID_NonPositiveEnvFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  string
	}{
		{name: "zero", val: "0"},
		{name: "negative", val: "-11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", tc.val)
			if got := prd13PartitionID(); got != 0 {
				t.Fatalf("prd13PartitionID() = %d, want 0", got)
			}
		})
	}
}

func TestPRD13PartitionID_ValidPositiveEnv(t *testing.T) {
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "13")
	if got := prd13PartitionID(); got != 13 {
		t.Fatalf("prd13PartitionID() = %d, want 13", got)
	}
}

func TestAppendPRD13CommittedSignal_InvalidPartitionFailsClosed(t *testing.T) {
	t.Setenv("RANSOMEYE_PRD13_PARTITION_ID", "bogus")
	seed := sha256.Sum256([]byte("pipeline-worker-partition-test-seed"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])

	ev := &ingest.VerifiedTelemetry{
		Payload:        []byte("payload"),
		AgentSignature: make([]byte, ed25519.SignatureSize),
	}
	contentHash := sha256.Sum256(ev.Payload)
	meta := ack.Metadata{
		ReplayKey:     strings.Repeat("a", 64) + "|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222|33333333-3333-4333-8333-333333333333",
		MessageID:     "33333333-3333-4333-8333-333333333333",
		ContentSHA256: contentHash,
	}
	p := &WorkerPool{
		PRD13CommitKey:      privateKey,
		PRD13CommitKeyID:    "k1",
		PRD13CommitKeyEpoch: 1,
	}

	err := p.appendPRD13CommittedSignal(context.Background(), nil, meta, ev)
	if err == nil {
		t.Fatal("expected invalid partition config error")
	}
	if !strings.Contains(err.Error(), "partition_id") {
		t.Fatalf("unexpected error: %v", err)
	}
}
