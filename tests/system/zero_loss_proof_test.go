package system

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestZeroLossInvariantDeterministic(t *testing.T) {
	dir := t.TempDir()
	firstProof := filepath.Join(dir, "proof-run-1.json")
	secondProof := filepath.Join(dir, "proof-run-2.json")

	runZeroLossProof(t, firstProof)
	runZeroLossProof(t, secondProof)

	first, err := os.ReadFile(firstProof)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", firstProof, err)
	}
	second, err := os.ReadFile(secondProof)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", secondProof, err)
	}
	validateProofContents(t, first)
	if !bytes.Equal(first, second) {
		t.Fatalf("zero-loss proof mismatch between runs\nrun1=%s\nrun2=%s", first, second)
	}
}

func runZeroLossProof(t *testing.T, proofPath string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		"go",
		"test",
		"-timeout",
		"300s",
		"-count=1",
		"./core/internal/pipeline",
		"-run",
		"^TestSystemZeroLossInvariant$",
	)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "RANSOMEYE_SYSTEM_PROOF_OUT="+proofPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("zero-loss proof subprocess timed out after 5m\n%s", output)
		}
		t.Fatalf("zero-loss proof subprocess failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(proofPath); err != nil {
		t.Fatalf("proof file missing after subprocess: %v\n%s", err, output)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root invalid (%s): %v", root, err)
	}
	return root
}

func validateProofContents(t *testing.T, raw []byte) {
	t.Helper()
	expected := expectedEventCount()
	if len(raw) == 0 {
		t.Fatal("proof file is empty")
	}
	if !bytes.Contains(raw, []byte(fmt.Sprintf(`"accepted_count": %d`, expected))) {
		t.Fatalf("proof file missing accepted_count invariant:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(fmt.Sprintf(`"persisted_count": %d`, expected))) {
		t.Fatalf("proof file missing persisted_count invariant:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(`"ordered_persistence_hash"`)) {
		t.Fatalf("proof file missing ordering digest:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(`"pressure_reject_count"`)) {
		t.Fatalf("proof file missing pressure proof:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(`"failsafe_reject_count"`)) {
		t.Fatalf("proof file missing failsafe proof:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(`"restart_count"`)) {
		t.Fatalf("proof file missing restart proof:\n%s", raw)
	}
	if testing.Verbose() {
		fmt.Printf("%s\n", raw)
	}
}

func expectedEventCount() uint64 {
	raw := os.Getenv("RANSOMEYE_ZERO_LOSS_EVENT_COUNT")
	if raw == "" {
		return 1_000_000
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 {
		return 1_000_000
	}
	return value
}
