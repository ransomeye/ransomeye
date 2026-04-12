package replay

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"ransomeye/core/internal/ai"
	corecrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/ingest"
)

func TestDeterministicReplay(t *testing.T) {
	envelope, _ := deterministicReplayEnvelope(t)
	setMatchingReplayEnv(t, envelope)

	run1, run2, err := VerifyEnvelope(context.Background(), envelope)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if run1.OutputHash != run2.OutputHash {
		t.Fatalf("output hash mismatch\nrun1=%s\nrun2=%s", run1.OutputHash, run2.OutputHash)
	}
	if stage, expectedHash, actualHash, ok := FirstStageMismatch(run1.StageHashes, run2.StageHashes); ok {
		t.Fatalf("stage hash mismatch stage=%s expected=%s actual=%s", stage, expectedHash, actualHash)
	}
	if run1.StageHashes.Final != run1.OutputHash {
		t.Fatalf("final stage hash = %s, want %s", run1.StageHashes.Final, run1.OutputHash)
	}
	assertStageHashesPresent(t, run1.StageHashes)
}

func TestEnvironmentMismatch(t *testing.T) {
	envelope, _ := deterministicReplayEnvelope(t)

	t.Run("config", func(t *testing.T) {
		setMatchingReplayEnv(t, envelope)
		t.Setenv(DefaultConfigHashEnv, strings.Repeat("f", 64))
		_, err := RunEnvelope(context.Background(), envelope)
		if err == nil || !strings.Contains(err.Error(), "config mismatch") {
			t.Fatalf("RunEnvelope error = %v, want config mismatch", err)
		}
	})

	t.Run("model", func(t *testing.T) {
		setMatchingReplayEnv(t, envelope)
		t.Setenv(DefaultModelHashEnv, strings.Repeat("e", 64))
		_, err := RunEnvelope(context.Background(), envelope)
		if err == nil || !strings.Contains(err.Error(), "model mismatch") {
			t.Fatalf("RunEnvelope error = %v, want model mismatch", err)
		}
	})

	t.Run("feature_version", func(t *testing.T) {
		setMatchingReplayEnv(t, envelope)
		t.Setenv(DefaultFeatureVersionEnv, "ml.features.v2")
		_, err := RunEnvelope(context.Background(), envelope)
		if err == nil || !strings.Contains(err.Error(), "feature version mismatch") {
			t.Fatalf("RunEnvelope error = %v, want feature version mismatch", err)
		}
	})

	t.Run("prd", func(t *testing.T) {
		setMatchingReplayEnv(t, envelope)
		t.Setenv(DefaultPRDHashEnv, strings.Repeat("d", 64))
		_, err := RunEnvelope(context.Background(), envelope)
		if err == nil || !strings.Contains(err.Error(), "PRD mismatch") {
			t.Fatalf("RunEnvelope error = %v, want PRD mismatch", err)
		}
	})
}

func TestDecisionTimestampDeterministic(t *testing.T) {
	envelope, _ := deterministicReplayEnvelope(t)
	setMatchingReplayEnv(t, envelope)

	result, err := RunEnvelope(context.Background(), envelope)
	if err != nil {
		t.Fatalf("RunEnvelope: %v", err)
	}

	var decisions []struct {
		Timestamp int64 `json:"timestamp"`
	}
	if err := json.Unmarshal(result.StageArtifacts.Decision, &decisions); err != nil {
		t.Fatalf("json.Unmarshal decision artifacts: %v", err)
	}
	if len(decisions) == 0 {
		t.Fatal("decision artifacts empty")
	}
	want := int64(envelope.Events[0].TimestampUnixNano / 1_000_000_000)
	if decisions[0].Timestamp != want {
		t.Fatalf("decision timestamp = %d, want %d", decisions[0].Timestamp, want)
	}
	if decisions[0].Timestamp == time.Now().UTC().Unix() {
		t.Fatal("decision timestamp unexpectedly matched current wall clock")
	}
}

func TestReplayArtifactsBoundToHashes(t *testing.T) {
	envelope, _ := deterministicReplayEnvelope(t)
	setMatchingReplayEnv(t, envelope)

	result, err := RunEnvelope(context.Background(), envelope)
	if err != nil {
		t.Fatalf("RunEnvelope: %v", err)
	}

	checks := []struct {
		name string
		raw  json.RawMessage
		hash string
	}{
		{name: stageCapture, raw: result.StageArtifacts.Capture, hash: result.InputHash},
		{name: stageIngest, raw: result.StageArtifacts.Ingest, hash: result.StageHashes.Ingest},
		{name: stageFeature, raw: result.StageArtifacts.Feature, hash: result.StageHashes.Feature},
		{name: stageModel, raw: result.StageArtifacts.Model, hash: result.StageHashes.Model},
		{name: stageSINE, raw: result.StageArtifacts.SINE, hash: result.StageHashes.SINE},
		{name: stageDecision, raw: result.StageArtifacts.Decision, hash: result.StageHashes.Decision},
		{name: stageEnforcement, raw: result.StageArtifacts.Enforcement, hash: result.StageHashes.Enforcement},
		{name: stageFinal, raw: result.StageArtifacts.Final, hash: result.StageHashes.Final},
	}
	for _, check := range checks {
		_, got, err := marshalAndHash(json.RawMessage(check.raw))
		if err != nil {
			t.Fatalf("marshalAndHash %s: %v", check.name, err)
		}
		if got != check.hash {
			t.Fatalf("%s hash = %s, want %s", check.name, got, check.hash)
		}
	}
}

func TestDeterministicCrossProcess(t *testing.T) {
	envelope, path := deterministicReplayEnvelope(t)
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot: %v", err)
	}

	run1 := runReplayCommand(t, root, path, envelope)
	run2 := runReplayCommand(t, root, path, envelope)

	if run1.OutputHash != run2.OutputHash {
		t.Fatalf("cross-process output hash mismatch\nrun1=%s\nrun2=%s", run1.OutputHash, run2.OutputHash)
	}
	if stage, expectedHash, actualHash, ok := FirstStageMismatch(run1.StageHashes, run2.StageHashes); ok {
		t.Fatalf("cross-process stage hash mismatch stage=%s expected=%s actual=%s", stage, expectedHash, actualHash)
	}
}

func deterministicReplayEnvelope(t *testing.T) (Envelope, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.rre")
	runtimeModel := replayRuntimeModel(t)
	capture, err := NewInputCapture(path, Metadata{
		ConfigHash:     strings.Repeat("1", 64),
		ModelHash:      runtimeModel.Identity.ModelHash,
		FeatureVersion: runtimeModel.Identity.FeatureVersion,
		PRDHash:        strings.Repeat("3", 64),
	})
	if err != nil {
		t.Fatalf("NewInputCapture: %v", err)
	}

	ev1 := deterministicReplayEvent(
		t,
		7,
		uuid.MustParse("00000000-0000-0000-0000-000000000007"),
		1_700_000_000_000_000_000,
		ingest.EventTypeCodeDecept,
		4242,
		250,
		251,
		252,
		8,
		"DECEPTION_EVENT",
	)
	ev2 := deterministicReplayEvent(
		t,
		8,
		uuid.MustParse("00000000-0000-0000-0000-000000000008"),
		1_700_000_000_000_000_100,
		ingest.EventTypeCodeDecept,
		999999,
		255,
		254,
		253,
		8,
		"DECEPTION_EVENT",
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
	return envelope, path
}

func setMatchingReplayEnv(t *testing.T, envelope Envelope) {
	t.Helper()
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot: %v", err)
	}
	t.Setenv(DefaultConfigHashEnv, envelope.ConfigHash)
	t.Setenv(DefaultModelHashEnv, envelope.ModelHash)
	t.Setenv(DefaultFeatureVersionEnv, envelope.FeatureVersion)
	t.Setenv(DefaultPRDHashEnv, envelope.PRDHash)
	t.Setenv("RANSOMEYE_AI_ROOT", filepath.Join(root, "ml"))
}

func runReplayCommand(t *testing.T, repoRoot, inputPath string, envelope Envelope) Result {
	t.Helper()

	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("sudo -n is required for cross-process replay verification")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("exec.LookPath(go): %v", err)
	}
	cmd := exec.Command(
		"sudo",
		"-n",
		"env",
		DefaultConfigHashEnv+"="+envelope.ConfigHash,
		DefaultModelHashEnv+"="+envelope.ModelHash,
		DefaultFeatureVersionEnv+"="+envelope.FeatureVersion,
		DefaultPRDHashEnv+"="+envelope.PRDHash,
		"RANSOMEYE_AI_ROOT="+filepath.Join(repoRoot, "ml"),
		"RANSOMEYE_REPO_ROOT="+repoRoot,
		goBin,
		"run",
		"./core/cmd/replay-engine",
		"--input",
		inputPath,
	)
	if signingKeyPath := strings.TrimSpace(os.Getenv(DefaultReplaySigningKeyEnv)); signingKeyPath != "" {
		cmd.Args = append(cmd.Args[:4], append([]string{
			DefaultReplaySigningKeyEnv + "=" + signingKeyPath,
		}, cmd.Args[4:]...)...)
	}
	cmd.Dir = repoRoot
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("replay command failed: %v", err)
	}

	var result Result
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("json.Unmarshal replay command output: %v\noutput=%s", err, string(out))
	}
	return result
}

func replayRuntimeModel(t *testing.T) ai.RuntimeModel {
	t.Helper()
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot: %v", err)
	}
	keyPath := corecrypto.ResolveWormSigningKeyPath()
	f, err := os.Open(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || os.IsPermission(err) {
			t.Skipf("replay tests require readable worm signing key at %s: %v", keyPath, err)
		}
		t.Fatalf("worm signing key: %v", err)
	}
	_ = f.Close()
	t.Setenv(DefaultReplaySigningKeyEnv, keyPath)
	previousLoader := loadReplayRuntimeModel
	loadReplayRuntimeModel = func(root string) (ai.RuntimeModel, error) {
		return ai.LoadRuntimeModelFromRootWithSigningKeyPath(root, keyPath)
	}
	t.Cleanup(func() { loadReplayRuntimeModel = previousLoader })
	model, err := loadReplayRuntimeModel(filepath.Join(root, "ml"))
	if err != nil {
		t.Fatalf("LoadRuntimeModelFromRootWithSigningKeyPath: %v", err)
	}
	return model
}

func deterministicReplayEvent(
	t *testing.T,
	logicalClock uint64,
	eventID uuid.UUID,
	timestampUnixNano uint64,
	eventTypeCode uint32,
	auxPID uint32,
	processByte byte,
	fileByte byte,
	networkByte byte,
	droppedCount uint64,
	eventType string,
) *ingest.VerifiedTelemetry {
	t.Helper()

	agentID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	var processHash [32]byte
	var fileHash [32]byte
	var networkTuple [16]byte
	var bootSessionID [16]byte
	processHash[0] = processByte
	fileHash[0] = fileByte
	networkTuple[0] = networkByte
	bootSessionID[0] = byte(logicalClock + 3)

	payload, err := ingest.BuildCanonicalV1(
		logicalClock,
		agentID,
		eventID,
		eventTypeCode,
		auxPID,
		processHash,
		fileHash,
		networkTuple,
		timestampUnixNano,
		bootSessionID,
	)
	if err != nil {
		t.Fatalf("BuildCanonicalV1: %v", err)
	}

	return &ingest.VerifiedTelemetry{
		Payload:        payload[:],
		AgentSignature: []byte("deterministic-signature"),
		AgentIDStr:     agentID.String(),
		EventType:      eventType,
		TimestampUnix:  float64(timestampUnixNano) / 1e9,
		LogicalClock:   int64(logicalClock),
		DroppedCount:   droppedCount,
	}
}

func assertStageHashesPresent(t *testing.T, hashes StageHashes) {
	t.Helper()
	for stage, value := range map[string]string{
		stageIngest:      hashes.Ingest,
		stageFeature:     hashes.Feature,
		stageModel:       hashes.Model,
		stageSINE:        hashes.SINE,
		stageDecision:    hashes.Decision,
		stageEnforcement: hashes.Enforcement,
		stageFinal:       hashes.Final,
	} {
		if value == "" {
			t.Fatalf("missing stage hash for %s", stage)
		}
	}
}
