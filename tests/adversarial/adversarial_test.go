package adversarial_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

type harnessResult struct {
	Attack               string `json:"attack"`
	Detected             bool   `json:"detected"`
	LatencyMS            int64  `json:"latency_ms"`
	EnforcementLatencyMS int64  `json:"enforcement_latency_ms"`
	FalseNegatives       int    `json:"false_negatives"`
	FalsePositives       int    `json:"false_positives"`
	Enforced             bool   `json:"enforced"`
	ReplayConsistent     bool   `json:"replay_consistent"`
	ExpectedAction       string `json:"expected_action"`
	ObservedAction       string `json:"observed_action"`
}

func TestAdversarialHarness(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "run", "./core/cmd/adversarial-harness")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run adversarial harness: %v\n%s", err, out)
	}

	var results []harnessResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("json.Unmarshal harness output: %v\n%s", err, out)
	}

	expected := map[string]string{
		"high_entropy_encryption": "block_write",
		"low_slow_encryption":     "block_write",
		"fileless_execution":      "kill_process",
		"lolbins_abuse":           "kill_process",
		"process_kill_evasion":    "kill_process",
	}
	if len(results) != len(expected) {
		t.Fatalf("scenario count = %d, want %d", len(results), len(expected))
	}

	seen := make(map[string]harnessResult, len(results))
	for _, result := range results {
		seen[result.Attack] = result
	}

	for attack, action := range expected {
		result, ok := seen[attack]
		if !ok {
			t.Fatalf("missing attack result for %s", attack)
		}
		if !result.Detected {
			t.Fatalf("%s detected = false", attack)
		}
		if !result.Enforced {
			t.Fatalf("%s enforced = false", attack)
		}
		if !result.ReplayConsistent {
			t.Fatalf("%s replay_consistent = false", attack)
		}
		if result.FalseNegatives != 0 {
			t.Fatalf("%s false_negatives = %d, want 0", attack, result.FalseNegatives)
		}
		if result.FalsePositives != 0 {
			t.Fatalf("%s false_positives = %d, want 0", attack, result.FalsePositives)
		}
		if result.ExpectedAction != action {
			t.Fatalf("%s expected_action = %s, want %s", attack, result.ExpectedAction, action)
		}
		if result.ObservedAction != action {
			t.Fatalf("%s observed_action = %s, want %s", attack, result.ObservedAction, action)
		}
		if result.LatencyMS >= 100 {
			t.Fatalf("%s latency_ms = %d, want < 100", attack, result.LatencyMS)
		}
		if result.EnforcementLatencyMS >= 200 {
			t.Fatalf("%s enforcement_latency_ms = %d, want < 200", attack, result.EnforcementLatencyMS)
		}
	}
}

func TestSampleOutputFixture(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "tests", "adversarial", "sample_output.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile sample_output.json: %v", err)
	}

	var results []harnessResult
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatalf("json.Unmarshal sample_output.json: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("sample_output.json entries = %d, want 5", len(results))
	}
	for _, result := range results {
		if result.Attack == "" {
			t.Fatal("sample_output.json contains empty attack name")
		}
		if result.ExpectedAction == "" || result.ObservedAction == "" {
			t.Fatalf("sample_output.json missing action fields for %s", result.Attack)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
