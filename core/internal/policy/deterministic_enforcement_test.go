package policy

import "testing"

func TestDeterministicEnforcementSameDetectionSameAction(t *testing.T) {
	engine := NewEngine(EnforcementPolicy{
		Mode:           ModeAuto,
		Threshold:      0.5,
		AllowedActions: []string{ActionKillProcess, ActionBlockWrite},
	}, true)

	input := DetectionInput{
		Score:          0.97,
		Classification: "malicious",
		Explanation: []ExplanationSignal{
			{Feature: "process_anomaly", Impact: 0.61, Value: 0.8},
			{Feature: "entropy_score", Impact: 0.31, Value: 0.7},
		},
	}

	got1 := engine.Evaluate(input)
	got2 := engine.Evaluate(input)

	if got1 != got2 {
		t.Fatalf("decision mismatch: got1=%+v got2=%+v", got1, got2)
	}
	if got1.Action != ActionKillProcess {
		t.Fatalf("action = %q, want %q", got1.Action, ActionKillProcess)
	}
	if !got1.Allowed {
		t.Fatal("expected allowed=true when auto mode is explicitly enabled")
	}
}

func TestDeterministicEnforcementMapsEncryptionSignalsToBlockWrite(t *testing.T) {
	engine := NewEngine(EnforcementPolicy{
		Mode:           ModeAuto,
		Threshold:      0.5,
		AllowedActions: []string{ActionKillProcess, ActionBlockWrite},
	}, true)

	decision := engine.Evaluate(DetectionInput{
		Score:          0.83,
		Classification: "malicious",
		Explanation: []ExplanationSignal{
			{Feature: "model_prediction", Impact: 0.49, Value: 0.89},
			{Feature: "entropy_score", Impact: 0.13, Value: 0.92},
			{Feature: "burst_score", Impact: 0.15, Value: 1.0},
		},
	})

	if decision.Action != ActionBlockWrite {
		t.Fatalf("action = %q, want %q", decision.Action, ActionBlockWrite)
	}
	if !decision.Allowed {
		t.Fatal("expected allowed=true when auto mode is explicitly enabled")
	}
}
