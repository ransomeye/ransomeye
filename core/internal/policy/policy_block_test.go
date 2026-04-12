package policy

import "testing"

func TestPolicyBlockAutoDisabled(t *testing.T) {
	engine := NewEngine(EnforcementPolicy{
		Mode:           ModeAuto,
		Threshold:      0.5,
		AllowedActions: []string{ActionKillProcess, ActionBlockWrite},
	}, false)

	decision := engine.Evaluate(DetectionInput{
		Score:          0.99,
		Classification: "malicious",
		Explanation: []ExplanationSignal{
			{Feature: "process_anomaly", Impact: 0.72, Value: 0.9},
		},
	})

	if decision.Action != ActionKillProcess {
		t.Fatalf("action = %q, want %q", decision.Action, ActionKillProcess)
	}
	if decision.Allowed {
		t.Fatal("auto=false must block execution")
	}
}
