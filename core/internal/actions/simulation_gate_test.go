package actions

import "testing"

func TestNormalizeRiskScore(t *testing.T) {
	tests := []struct {
		name       string
		input      float64
		fallback   float64
		wantStored float64
		wantNorm   float64
	}{
		{name: "normalized", input: 0.7, fallback: 0.2, wantStored: 70, wantNorm: 0.7},
		{name: "percent", input: 70, fallback: 0.2, wantStored: 70, wantNorm: 0.7},
		{name: "fallback", input: 0, fallback: 0.4, wantStored: 40, wantNorm: 0.4},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotStored, gotNorm, err := normalizeRiskScore(tc.input, tc.fallback)
			if err != nil {
				t.Fatalf("normalizeRiskScore() error = %v", err)
			}
			if gotStored != tc.wantStored || gotNorm != tc.wantNorm {
				t.Fatalf("normalizeRiskScore() = (%v, %v), want (%v, %v)", gotStored, gotNorm, tc.wantStored, tc.wantNorm)
			}
		})
	}
}

func TestEffectiveRecommendationForcesHoldAboveThreshold(t *testing.T) {
	got := effectiveRecommendation(recommendationProceed, 0.91, DefaultSimulationRiskThreshold)
	if got != recommendationHold {
		t.Fatalf("effectiveRecommendation() = %s, want %s", got, recommendationHold)
	}
}

func TestExtractAffectedSystemsUsesAttackPathsOnlyData(t *testing.T) {
	nodeSequence := []any{
		"host-a",
		map[string]any{"target": "host-b"},
		[]any{"host-a", "host-c"},
	}

	got := extractAffectedSystems(nodeSequence)
	want := []string{"host-a", "host-b", "host-c"}

	if len(got) != len(want) {
		t.Fatalf("extractAffectedSystems() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extractAffectedSystems()[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}
