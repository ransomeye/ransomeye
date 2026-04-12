package pipeline

import (
	"time"

	"ransomeye/core/internal/policy"
)

// DetectionEvent is a lightweight SOC-facing event emitted by pipeline.
type DetectionEvent struct {
	ID              string
	Timestamp       time.Time
	Confidence      float64
	Decision        string
	ModelPrediction float64
	EntropyScore    float64
	BurstScore      float64
	ProcessAnomaly  float64
	SinePass        bool
	Explanation     []DetectionContribution
	PolicyDecision  policy.EnforcementDecision
}

type DetectionContribution struct {
	Feature string
	Impact  float64
	Value   float64
}
