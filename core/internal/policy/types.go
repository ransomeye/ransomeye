package policy

const (
	ModeObserve = "observe"
	ModeManual  = "manual"
	ModeAuto    = "auto"

	ActionNone        = "none"
	ActionKillProcess = "kill_process"
	ActionBlockWrite  = "block_write"
)

type EnforcementPolicy struct {
	Mode           string
	Threshold      float64
	AllowedActions []string
}

type ExplanationSignal struct {
	Feature string
	Impact  float64
	Value   float64
}

type DetectionInput struct {
	Score          float64
	Classification string
	Explanation    []ExplanationSignal
}

type EnforcementDecision struct {
	Action  string
	Allowed bool
}

type DecisionEvaluator interface {
	Evaluate(DetectionInput) EnforcementDecision
}
