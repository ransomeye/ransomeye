package policy

import "sort"

const defaultThreshold = 0.9

type Engine struct {
	policy           EnforcementPolicy
	autoEnforceReady bool
}

func NewEngine(policy EnforcementPolicy, autoEnforceReady bool) *Engine {
	return &Engine{
		policy:           normalizePolicy(policy),
		autoEnforceReady: autoEnforceReady,
	}
}

func DefaultEnforcementPolicy() EnforcementPolicy {
	return EnforcementPolicy{
		Mode:           ModeObserve,
		Threshold:      defaultThreshold,
		AllowedActions: []string{ActionKillProcess, ActionBlockWrite},
	}
}

func (e *Engine) Evaluate(input DetectionInput) EnforcementDecision {
	decision := EnforcementDecision{Action: ActionNone, Allowed: false}
	if e == nil {
		return decision
	}

	policy := normalizePolicy(e.policy)
	if input.Classification != "malicious" {
		return decision
	}
	if input.Score < policy.Threshold {
		return decision
	}

	action := mapDetectionToAction(input.Explanation)
	if action == ActionNone {
		return decision
	}
	if !policyAllowsAction(policy, action) {
		return decision
	}

	decision.Action = action
	if policy.Mode != ModeAuto {
		return decision
	}
	if !e.autoEnforceReady {
		return decision
	}

	decision.Allowed = true
	return decision
}

func normalizePolicy(policy EnforcementPolicy) EnforcementPolicy {
	switch policy.Mode {
	case ModeObserve, ModeManual, ModeAuto:
	default:
		policy.Mode = ModeObserve
	}

	if policy.Threshold < 0 || policy.Threshold > 1 {
		policy.Threshold = defaultThreshold
	}

	filtered := make([]string, 0, len(policy.AllowedActions))
	seen := make(map[string]struct{}, len(policy.AllowedActions))
	for _, action := range policy.AllowedActions {
		switch action {
		case ActionKillProcess, ActionBlockWrite:
			if _, ok := seen[action]; ok {
				continue
			}
			seen[action] = struct{}{}
			filtered = append(filtered, action)
		}
	}
	sort.Strings(filtered)
	policy.AllowedActions = filtered
	return policy
}

func policyAllowsAction(policy EnforcementPolicy, action string) bool {
	for _, allowed := range policy.AllowedActions {
		if allowed == action {
			return true
		}
	}
	return false
}

func mapDetectionToAction(explanation []ExplanationSignal) string {
	if len(explanation) == 0 {
		return ActionNone
	}

	signals := make(map[string]ExplanationSignal, len(explanation))
	for _, item := range explanation {
		signals[item.Feature] = item
	}
	if entropy, ok := signals["entropy_score"]; ok && entropy.Value >= 0.8 {
		return ActionBlockWrite
	}
	if burst, ok := signals["burst_score"]; ok && burst.Value >= 0.9 {
		if entropy, ok := signals["entropy_score"]; ok && entropy.Value >= 0.55 {
			return ActionBlockWrite
		}
	}

	best := explanation[0]
	for _, item := range explanation[1:] {
		if item.Impact > best.Impact {
			best = item
			continue
		}
		if item.Impact == best.Impact && item.Feature < best.Feature {
			best = item
		}
	}

	switch best.Feature {
	case "entropy_score", "burst_score":
		return ActionBlockWrite
	case "model_prediction", "process_anomaly":
		return ActionKillProcess
	default:
		return ActionKillProcess
	}
}
