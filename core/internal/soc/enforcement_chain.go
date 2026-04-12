package soc

import (
	"ransomeye/core/internal/health"
	"ransomeye/core/internal/policy"
)

// IsolationSimulationGateScope documents where actions.SimulationGate applies (PRD-20 honesty).
const IsolationSimulationGateScope = "db_hil_isolate_host_only_not_pipeline_automation"

// AuthoritativeDecisionPath is the in-process Mishka decision path (not advisory AI).
const AuthoritativeDecisionPath = "deterministic_detector_in_process"

// EnforcementDispatchGateView is the live pre-dispatch gate used by pipeline workers (fail-closed).
func EnforcementDispatchGateView() (blocked bool, reason string) {
	ev := policy.NewPolicyEvaluator(health.BlockEvalStateProvider())
	r := ev.EvaluateEnforcementDispatch()
	if r == policy.BlockNone {
		return false, ""
	}
	return true, policy.FormatEnforcementDispatchBlock(r)
}
