package policy

import (
	"fmt"

	"ransomeye/core/internal/contracts"
	"ransomeye/core/internal/health"
)

// BlockReason is the result of policy evaluation (allow or block and why).
type BlockReason int

const (
	BlockNone BlockReason = iota
	BlockNoDPI
	BlockNoSINE
	BlockNoAI
	BlockPipelineDegraded
)

// PolicyEvaluator evaluates whether enforcement dispatch is allowed.
// Holds the state provider; router must not access BlockEvalStateProvider directly.
type PolicyEvaluator struct {
	stateProvider contracts.BlockEvalStateProvider
}

// NewPolicyEvaluator returns an evaluator that uses the given state provider internally.
func NewPolicyEvaluator(stateProvider contracts.BlockEvalStateProvider) *PolicyEvaluator {
	return &PolicyEvaluator{stateProvider: stateProvider}
}

// Evaluate returns BlockNone if dispatch is allowed, else the reason to block.
// State is read inside the policy layer; router does not access state directly.
func (e *PolicyEvaluator) Evaluate() BlockReason {
	if e.stateProvider == nil {
		return BlockPipelineDegraded
	}
	state := e.stateProvider.GetBlockEvalState()
	if health.DPIPlaneEnvConfigured() && !state.DPIReady {
		return BlockNoDPI
	}
	if health.SINEPlaneEnvConfigured() && !state.SINEReady {
		return BlockNoSINE
	}
	if health.AIPlaneEnvConfigured() && !state.AIReady {
		return BlockNoAI
	}
	if !state.PipelineHealthy {
		return BlockPipelineDegraded
	}
	return BlockNone
}

// EvaluateEnforcementDispatch gates automated enforcement dispatch (kill/block-write) on the ingest worker.
// Mishka: advisory AI must not gate authoritative execution; DPI is not part of the agent-telemetry
// enforcement precondition (optional DPI plane down must not block linux_agent dispatch).
// Configured SINE is on the hot path (Filter before persistence), so SINE readiness is enforced here too.
func (e *PolicyEvaluator) EvaluateEnforcementDispatch() BlockReason {
	if e == nil {
		return BlockPipelineDegraded
	}
	if e.stateProvider == nil {
		return BlockPipelineDegraded
	}
	state := e.stateProvider.GetBlockEvalState()
	if !state.PipelineHealthy {
		return BlockPipelineDegraded
	}
	if health.SINEPlaneEnvConfigured() && !state.SINEReady {
		return BlockNoSINE
	}
	return BlockNone
}

// FormatEnforcementDispatchBlock returns a stable machine-readable reason for logs and SOC JSON.
func FormatEnforcementDispatchBlock(r BlockReason) string {
	switch r {
	case BlockNone:
		return ""
	case BlockNoDPI:
		return "no_dpi"
	case BlockNoSINE:
		return "no_sine"
	case BlockNoAI:
		return "no_ai"
	case BlockPipelineDegraded:
		return "pipeline_degraded"
	default:
		return fmt.Sprintf("unknown_%d", int(r))
	}
}
