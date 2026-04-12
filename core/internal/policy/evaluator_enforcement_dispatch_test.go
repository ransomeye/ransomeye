package policy

import (
	"testing"

	"ransomeye/core/internal/contracts"
)

type stubBlockState struct {
	st contracts.BlockEvalState
}

func (s stubBlockState) GetBlockEvalState() contracts.BlockEvalState {
	return s.st
}

func TestEvaluateEnforcementDispatch_NilProvider(t *testing.T) {
	var ev *PolicyEvaluator
	if r := ev.EvaluateEnforcementDispatch(); r != BlockPipelineDegraded {
		t.Fatalf("nil evaluator: got %v", r)
	}
	ev = NewPolicyEvaluator(nil)
	if r := ev.EvaluateEnforcementDispatch(); r != BlockPipelineDegraded {
		t.Fatalf("nil provider: got %v", r)
	}
}

func TestEvaluateEnforcementDispatch_PipelineUnhealthy(t *testing.T) {
	ev := NewPolicyEvaluator(stubBlockState{st: contracts.BlockEvalState{
		PipelineHealthy: false,
		SINEReady:       true,
	}})
	if r := ev.EvaluateEnforcementDispatch(); r != BlockPipelineDegraded {
		t.Fatalf("got %v want BlockPipelineDegraded", r)
	}
}

func TestEvaluateEnforcementDispatch_SINEConfiguredNotReady(t *testing.T) {
	t.Setenv("RANSOMEYE_SINE_ADDR", "127.0.0.1:50051")
	ev := NewPolicyEvaluator(stubBlockState{st: contracts.BlockEvalState{
		PipelineHealthy: true,
		SINEReady:       false,
	}})
	if r := ev.EvaluateEnforcementDispatch(); r != BlockNoSINE {
		t.Fatalf("got %v want BlockNoSINE", r)
	}
}

func TestEvaluateEnforcementDispatch_SINENotConfigured_IgnoresSINEBit(t *testing.T) {
	t.Setenv("RANSOMEYE_SINE_ADDR", "")
	ev := NewPolicyEvaluator(stubBlockState{st: contracts.BlockEvalState{
		PipelineHealthy: true,
		SINEReady:       false,
	}})
	if r := ev.EvaluateEnforcementDispatch(); r != BlockNone {
		t.Fatalf("got %v want BlockNone", r)
	}
}

func TestEvaluateEnforcementDispatch_IgnoresAIAndDPIComparedToEvaluate(t *testing.T) {
	t.Setenv("RANSOMEYE_DPI_PUBLIC_KEY_PATH", "")
	t.Setenv("RANSOMEYE_DPI_AGENT_ID", "")
	t.Setenv("RANSOMEYE_DPI_TENANT_ID", "")
	t.Setenv("RANSOMEYE_SINE_ADDR", "")
	t.Setenv("RANSOMEYE_AI_ADDR", "127.0.0.1:50052")

	ev := NewPolicyEvaluator(stubBlockState{st: contracts.BlockEvalState{
		PipelineHealthy: true,
		DPIReady:        false,
		SINEReady:       false,
		AIReady:         false,
	}})
	if r := ev.Evaluate(); r != BlockNoAI {
		t.Fatalf("Evaluate() = %v want BlockNoAI", r)
	}
	if r := ev.EvaluateEnforcementDispatch(); r != BlockNone {
		t.Fatalf("EvaluateEnforcementDispatch() = %v want BlockNone (advisory / non-enforcement planes)", r)
	}
}
