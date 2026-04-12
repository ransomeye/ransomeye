package contracts

// BlockEvalState is the read-only snapshot used by enforcement to decide if dispatch is allowed.
// Provided by health; enforcement depends only on this contract.
type BlockEvalState struct {
	DPIReady        bool
	SINEReady       bool
	AIReady         bool
	PipelineHealthy bool
}

// BlockEvalStateProvider supplies the current system state for block evaluation.
// Implemented by health; injected into enforcement.
type BlockEvalStateProvider interface {
	GetBlockEvalState() BlockEvalState
}

// noOpBlockEvalState is a provider that always returns zero state (dispatch blocked).
type noOpBlockEvalState struct{}

func (noOpBlockEvalState) GetBlockEvalState() BlockEvalState { return BlockEvalState{} }

// NoOpBlockEvalStateProvider returns a provider that always reports non-ready (for fallback wiring).
func NoOpBlockEvalStateProvider() BlockEvalStateProvider { return noOpBlockEvalState{} }
