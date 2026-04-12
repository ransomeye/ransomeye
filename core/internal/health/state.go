package health

import (
	"sync/atomic"

	"ransomeye/core/internal/contracts"
)

type SystemState struct {
	DPIReady        bool
	SINEReady       bool
	AIReady         bool
	PipelineHealthy bool
}

func (s *SystemState) IsOperational() bool {
	if s == nil {
		return false
	}
	// Mishka: optional retired planes must not mark the core slice non-operational when unset.
	// Operational means the ingest/processing pipeline is healthy; plane bits are exposed separately for observability.
	return s.PipelineHealthy
}

var globalState atomic.Pointer[SystemState]

// complianceBootstrapOK is set only after production runtime compliance gates complete in main (DEV MODE never sets it).
var complianceBootstrapOK atomic.Bool

// MarkComplianceBootstrapOK records that fail-closed startup gates (integrity loop, TLS/outbound where required) finished.
func MarkComplianceBootstrapOK() {
	complianceBootstrapOK.Store(true)
}

// ComplianceBootstrapOK is true only on paths that ran the full production bootstrap (not DEV MODE shortcuts).
func ComplianceBootstrapOK() bool {
	return complianceBootstrapOK.Load()
}

// SliceTelemetryOK is true when DB and pipeline are healthy and production bootstrap (integrity loop, etc.) completed.
// Used by SOC HTTP handlers so /health, /system/health, ingestion, and shadow agree on degraded vs ok.
func SliceTelemetryOK(dbOK, pipelineOK bool) bool {
	return dbOK && pipelineOK && ComplianceBootstrapOK()
}

func GetSystemState() *SystemState {
	s := globalState.Load()
	if s == nil {
		return &SystemState{}
	}
	return s
}

func SetSystemState(s *SystemState) {
	globalState.Store(s)
}

func UpdateSystemState(mutator func(s *SystemState)) {
	for {
		old := globalState.Load()

		var base SystemState
		if old != nil {
			base = *old
		}

		// apply mutation on copy
		mutator(&base)

		// attempt atomic swap
		if globalState.CompareAndSwap(old, &base) {
			return
		}
	}
}

// blockEvalStateProvider implements contracts.BlockEvalStateProvider from health state.
type blockEvalStateProvider struct{}

func (blockEvalStateProvider) GetBlockEvalState() contracts.BlockEvalState {
	s := GetSystemState()
	if s == nil {
		return contracts.BlockEvalState{}
	}
	return contracts.BlockEvalState{
		DPIReady:        s.DPIReady,
		SINEReady:       s.SINEReady,
		AIReady:         s.AIReady,
		PipelineHealthy: s.PipelineHealthy,
	}
}

// BlockEvalStateProvider returns a provider for enforcement to use (dependency inversion).
func BlockEvalStateProvider() contracts.BlockEvalStateProvider {
	return blockEvalStateProvider{}
}

func MarkSystemDegraded(reason string) {
	UpdateSystemState(func(s *SystemState) {
		s.PipelineHealthy = false
		if reason == "SINE_DOWN" {
			s.SINEReady = false
		}
	})
}

func MarkSINEHealthy() {
	UpdateSystemState(func(s *SystemState) {
		s.SINEReady = true
	})
}

func MarkAIHealthy() {
	UpdateSystemState(func(s *SystemState) {
		s.AIReady = true
	})
}
