package soc

import (
	"ransomeye/core/internal/health"
	"ransomeye/core/internal/metrics"
)

const (
	planeUnconfigured  = "unconfigured"
	planeActive        = "active"
	scopeNotApplicable = "not_applicable"
	scopeLive          = "live"
)

func optionalPlaneLabel(configured bool) string {
	if !configured {
		return planeUnconfigured
	}
	return planeActive
}

// ingestionSINEStateLine is the value for JSON field sine_state on ingestion/fleet APIs:
// when the SINE sidecar is not part of this deployment, counters/default metrics must not read as "OK".
func ingestionSINEStateLine() string {
	if !health.SINEPlaneEnvConfigured() {
		return "not_applicable"
	}
	return metrics.SINEState()
}

func dpiMetricsScope() string {
	if !health.DPIPlaneEnvConfigured() {
		return scopeNotApplicable
	}
	return scopeLive
}

func dpiProbeFleetPayload() map[string]any {
	if !health.DPIPlaneEnvConfigured() {
		return map[string]any{
			"plane":              planeUnconfigured,
			"metrics_scope":      scopeNotApplicable,
			"role":               "dpi_probe",
			"packets_total":      nil,
			"packets_dropped":    nil,
			"drop_ratio_ppm":     nil,
			"throttle_mode":      nil,
			"sampling_rate":      nil,
			"control_latency_us": nil,
		}
	}
	return map[string]any{
		"plane":              planeActive,
		"metrics_scope":      scopeLive,
		"role":               "dpi_probe",
		"packets_total":      metrics.DPIPacketsTotal(),
		"packets_dropped":    metrics.DPIPacketsDropped(),
		"drop_ratio_ppm":     metrics.DPIDropRatio(),
		"throttle_mode":      metrics.DPIThrottleMode(),
		"sampling_rate":      metrics.DPISamplingRate(),
		"control_latency_us": metrics.DPIControlLatency(),
	}
}
