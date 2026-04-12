package health

import (
	"strings"
	"sync/atomic"
)

// Air-gap posture labels (PRD-19 / observability). Physical offline validation is a separate operator step.
const (
	AirGapDisabled                  = "disabled"
	AirGapConfiguredNotValidated    = "configured_not_validated"
	AirGapValidated                 = "validated"
	AirGapBypassedForLab            = "bypassed_for_lab"
)

var (
	airGapPosture atomic.Value // string
	airGapDetail  atomic.Value // string
)

func init() {
	airGapPosture.Store(AirGapDisabled)
	airGapDetail.Store("")
}

// SetAirGapRuntimeState records the outcome of startup air-gap evaluation (main / bootstrap only).
func SetAirGapRuntimeState(posture, detail string) {
	p := strings.TrimSpace(posture)
	if p == "" {
		p = AirGapDisabled
	}
	airGapPosture.Store(p)
	airGapDetail.Store(strings.TrimSpace(detail))
}

// AirGapPosture returns the last recorded posture (default disabled before main sets it).
func AirGapPosture() string {
	v := airGapPosture.Load()
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return AirGapDisabled
}

// AirGapDetail returns a short non-sensitive reason (e.g. compliance error text) when posture is not validated.
func AirGapDetail() string {
	v := airGapDetail.Load()
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// AirGapDegradesHealth is true when the node is not in a production air-gap validated posture.
// "disabled" means air-gap enforcement is not requested — it does not degrade health.
func AirGapDegradesHealth() bool {
	switch AirGapPosture() {
	case AirGapBypassedForLab, AirGapConfiguredNotValidated:
		return true
	default:
		return false
	}
}
