package enforcement

const (
	ActionLogOnly   = "LOG_ONLY"
	ActionAlertOnly = "ALERT_ONLY"
	ActionKillProc  = "KILL_PROCESS"
	ActionIsolate   = "ISOLATE_HOST"
)

// EvaluateEnforcementDecision maps AEC class + tenant config to an action string.
//
// Rules:
// - AEC-0 always LOG_ONLY
// - If auto-enforce disabled: AEC-1/2/3 -> ALERT_ONLY
// - If auto-enforce enabled: AEC-2 -> KILL_PROCESS, AEC-3 -> ISOLATE_HOST
func EvaluateEnforcementDecision(aecClass string, tenantConfigAec bool) string {
	switch aecClass {
	case "AEC-0":
		return ActionLogOnly
	case "AEC-1":
		if !IsAutoEnforceEnabled(tenantConfigAec) {
			return ActionAlertOnly
		}
		return ActionAlertOnly
	case "AEC-2":
		if !IsAutoEnforceEnabled(tenantConfigAec) {
			return ActionAlertOnly
		}
		return ActionKillProc
	case "AEC-3":
		if !IsAutoEnforceEnabled(tenantConfigAec) {
			return ActionAlertOnly
		}
		return ActionIsolate
	default:
		// Fail-safe: unknown classification cannot trigger enforcement.
		return ActionAlertOnly
	}
}

