package enforcement

// Human Supremacy (P0): compile-time default must be false.
const AEC_AUTO_ENFORCE_DEFAULT = false

// IsAutoEnforceEnabled returns true only if BOTH:
// - the compile-time default allows it, and
// - the tenant configuration explicitly enables it.
func IsAutoEnforceEnabled(tenantConfigAec bool) bool {
	return AEC_AUTO_ENFORCE_DEFAULT && tenantConfigAec
}

