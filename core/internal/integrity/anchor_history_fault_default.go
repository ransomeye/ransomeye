//go:build !test_fault_injection

package integrity

const anchorHistoryFaultInjectionEnabled = false

func shouldFail(string) bool {
	return false
}
