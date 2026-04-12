//go:build test_fault_injection

package integrity

import "os"

const (
	anchorHistoryFaultInjectionEnabled = true
	anchorHistoryFaultPointEnv         = "RANSOMEYE_FAULT_POINT"
)

func shouldFail(point string) bool {
	return os.Getenv(anchorHistoryFaultPointEnv) == point
}
