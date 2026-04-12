//go:build !test_fault_injection

package integrity

const (
	// AnchorHistoryPath is append-only approved anchor digests with chained hashes (Phase 7.2).
	AnchorHistoryPath = "/var/lib/ransomeye/state/anchor.history"
	anchorHistoryTmp  = "/var/lib/ransomeye/state/anchor.history.tmp"
)
