//go:build test_fault_injection

package integrity

import "path/filepath"

const (
	defaultAnchorHistoryPath = "/var/lib/ransomeye/state/anchor.history"
	defaultAnchorHistoryTmp  = "/var/lib/ransomeye/state/anchor.history.tmp"
)

var (
	// AnchorHistoryPath is append-only approved anchor digests with chained hashes (Phase 7.2).
	AnchorHistoryPath = defaultAnchorHistoryPath
	anchorHistoryTmp  = defaultAnchorHistoryTmp
)

func setAnchorHistoryTestPaths(dir string) {
	AnchorHistoryPath = filepath.Join(dir, "anchor.history")
	anchorHistoryTmp = filepath.Join(dir, "anchor.history.tmp")
}

func resetAnchorHistoryTestPaths() {
	AnchorHistoryPath = defaultAnchorHistoryPath
	anchorHistoryTmp = defaultAnchorHistoryTmp
}
