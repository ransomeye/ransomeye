// mishka-integrity-state-bootstrap: root-only one-shot — anchor file, monotonic version seed, wipe chain/history for first-run integrity bootstrap.
package main

import (
	"fmt"
	"os"

	"ransomeye/core/internal/integrity"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "must run as root")
		os.Exit(2)
	}
	_ = os.Remove(integrity.VersionChainPath)
	_ = os.Remove(integrity.AnchorHistoryPath)
	_ = os.Remove(integrity.StoredVersionPath)

	a, err := integrity.ComputeMachineAnchor()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := integrity.WriteAnchorFileAtomic(a); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(integrity.StoredVersionPath, []byte("1\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = os.Chown(integrity.StoredVersionPath, 0, 0)
	fmt.Println("OK: anchor + version=1; removed version.chain and anchor.history if present")
}
