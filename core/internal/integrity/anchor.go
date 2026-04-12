// Phase 6.9: root-of-trust bound to machine identity (/etc/machine-id).
package integrity

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// MachineIDPath is the systemd/host machine identifier (trimmed, no timestamps).
	MachineIDPath = "/etc/machine-id"
	// AnchorFilePath stores SHA256(anchor_preimage_utf8 || 0³²) as raw 32 bytes (0400); preimage Phase 7.0 multi-source.
	AnchorFilePath = "/var/lib/ransomeye/state/anchor"
	anchorFileTmp  = "/var/lib/ransomeye/state/anchor.tmp"
)

var zeroGenesis [32]byte

// ComputeMachineAnchor returns anchor = SHA256( normalized machine-id + "\n" + cpu-id + "\n" + rootfs-uuid || 32 zero bytes ).
// All sources are mandatory (Phase 7.0); see anchor_sources.go.
func ComputeMachineAnchor() ([32]byte, error) {
	pre, err := anchorPreimage()
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte(pre))
	h.Write(zeroGenesis[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func readAnchorFileRaw() ([32]byte, error) {
	b, err := os.ReadFile(AnchorFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return [32]byte{}, fmt.Errorf("integrity: anchor file missing: %s", AnchorFilePath)
		}
		return [32]byte{}, fmt.Errorf("integrity: anchor file: %w", err)
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("integrity: anchor file want 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// WriteAnchorFileAtomic publishes the anchor (installer / provisioning only); final path is root:root 0400.
func WriteAnchorFileAtomic(anchor [32]byte) error {
	dir := filepath.Dir(AnchorFilePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("integrity state dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)
	if err := os.WriteFile(anchorFileTmp, anchor[:], 0o400); err != nil {
		return fmt.Errorf("integrity anchor tmp: %w", err)
	}
	if err := os.Rename(anchorFileTmp, AnchorFilePath); err != nil {
		return fmt.Errorf("integrity anchor rename: %w", err)
	}
	_ = os.Chown(AnchorFilePath, 0, 0)
	_ = os.Chmod(AnchorFilePath, 0o400)
	return nil
}
