// Phase 6.7: anti-rollback via monotonic signed manifest version (uint64 header).
package integrity

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// StoredVersionPath persistent monotonic counter (outside /etc; survives reboot).
	StoredVersionPath = "/var/lib/ransomeye/state/version"
	storedVersionTmp  = "/var/lib/ransomeye/state/version.tmp"
)

// parseManifestVersionFirstLine requires the first line of the manifest (before any newline) to be "version: <uint64>" (case-insensitive key), part of the signed blob.
func parseManifestVersionFirstLine(manifestBytes []byte) (uint64, error) {
	if len(manifestBytes) == 0 {
		return 0, fmt.Errorf("integrity.manifest: empty")
	}
	idx := bytes.IndexByte(manifestBytes, '\n')
	var first []byte
	if idx < 0 {
		first = bytes.TrimSpace(manifestBytes)
	} else {
		first = bytes.TrimSpace(manifestBytes[:idx])
	}
	if len(first) == 0 {
		return 0, fmt.Errorf("integrity.manifest: first line must be version header")
	}
	line := string(first)
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return 0, fmt.Errorf("integrity.manifest: first line must be version header")
	}
	key := strings.TrimSpace(strings.ToLower(line[:colon]))
	if key != "version" {
		return 0, fmt.Errorf("integrity.manifest: first line must be version header")
	}
	numStr := strings.TrimSpace(line[colon+1:])
	if numStr == "" {
		return 0, fmt.Errorf("integrity.manifest: version value empty")
	}
	v, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("integrity.manifest: version: %w", err)
	}
	return v, nil
}

func readStoredVersion() (uint64, error) {
	b, err := os.ReadFile(StoredVersionPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("integrity state missing: %s", StoredVersionPath)
		}
		return 0, fmt.Errorf("integrity violation: %s", StoredVersionPath)
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

func enforceAntiRollback(manifestVersion uint64) error {
	stored, err := readStoredVersion()
	if err != nil {
		return err
	}
	if manifestVersion < stored {
		return fmt.Errorf("rollback detected: manifest version %d < stored %d", manifestVersion, stored)
	}
	return nil
}

// writeStoredVersionAtomic crash-safe publish (tmp → rename); final file root:root 0600 (Phase 6.7).
func writeStoredVersionAtomic(v uint64) error {
	dir := filepath.Dir(StoredVersionPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("integrity state dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)
	payload := strconv.FormatUint(v, 10) + "\n"
	if err := os.WriteFile(storedVersionTmp, []byte(payload), 0o600); err != nil {
		return fmt.Errorf("integrity state tmp: %w", err)
	}
	if err := os.Rename(storedVersionTmp, StoredVersionPath); err != nil {
		return fmt.Errorf("integrity state rename: %w", err)
	}
	_ = os.Chown(StoredVersionPath, 0, 0)
	_ = os.Chmod(StoredVersionPath, 0o600)
	return nil
}

// lineIsManifestVersionHeader reports whether the line is the signed version header (skip in hash loop).
func lineIsManifestVersionHeader(trimmed string) bool {
	colon := strings.IndexByte(trimmed, ':')
	if colon < 0 {
		return false
	}
	return strings.TrimSpace(strings.ToLower(trimmed[:colon])) == "version"
}
