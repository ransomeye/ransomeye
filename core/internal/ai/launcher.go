// PRD-02 / PRD-10 / PRD-14 / PRD-15 / PRD-18: optional AI sidecar vendor verification (no subprocess control from Core).

package ai

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const DefaultAIInstallRoot = "/opt/ransomeye/ai-sidecar"

// VerifyBeforeStart fail-closed gate for Core startup (no process control).
func VerifyBeforeStart() error {
	root := resolveAIInstallRoot()
	if err := verifyVendorIntegrity(root); err != nil {
		return err
	}
	return VerifyModelArtifacts(root)
}

// VerifyVendorIntegrity validates vendor.sha256 against files under root.
func VerifyVendorIntegrity(root string) error {
	return verifyVendorIntegrity(root)
}

// VerifyBeforeStartWithHashCache full read + SHA256 per vendor file; skip hex compare vs manifest only when digest matches cached [32]byte. seen records paths verified this pass (for cache pruning). Single-goroutine runtime use only.
func VerifyBeforeStartWithHashCache(hashCache map[string][32]byte, seen map[string]bool) error {
	// Mishka Phase-1 default slice: Core runs without an AI gRPC sidecar. Skip vendor/model
	// verification in the periodic runtime gate unless operators set RANSOMEYE_AI_ADDR.
	if strings.TrimSpace(os.Getenv("RANSOMEYE_AI_ADDR")) == "" {
		return nil
	}
	root := resolveAIInstallRoot()
	if err := verifyVendorIntegrityWithHashCache(root, hashCache, seen); err != nil {
		return err
	}
	return VerifyModelArtifacts(root)
}

func verifyVendorIntegrity(root string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("ai root: %w", err)
	}
	rootAbs = filepath.Clean(rootAbs)

	manifestPath := filepath.Join(rootAbs, "vendor.sha256")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("vendor.sha256: %w", err)
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		expectedHex, rel, err := parseManifestLine(line)
		if err != nil {
			return fmt.Errorf("vendor.sha256 line %d: %w", lineNum, err)
		}
		if strings.HasPrefix(rel, "*") {
			rel = strings.TrimSpace(strings.TrimPrefix(rel, "*"))
		}
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("vendor.sha256 line %d: illegal path %q", lineNum, rel)
		}

		full := filepath.Clean(filepath.Join(rootAbs, rel))
		relToRoot, err := filepath.Rel(rootAbs, full)
		if err != nil || relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
			return fmt.Errorf("vendor.sha256 line %d: path escapes root %q", lineNum, rel)
		}

		b, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("vendor file %q: %w", rel, err)
		}
		sum := sha256.Sum256(b)
		actual := hex.EncodeToString(sum[:])
		if actual != expectedHex {
			return fmt.Errorf("integrity mismatch: %s", rel)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

func verifyVendorIntegrityWithHashCache(root string, hashCache map[string][32]byte, seen map[string]bool) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("ai root: %w", err)
	}
	rootAbs = filepath.Clean(rootAbs)

	manifestPath := filepath.Join(rootAbs, "vendor.sha256")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("vendor.sha256: %w", err)
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		expectedHex, rel, err := parseManifestLine(line)
		if err != nil {
			return fmt.Errorf("vendor.sha256 line %d: %w", lineNum, err)
		}
		if strings.HasPrefix(rel, "*") {
			rel = strings.TrimSpace(strings.TrimPrefix(rel, "*"))
		}
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("vendor.sha256 line %d: illegal path %q", lineNum, rel)
		}

		full := filepath.Clean(filepath.Join(rootAbs, rel))
		relToRoot, err := filepath.Rel(rootAbs, full)
		if err != nil || relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
			return fmt.Errorf("vendor.sha256 line %d: path escapes root %q", lineNum, rel)
		}

		b, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("integrity violation: %s", full)
		}
		sum := sha256.Sum256(b)

		if hashCache != nil {
			prev, ok := hashCache[full]
			if ok && prev == sum {
				if seen != nil {
					seen[full] = true
				}
				continue
			}
		}

		actual := hex.EncodeToString(sum[:])
		if actual != expectedHex {
			return fmt.Errorf("integrity violation: %s", full)
		}
		if hashCache != nil {
			hashCache[full] = sum
			if seen != nil {
				seen[full] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

func parseManifestLine(line string) (digestHex, relPath string, err error) {
	if idx := strings.Index(line, "  "); idx >= 0 {
		return strings.ToLower(strings.TrimSpace(line[:idx])), strings.TrimSpace(line[idx+2:]), nil
	}
	if idx := strings.Index(line, " *"); idx >= 0 {
		return strings.ToLower(strings.TrimSpace(line[:idx])), strings.TrimSpace(line[idx+2:]), nil
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", fmt.Errorf("malformed line %q", line)
	}
	return strings.ToLower(fields[0]), strings.Join(fields[1:], " "), nil
}
