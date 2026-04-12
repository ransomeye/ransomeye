// Package integrity: Ed25519-signed binary manifest (Phase 6.3 / PRD-18).
package integrity

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const (
	DefaultManifestPath = "/etc/ransomeye/integrity.manifest"
	DefaultSigPath      = "/etc/ransomeye/integrity.sig"
	DefaultWormPubPath  = "/etc/ransomeye/worm_signing.pub"
)

// VerifySignedManifest Ed25519-verifies manifest bytes, then SHA256-checks every listed file (fail-closed).
func VerifySignedManifest(manifestPath, sigPath, wormPubPath string) error {
	return verifySignedManifestWithHashCache(manifestPath, sigPath, wormPubPath, nil, nil)
}

// verifySignedManifestWithHashCache optional hashCache: full read + SHA256 every path; skip manifest hex compare only when digest matches last verified [32]byte. seen must be non-nil when hashCache is non-nil (paths touched this pass; used to bound cache size).
func verifySignedManifestWithHashCache(manifestPath, sigPath, wormPubPath string, hashCache map[string][32]byte, seen map[string]bool) error {
	if manifestPath == "" {
		manifestPath = DefaultManifestPath
	}
	if sigPath == "" {
		sigPath = DefaultSigPath
	}
	if wormPubPath == "" {
		wormPubPath = DefaultWormPubPath
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("integrity violation: %s", manifestPath)
	}
	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("integrity violation: %s", sigPath)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("integrity violation: %s", sigPath)
	}
	pubBytes, err := os.ReadFile(wormPubPath)
	if err != nil {
		return fmt.Errorf("integrity violation: %s", wormPubPath)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("integrity violation: %s", wormPubPath)
	}

	if !ed25519.Verify(pubBytes, manifestBytes, sigBytes) {
		return fmt.Errorf("integrity violation: %s", manifestPath)
	}

	manifestVersion, err := parseManifestVersionFirstLine(manifestBytes)
	if err != nil {
		return err
	}
	chainTipVer, chainTipHash, err := prepareDualAnchorBeforeManifest(manifestVersion)
	if err != nil {
		return err
	}

	sc := bufio.NewScanner(bytes.NewReader(manifestBytes))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	found := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if lineIsManifestVersionHeader(line) {
			continue
		}
		path, wantHex, err := parseManifestLine(line)
		if err != nil {
			return fmt.Errorf("integrity.manifest line %d: %w", lineNum, err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("integrity violation: %s", path)
		}
		sum := sha256.Sum256(data)

		if hashCache != nil {
			prev, ok := hashCache[path]
			if ok && prev == sum {
				if seen != nil {
					seen[path] = true
				}
				found++
				continue
			}
		}

		actual := hex.EncodeToString(sum[:])
		if actual != wantHex {
			return fmt.Errorf("integrity violation: %s", path)
		}
		if hashCache != nil {
			hashCache[path] = sum
			if seen != nil {
				seen[path] = true
			}
		}
		found++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if found == 0 {
		return fmt.Errorf("integrity.manifest: no entries")
	}
	if err := commitDualAnchorAfterSuccess(manifestVersion, chainTipVer, chainTipHash); err != nil {
		return err
	}
	return nil
}

func parseManifestLine(line string) (path string, digestHex string, err error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(line, prefix) {
		return "", "", fmt.Errorf("line must start with %q", prefix)
	}
	rest := strings.TrimPrefix(line, prefix)
	i := 0
	for i < len(rest) {
		c := rest[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			break
		}
		i++
	}
	if i != 64 {
		return "", "", fmt.Errorf("want 64 hex chars, got %d", i)
	}
	hexPart := strings.ToLower(rest[:i])
	pathPart := strings.TrimSpace(rest[i:])
	if pathPart == "" || !strings.HasPrefix(pathPart, "/") {
		return "", "", fmt.Errorf("missing absolute path")
	}
	return pathPart, hexPart, nil
}
