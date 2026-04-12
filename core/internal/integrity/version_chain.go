// Phase 6.8–6.9: dual-anchor anti-rollback + machine-bound chain genesis (append-only hash chain).
package integrity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// VersionChainPath append-only log: version:N sha256:<H(n)> where H(n)=SHA256(version_n || H(n-1)).
	// Chain H(0) is the first line of anchor.history (Phase 7.1); unchanged when later rotations append new anchors.
	VersionChainPath = "/var/lib/ransomeye/state/version.chain"
)

func chainStepHash(version uint64, prevHash *[32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(strconv.FormatUint(version, 10)))
	h.Write(prevHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyVersionChain verifies root-of-trust then replays the chain (anchor genesis, strict monotonicity).
func VerifyVersionChain() error {
	anchor, err := VerifyAndLoadAnchor()
	if err != nil {
		return err
	}
	_, _, err = replayVersionChainFromFile(anchor)
	return err
}

func replayVersionChainFromFile(chainGenesis [32]byte) (lastVer uint64, lastHash [32]byte, err error) {
	b, err := os.ReadFile(VersionChainPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, [32]byte{}, fmt.Errorf("integrity: version.chain missing: %s", VersionChainPath)
		}
		return 0, [32]byte{}, fmt.Errorf("integrity: version.chain: %w", err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return 0, [32]byte{}, fmt.Errorf("integrity: version.chain empty")
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	lineNum := 0
	prev := chainGenesis
	var maxVer uint64
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		v, gotHash, perr := parseChainLine(line)
		if perr != nil {
			return 0, [32]byte{}, fmt.Errorf("integrity: version.chain line %d: %w", lineNum, perr)
		}
		if v <= maxVer {
			return 0, [32]byte{}, fmt.Errorf("integrity: version.chain line %d: version %d must exceed prior %d", lineNum, v, maxVer)
		}
		want := chainStepHash(v, &prev)
		if !bytes.Equal(gotHash[:], want[:]) {
			return 0, [32]byte{}, fmt.Errorf("integrity: version.chain line %d: hash mismatch (tamper or truncate)", lineNum)
		}
		prev = want
		maxVer = v
	}
	if err := sc.Err(); err != nil {
		return 0, [32]byte{}, err
	}
	if maxVer == 0 {
		return 0, [32]byte{}, fmt.Errorf("integrity: version.chain has no entries")
	}
	return maxVer, prev, nil
}

func parseChainLine(line string) (v uint64, digest [32]byte, err error) {
	// format: version:N sha256:<64 hex> (no timestamps)
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return 0, [32]byte{}, fmt.Errorf("want \"version:N sha256:<hex>\"")
	}
	vp := strings.TrimSpace(fields[0])
	sp := strings.TrimSpace(fields[1])
	if !strings.HasPrefix(strings.ToLower(vp), "version:") {
		return 0, [32]byte{}, fmt.Errorf("missing version: prefix")
	}
	numStr := strings.TrimSpace(vp[len("version:"):])
	if numStr == "" {
		return 0, [32]byte{}, fmt.Errorf("version number empty")
	}
	v, err = strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("version: %w", err)
	}
	if !strings.HasPrefix(strings.ToLower(sp), "sha256:") {
		return 0, [32]byte{}, fmt.Errorf("missing sha256: prefix")
	}
	hexStr := strings.ToLower(strings.TrimSpace(sp[len("sha256:"):]))
	if len(hexStr) != 64 {
		return 0, [32]byte{}, fmt.Errorf("sha256 want 64 hex chars")
	}
	dec, err := hex.DecodeString(hexStr)
	if err != nil || len(dec) != 32 {
		return 0, [32]byte{}, fmt.Errorf("sha256 hex: %w", err)
	}
	copy(digest[:], dec)
	return v, digest, nil
}

// crossCheckAnchors ensures fast-path version file matches chain tip (detects version-file-only tamper or truncated chain).
func crossCheckAnchors(chainVer uint64) error {
	fileVer, err := readStoredVersion()
	if err != nil {
		return err
	}
	if fileVer != chainVer {
		return fmt.Errorf("integrity: version file vs chain mismatch (chain=%d file=%d): possible tamper or truncate", chainVer, fileVer)
	}
	return nil
}

// bootstrapVersionChainIfMissing builds version.chain from anchor genesis through readStoredVersion() when the file is absent.
func bootstrapVersionChainIfMissing(chainGenesis [32]byte) error {
	_, statErr := os.Stat(VersionChainPath)
	if statErr == nil {
		return nil
	}
	if !os.IsNotExist(statErr) {
		return fmt.Errorf("integrity: version.chain stat: %w", statErr)
	}
	V, err := readStoredVersion()
	if err != nil {
		return err
	}
	if V == 0 {
		return fmt.Errorf("integrity: cannot bootstrap version.chain from version 0")
	}
	dir := filepath.Dir(VersionChainPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("integrity state dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)
	f, err := os.OpenFile(VersionChainPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("integrity: version.chain create: %w", err)
	}
	defer f.Close()
	prev := chainGenesis
	for i := uint64(1); i <= V; i++ {
		hi := chainStepHash(i, &prev)
		line := fmt.Sprintf("version:%d sha256:%s\n", i, hex.EncodeToString(hi[:]))
		if _, err := f.WriteString(line); err != nil {
			return fmt.Errorf("integrity: version.chain bootstrap: %w", err)
		}
		prev = hi
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("integrity: version.chain sync: %w", err)
	}
	_ = os.Chmod(VersionChainPath, 0o600)
	_ = os.Chown(VersionChainPath, 0, 0)
	return nil
}

func appendVersionChainEntry(version uint64, newHash [32]byte) error {
	line := fmt.Sprintf("version:%d sha256:%s\n", version, hex.EncodeToString(newHash[:]))
	f, err := os.OpenFile(VersionChainPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("integrity: version.chain append open: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("integrity: version.chain append: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("integrity: version.chain append sync: %w", err)
	}
	_ = os.Chmod(VersionChainPath, 0o600)
	_ = os.Chown(VersionChainPath, 0, 0)
	return nil
}

// prepareDualAnchorBeforeManifest verifies (or bootstraps) chain, cross-checks file vs chain, and rejects manifest rollback vs chain tip.
func prepareDualAnchorBeforeManifest(manifestVersion uint64) (chainTipVer uint64, chainTipHash [32]byte, err error) {
	anchor, err := VerifyAndLoadAnchor()
	if err != nil {
		return 0, [32]byte{}, err
	}
	if _, err := readStoredVersion(); err != nil {
		return 0, [32]byte{}, err
	}
	if err := bootstrapVersionChainIfMissing(anchor); err != nil {
		return 0, [32]byte{}, err
	}
	chainTipVer, chainTipHash, err = replayVersionChainFromFile(anchor)
	if err != nil {
		return 0, [32]byte{}, err
	}
	if err := crossCheckAnchors(chainTipVer); err != nil {
		return 0, [32]byte{}, err
	}
	if manifestVersion < chainTipVer {
		return 0, [32]byte{}, fmt.Errorf("rollback vs chain: manifest version %d < chain tip %d", manifestVersion, chainTipVer)
	}
	if err := enforceAntiRollback(manifestVersion); err != nil {
		return 0, [32]byte{}, err
	}
	return chainTipVer, chainTipHash, nil
}

func commitDualAnchorAfterSuccess(manifestVersion, chainTipVer uint64, chainTipHash [32]byte) error {
	if manifestVersion <= chainTipVer {
		return writeStoredVersionAtomic(manifestVersion)
	}
	nextHash := chainStepHash(manifestVersion, &chainTipHash)
	if err := appendVersionChainEntry(manifestVersion, nextHash); err != nil {
		return err
	}
	return writeStoredVersionAtomic(manifestVersion)
}
