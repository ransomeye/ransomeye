// Phase 7.1–7.2: append-only anchor.history — membership + tamper-evident hash chain per line.
package integrity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var anchorHistoryGenesis [32]byte

func anchorHistoryLineHash(prevChainHash, anchorDigest [32]byte) [32]byte {
	h := sha256.New()
	h.Write(anchorDigest[:])
	h.Write(prevChainHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyRootAnchor fails closed if the current host anchor is not listed in anchor.history or chain is invalid.
func VerifyRootAnchor() error {
	_, err := VerifyAndLoadAnchor()
	return err
}

// VerifyAndLoadAnchor runs legacy→chained migration if needed, verifies the history hash chain, checks membership
// of the live anchor, returns the chain-genesis anchor (first line’s anchor digest for version.chain).
func VerifyAndLoadAnchor() ([32]byte, error) {
	discardStaleAnchorHistoryTmp()
	current, err := ComputeMachineAnchor()
	if err != nil {
		return [32]byte{}, err
	}
	if err := migrateOrEnsureAnchorHistory(current); err != nil {
		return [32]byte{}, err
	}
	if err := migrateLegacyAnchorHistoryIfNeeded(); err != nil {
		return [32]byte{}, err
	}
	entries, err := parseAnchorHistoryEntries()
	if err != nil {
		return [32]byte{}, err
	}
	if len(entries) == 0 {
		return [32]byte{}, fmt.Errorf("integrity: anchor.history has no entries")
	}
	if !anchorHistoryContains(entries, current) {
		return [32]byte{}, fmt.Errorf("root-of-trust violation: current anchor not in anchor.history (use ApproveNewAnchor or installer --reprovision-anchor)")
	}
	return entries[0], nil
}

func anchorHistoryContains(entries [][32]byte, want [32]byte) bool {
	for _, e := range entries {
		if bytes.Equal(e[:], want[:]) {
			return true
		}
	}
	return false
}

func parseAnchorHistoryEntries() ([][32]byte, error) {
	if err := migrateLegacyAnchorHistoryIfNeeded(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(AnchorHistoryPath)
	if err != nil {
		return nil, fmt.Errorf("integrity: anchor.history: %w", err)
	}
	anchors, _, err := verifyChainedHistoryBytes(b)
	if err != nil {
		return nil, err
	}
	return anchors, nil
}

// verifyChainedHistoryBytes replays H(n) = SHA256(anchor_n || H(n-1)) with H(0)=0³²; returns anchors and final chain hash.
func verifyChainedHistoryBytes(content []byte) ([][32]byte, [32]byte, error) {
	var anchors [][32]byte
	prev := anchorHistoryGenesis
	lineNum := 0
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		an, recHash, err := parseChainedHistoryLine(line, lineNum)
		if err != nil {
			return nil, [32]byte{}, err
		}
		want := anchorHistoryLineHash(prev, an)
		if !bytes.Equal(want[:], recHash[:]) {
			return nil, [32]byte{}, fmt.Errorf("integrity: anchor.history line %d: chain hash mismatch (tamper, truncate, or reorder)", lineNum)
		}
		anchors = append(anchors, an)
		prev = want
	}
	if err := sc.Err(); err != nil {
		return nil, [32]byte{}, err
	}
	if len(anchors) == 0 {
		return nil, [32]byte{}, fmt.Errorf("integrity: anchor.history has no entries")
	}
	return anchors, prev, nil
}

func parseChainedHistoryLine(line string, lineNum int) (anchor [32]byte, lineHash [32]byte, err error) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToLower(t), "anchor:") {
		return [32]byte{}, [32]byte{}, fmt.Errorf("line %d: want anchor: prefix", lineNum)
	}
	rest := strings.TrimSpace(t[len("anchor:"):])
	// rest is "<64hex> hash:<64hex>"
	i := strings.Index(strings.ToLower(rest), "hash:")
	if i < 0 {
		return [32]byte{}, [32]byte{}, fmt.Errorf("line %d: want anchor:<hex> hash:<hex>", lineNum)
	}
	aHex := strings.TrimSpace(rest[:i])
	hPart := strings.TrimSpace(rest[i:])
	if !strings.HasPrefix(strings.ToLower(hPart), "hash:") {
		return [32]byte{}, [32]byte{}, fmt.Errorf("line %d: bad hash field", lineNum)
	}
	hHex := strings.TrimSpace(hPart[len("hash:"):])
	if len(aHex) != 64 || len(hHex) != 64 {
		return [32]byte{}, [32]byte{}, fmt.Errorf("line %d: want 64-char hex digests", lineNum)
	}
	ad, err := hex.DecodeString(strings.ToLower(aHex))
	if err != nil || len(ad) != 32 {
		return [32]byte{}, [32]byte{}, fmt.Errorf("line %d: bad anchor hex", lineNum)
	}
	hd, err := hex.DecodeString(strings.ToLower(hHex))
	if err != nil || len(hd) != 32 {
		return [32]byte{}, [32]byte{}, fmt.Errorf("line %d: bad hash hex", lineNum)
	}
	copy(anchor[:], ad)
	copy(lineHash[:], hd)
	return anchor, lineHash, nil
}

func isLegacyAnchorHistoryFormat(content []byte) bool {
	hasLine := false
	for _, line := range strings.Split(string(content), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		hasLine = true
		if strings.Contains(strings.ToLower(t), "hash:") {
			return false
		}
	}
	return hasLine
}

func parseLegacyAnchorHistoryAnchors(content []byte) ([][32]byte, error) {
	var out [][32]byte
	lineNum := 0
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw := strings.TrimPrefix(strings.ToLower(line), "anchor:")
		raw = strings.TrimSpace(raw)
		if len(raw) != 64 {
			return nil, fmt.Errorf("integrity: legacy anchor.history line %d: want 64 hex chars", lineNum)
		}
		dec, err := hex.DecodeString(raw)
		if err != nil || len(dec) != 32 {
			return nil, fmt.Errorf("integrity: legacy line %d: bad hex", lineNum)
		}
		var d [32]byte
		copy(d[:], dec)
		out = append(out, d)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("integrity: legacy anchor.history empty")
	}
	return out, nil
}

func discardStaleAnchorHistoryTmp() {
	_ = os.Remove(anchorHistoryTmp)
}

func syncParentDirOf(path string) error {
	dir := filepath.Dir(path)
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer df.Close()
	return df.Sync()
}

// atomicWriteVerifiedAnchorHistory writes chained content via tmp → fsync → rename → fsync(parent) (Phase 7.2.1).
func atomicWriteVerifiedAnchorHistory(content []byte) error {
	discardStaleAnchorHistoryTmp()
	tf, err := os.OpenFile(anchorHistoryTmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("integrity: anchor.history tmp: %w", err)
	}
	if _, err := tf.Write(content); err != nil {
		tf.Close()
		_ = os.Remove(anchorHistoryTmp)
		return fmt.Errorf("integrity: anchor.history tmp write: %w", err)
	}
	if anchorHistoryFaultInjectionEnabled && shouldFail("after_write_tmp") {
		panic("simulated crash")
	}
	if err := tf.Sync(); err != nil {
		tf.Close()
		_ = os.Remove(anchorHistoryTmp)
		return fmt.Errorf("integrity: anchor.history tmp sync: %w", err)
	}
	if anchorHistoryFaultInjectionEnabled && shouldFail("after_fsync") {
		panic("simulated crash")
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(anchorHistoryTmp)
		return err
	}
	_ = os.Chown(anchorHistoryTmp, 0, 0)
	_ = os.Chmod(anchorHistoryTmp, 0o600)
	if _, _, err := verifyChainedHistoryBytes(content); err != nil {
		_ = os.Remove(anchorHistoryTmp)
		return fmt.Errorf("integrity: anchor.history pre-rename verify: %w", err)
	}
	if anchorHistoryFaultInjectionEnabled && shouldFail("before_rename") {
		panic("simulated crash")
	}
	if err := os.Rename(anchorHistoryTmp, AnchorHistoryPath); err != nil {
		return fmt.Errorf("integrity: anchor.history rename: %w", err)
	}
	if anchorHistoryFaultInjectionEnabled && shouldFail("after_rename_before_fsync_dir") {
		panic("simulated crash")
	}
	if err := syncParentDirOf(AnchorHistoryPath); err != nil {
		return fmt.Errorf("integrity: anchor.history parent sync: %w", err)
	}
	final, err := os.ReadFile(AnchorHistoryPath)
	if err != nil {
		return fmt.Errorf("integrity: anchor.history read after rename: %w", err)
	}
	if _, _, err := verifyChainedHistoryBytes(final); err != nil {
		return fmt.Errorf("integrity: migration corruption: %w", err)
	}
	_ = os.Chown(AnchorHistoryPath, 0, 0)
	_ = os.Chmod(AnchorHistoryPath, 0o600)
	return nil
}

func rewriteAnchorHistoryChained(anchors [][32]byte) error {
	if len(anchors) == 0 {
		return fmt.Errorf("integrity: anchor.history migration: no anchors")
	}
	prev := anchorHistoryGenesis
	var sb strings.Builder
	for _, a := range anchors {
		h := anchorHistoryLineHash(prev, a)
		sb.WriteString(fmt.Sprintf("anchor:%s hash:%s\n", hex.EncodeToString(a[:]), hex.EncodeToString(h[:])))
		prev = h
	}
	content := []byte(sb.String())
	if err := atomicWriteVerifiedAnchorHistory(content); err != nil {
		return err
	}
	log.Printf("[AUDIT] anchor.history migrated to Phase 7.2 chained format (%d entries)", len(anchors))
	return nil
}

func migrateLegacyAnchorHistoryIfNeeded() error {
	discardStaleAnchorHistoryTmp()
	b, err := os.ReadFile(AnchorHistoryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return fmt.Errorf("integrity: anchor.history empty")
	}
	if !isLegacyAnchorHistoryFormat(b) {
		return nil
	}
	anchors, err := parseLegacyAnchorHistoryAnchors(b)
	if err != nil {
		return err
	}
	return rewriteAnchorHistoryChained(anchors)
}

// migrateOrEnsureAnchorHistory creates anchor.history from the legacy 0400 anchor file when the live anchor matches it.
func migrateOrEnsureAnchorHistory(current [32]byte) error {
	fi, err := os.Stat(AnchorHistoryPath)
	if err == nil && fi.Size() > 0 {
		return nil
	}
	if err == nil && fi.Size() == 0 {
		return fmt.Errorf("integrity: anchor.history empty")
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("integrity: anchor.history: %w", err)
	}
	if _, err := os.Stat(AnchorFilePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("integrity: anchor.history missing (initial provisioning required)")
		}
		return err
	}
	leg, err := readAnchorFileRaw()
	if err != nil {
		return err
	}
	if !bytes.Equal(current[:], leg[:]) {
		return fmt.Errorf("root-of-trust violation: anchor.history missing and legacy anchor mismatch (rotation not recorded)")
	}
	return writeAnchorHistoryFirstLine(current)
}

func writeAnchorHistoryFirstLine(anchor [32]byte) error {
	dir := filepath.Dir(AnchorHistoryPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("integrity state dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)
	discardStaleAnchorHistoryTmp()
	h := anchorHistoryLineHash(anchorHistoryGenesis, anchor)
	line := fmt.Sprintf("anchor:%s hash:%s\n", hex.EncodeToString(anchor[:]), hex.EncodeToString(h[:]))
	if err := atomicWriteVerifiedAnchorHistory([]byte(line)); err != nil {
		return fmt.Errorf("integrity: anchor.history bootstrap: %w", err)
	}
	return nil
}

func lastChainHashFromVerifiedFile() ([32]byte, error) {
	if err := migrateLegacyAnchorHistoryIfNeeded(); err != nil {
		return [32]byte{}, err
	}
	b, err := os.ReadFile(AnchorHistoryPath)
	if err != nil {
		return [32]byte{}, err
	}
	_, tip, err := verifyChainedHistoryBytes(b)
	if err != nil {
		return [32]byte{}, err
	}
	return tip, nil
}

// ApproveNewAnchor appends an approved anchor (root-only, O_APPEND only). Verifies chain before append.
func ApproveNewAnchor(newAnchor [32]byte) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("integrity: ApproveNewAnchor requires root")
	}
	discardStaleAnchorHistoryTmp()
	if err := migrateLegacyAnchorHistoryIfNeeded(); err != nil {
		return fmt.Errorf("integrity: ApproveNewAnchor: %w", err)
	}
	entries, err := parseAnchorHistoryEntries()
	if err != nil {
		return fmt.Errorf("integrity: ApproveNewAnchor: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("integrity: ApproveNewAnchor: anchor.history empty")
	}
	if anchorHistoryContains(entries, newAnchor) {
		log.Printf("[AUDIT] ApproveNewAnchor: digest already in anchor.history (no-op) fingerprint=%x", newAnchor[:8])
		return nil
	}
	prevTip, err := lastChainHashFromVerifiedFile()
	if err != nil {
		return fmt.Errorf("integrity: ApproveNewAnchor: %w", err)
	}
	newLineHash := anchorHistoryLineHash(prevTip, newAnchor)
	line := fmt.Sprintf("anchor:%s hash:%s\n", hex.EncodeToString(newAnchor[:]), hex.EncodeToString(newLineHash[:]))
	f, err := os.OpenFile(AnchorHistoryPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("integrity: anchor.history append: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("integrity: anchor.history append: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("integrity: anchor.history sync: %w", err)
	}
	_ = os.Chmod(AnchorHistoryPath, 0o600)
	_ = os.Chown(AnchorHistoryPath, 0, 0)
	log.Printf("[AUDIT] ApproveNewAnchor: appended fingerprint=%x", newAnchor[:8])
	return nil
}

// ReprovisionAnchorAppend computes the live anchor and appends it if missing (installer --reprovision-anchor parity).
func ReprovisionAnchorAppend() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("integrity: reprovision-anchor requires root")
	}
	cur, err := ComputeMachineAnchor()
	if err != nil {
		return err
	}
	return ApproveNewAnchor(cur)
}
