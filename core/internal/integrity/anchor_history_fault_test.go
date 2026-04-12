//go:build test_fault_injection

package integrity

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestAnchorHistoryMigrationFaultBeforeRenameLeavesOriginalIntact(t *testing.T) {
	for _, point := range []string{"after_write_tmp", "after_fsync", "before_rename"} {
		t.Run(point, func(t *testing.T) {
			useAnchorHistoryFaultTestDir(t)
			a1 := testAnchorDigest(0x11)
			a2 := testAnchorDigest(0x22)
			legacy := legacyAnchorHistoryBytes(a1, a2)
			if err := os.WriteFile(AnchorHistoryPath, legacy, 0o600); err != nil {
				t.Fatalf("write legacy history: %v", err)
			}

			t.Setenv(anchorHistoryFaultPointEnv, point)
			expectSimulatedCrash(t, func() {
				if err := migrateLegacyAnchorHistoryIfNeeded(); err != nil {
					t.Fatalf("migrateLegacyAnchorHistoryIfNeeded error before crash: %v", err)
				}
			})

			got, err := os.ReadFile(AnchorHistoryPath)
			if err != nil {
				t.Fatalf("read original history after crash: %v", err)
			}
			if string(got) != string(legacy) {
				t.Fatalf("original history changed after %s fault", point)
			}
			if _, err := os.Stat(anchorHistoryTmp); err != nil {
				t.Fatalf("expected tmp file after %s fault: %v", point, err)
			}

			t.Setenv(anchorHistoryFaultPointEnv, "")
			anchors, err := parseAnchorHistoryEntries()
			if err != nil {
				t.Fatalf("parseAnchorHistoryEntries after restart: %v", err)
			}
			if len(anchors) != 2 || anchors[0] != a1 || anchors[1] != a2 {
				t.Fatalf("unexpected anchors after restart: %v", anchors)
			}
			if _, err := os.Stat(anchorHistoryTmp); !os.IsNotExist(err) {
				t.Fatalf("tmp file still present after restart: %v", err)
			}
		})
	}
}

func TestAnchorHistoryMigrationFaultAfterRenameStillVerifies(t *testing.T) {
	useAnchorHistoryFaultTestDir(t)
	a1 := testAnchorDigest(0x31)
	a2 := testAnchorDigest(0x32)
	if err := os.WriteFile(AnchorHistoryPath, legacyAnchorHistoryBytes(a1, a2), 0o600); err != nil {
		t.Fatalf("write legacy history: %v", err)
	}

	t.Setenv(anchorHistoryFaultPointEnv, "after_rename_before_fsync_dir")
	expectSimulatedCrash(t, func() {
		if err := migrateLegacyAnchorHistoryIfNeeded(); err != nil {
			t.Fatalf("migrateLegacyAnchorHistoryIfNeeded error before crash: %v", err)
		}
	})

	if _, err := os.Stat(anchorHistoryTmp); !os.IsNotExist(err) {
		t.Fatalf("tmp file should be gone after rename fault: %v", err)
	}
	content, err := os.ReadFile(AnchorHistoryPath)
	if err != nil {
		t.Fatalf("read migrated history: %v", err)
	}
	if _, _, err := verifyChainedHistoryBytes(content); err != nil {
		t.Fatalf("verify chained history after rename fault: %v", err)
	}

	t.Setenv(anchorHistoryFaultPointEnv, "")
	anchors, err := parseAnchorHistoryEntries()
	if err != nil {
		t.Fatalf("parseAnchorHistoryEntries after restart: %v", err)
	}
	if len(anchors) != 2 || anchors[0] != a1 || anchors[1] != a2 {
		t.Fatalf("unexpected anchors after restart: %v", anchors)
	}
}

func TestAnchorHistoryMigrationIgnoresPartialTmpOnRestart(t *testing.T) {
	useAnchorHistoryFaultTestDir(t)
	a1 := testAnchorDigest(0x41)
	a2 := testAnchorDigest(0x42)
	legacy := legacyAnchorHistoryBytes(a1, a2)
	if err := os.WriteFile(AnchorHistoryPath, legacy, 0o600); err != nil {
		t.Fatalf("write legacy history: %v", err)
	}
	if err := os.WriteFile(anchorHistoryTmp, []byte("anchor:partial"), 0o600); err != nil {
		t.Fatalf("write partial tmp history: %v", err)
	}

	anchors, err := parseAnchorHistoryEntries()
	if err != nil {
		t.Fatalf("parseAnchorHistoryEntries with partial tmp: %v", err)
	}
	if len(anchors) != 2 || anchors[0] != a1 || anchors[1] != a2 {
		t.Fatalf("unexpected anchors after partial tmp recovery: %v", anchors)
	}
	if _, err := os.Stat(anchorHistoryTmp); !os.IsNotExist(err) {
		t.Fatalf("tmp file still present after partial tmp recovery: %v", err)
	}
}

func useAnchorHistoryFaultTestDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	setAnchorHistoryTestPaths(dir)
	t.Cleanup(resetAnchorHistoryTestPaths)
}

func testAnchorDigest(first byte) [32]byte {
	var out [32]byte
	out[0] = first
	out[31] = first ^ 0xff
	return out
}

func legacyAnchorHistoryBytes(anchors ...[32]byte) []byte {
	var payload []byte
	for _, anchor := range anchors {
		payload = append(payload, []byte("anchor:"+hex.EncodeToString(anchor[:])+"\n")...)
	}
	return payload
}

func expectSimulatedCrash(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected simulated crash")
		} else if got := fmt.Sprint(r); got != "simulated crash" {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	fn()
}
