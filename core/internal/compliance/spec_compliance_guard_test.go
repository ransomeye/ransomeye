package compliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadChecksumsRejectsPRD25(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prd.sha256")
	content := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  PRD-25_ZeroMiss_Behavioral_ThreatIntel_Augmentation_V0_0.md\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loadChecksums(path)
	if err == nil {
		t.Fatal("expected PRD-25 manifest rejection")
	}
	if !strings.Contains(err.Error(), "INVALID_PRD_SCOPE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadChecksumsAcceptsCanonicalPRDSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prd.sha256")
	content := "" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  PRD-00_Master_Product_Index_V0_0.md\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  PRD-24_Testing_Validation_Release_V0_0.md\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := loadChecksums(path)
	if err != nil {
		t.Fatalf("loadChecksums: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("entry count = %d, want 2", len(got))
	}
	if got["PRD-00_Master_Product_Index_V0_0.md"] == "" {
		t.Fatal("missing PRD-00 entry")
	}
	if got["PRD-24_Testing_Validation_Release_V0_0.md"] == "" {
		t.Fatal("missing PRD-24 entry")
	}
}
