package netcfg

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// disallowedPattern catches 127.0.0.1 and localhost.
// 0.0.0.0 is allowed in code for explicit bind-all listeners where required.
var disallowedPattern = regexp.MustCompile(`127\.0\.0\.1|localhost`)

func TestGlobalNoHardcodedNetworkAddresses(t *testing.T) {
	root := repoRootGlobal(t)

	// allowedFiles are strictly for constants, documentation, or explicit test cases.
	// Runtime logic MUST NOT be in this list.
	allowedFiles := map[string]struct{}{
		filepath.Clean(filepath.Join(root, "core", "internal", "netcfg", "addr.go")):          {},
		filepath.Clean(filepath.Join(root, "core", "internal", "db", "common.go")):           {},
		filepath.Clean(filepath.Join(root, "core", "internal", "config", "common_config.go")): {},
		filepath.Clean(filepath.Join(root, "core", "internal", "config", "bootstrap.go")):    {},
		filepath.Clean(filepath.Join(root, "ui", "src", "net", "loopback.ts")):               {},
		filepath.Clean(filepath.Join(root, "docs", "V0.0_SYSTEM_STATE.md")):                  {},
		filepath.Clean(filepath.Join(root, "docs", "prd_develop_doc", "PRD-25_reference.md")): {},
		filepath.Clean(filepath.Join(root, "docs", "prd_develop_doc", "PRD_Completion_Audit_Report.md")): {},
		filepath.Clean(filepath.Join(root, "skills", "architecture_skill.md")):               {},
		filepath.Clean(filepath.Join(root, "skills", "cryptography_skill.md")):               {},
		filepath.Clean(filepath.Join(root, "configs", "common.yaml")):                        {},
		filepath.Clean(filepath.Join(root, "configs", "common.yaml.template")):               {},
		filepath.Clean(filepath.Join(root, "installer", "nginx", "ransomeye.conf")):          {},
		filepath.Clean(filepath.Join(root, "core", "internal", "dbbootstrap", "pg_hba_strict.go")): {},
		filepath.Clean(filepath.Join(root, "core", "migrations", "040_final_sanity.sql")):   {},
		filepath.Clean(filepath.Join(root, "core", "cmd", "mishka-signal-send", "main.go")): {},
	}

	// scanDirs covers all primary code bases.
	scanDirs := []string{
		filepath.Join(root, "core"),
		filepath.Join(root, "cmd"),
		filepath.Join(root, "re-ctl"),
		filepath.Join(root, "sine-engine"),
		filepath.Join(root, "tools"),
	}

	var violations []string
	for _, dir := range scanDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() {
				if shouldSkipDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}

			if !shouldScan(path) {
				return nil
			}

			if _, ok := allowedFiles[filepath.Clean(path)]; ok {
				return nil
			}

			violations = append(violations, scanForHardcoded(root, path)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("PRD VIOLATION: Hardcoded network addresses found:\n%s", strings.Join(violations, "\n"))
		t.Logf("Total violations: %d", len(violations))
		t.FailNow()
	}
}

func repoRootGlobal(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
}

func shouldSkipDir(name string) bool {
	switch name {
	case "node_modules", "target", "__pycache__", ".venv", "venv", "vendor", ".git":
		return true
	}
	return false
}

func shouldScan(path string) bool {
	// Skip test files as they often contain hardcoded IPs for mock expectations.
	if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".test.ts") {
		return false
	}
	ext := filepath.Ext(path)
	switch ext {
	case ".go", ".py", ".rs", ".ts", ".tsx", ".sh", ".yaml", ".sql":
		return true
	}
	return false
}

func scanForHardcoded(root, path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "--") {
			continue
		}

		if disallowedPattern.MatchString(line) {
			rel, _ := filepath.Rel(root, path)
			lines = append(lines, fmt.Sprintf("%s:%d: %s", rel, lineNo, trimmed))
		}
	}
	return lines
}
