package netcfg

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var disallowedIPPattern = regexp.MustCompile(`127\.0\.0\.1|0\.0\.0\.0`)

func TestNoHardcodedNetworkAddresses(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]struct{}{
		filepath.Clean(filepath.Join(root, "core", "internal", "netcfg", "addr.go")):   {},
		filepath.Clean(filepath.Join(root, "core", "internal", "db", "common.go")):    {},
		filepath.Clean(filepath.Join(root, "core", "internal", "config", "common_config.go")): {},
		filepath.Clean(filepath.Join(root, "core", "internal", "config", "bootstrap.go")):     {},
		filepath.Clean(filepath.Join(root, "core", "internal", "dbbootstrap", "pg_hba_strict.go")): {},
		filepath.Clean(filepath.Join(root, "core", "cmd", "mishka-signal-send", "main.go")): {},
		filepath.Clean(filepath.Join(root, "ui", "src", "net", "loopback.ts")):        {},
	}

	scanRoots := []string{
		filepath.Join(root, "core"),
		filepath.Join(root, "sine-engine", "src"),
		filepath.Join(root, "ui", "src"),
		filepath.Join(root, "ui", "index.html"),
	}

	var violations []string
	for _, scanRoot := range scanRoots {
		info, err := os.Stat(scanRoot)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("stat %s: %v", scanRoot, err)
		}

		if !info.IsDir() {
			violations = append(violations, scanFile(root, scanRoot, allowed)...)
			continue
		}

		err = filepath.Walk(scanRoot, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if shouldSkipPath(path) {
				if info != nil && info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !shouldScanFile(path) {
				return nil
			}
			violations = append(violations, scanFile(root, path, allowed)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", scanRoot, err)
		}
	}

	sort.Strings(violations)
	if len(violations) > 0 {
		t.Fatalf("hardcoded network addresses found:\n%s", strings.Join(violations, "\n"))
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
}

func shouldSkipPath(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "node_modules", "target", "__pycache__", ".venv", "venv", "vendor":
		return true
	default:
		return false
	}
}

func shouldScanFile(path string) bool {
	base := filepath.Base(path)
	if strings.HasSuffix(base, "_test.go") {
		return false
	}

	switch filepath.Ext(base) {
	case ".go", ".py", ".rs", ".ts", ".tsx", ".js", ".html":
		return true
	default:
		return false
	}
}

func scanFile(root, path string, allowed map[string]struct{}) []string {
	path = filepath.Clean(path)
	if _, ok := allowed[path]; ok {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return []string{filepath.ToSlash(path) + ": open failed: " + err.Error()}
	}
	defer f.Close()

	var violations []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if !disallowedIPPattern.MatchString(line) {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		violations = append(violations, filepath.ToSlash(rel)+":"+itoa(lineNo)+": "+strings.TrimSpace(line))
	}
	if err := sc.Err(); err != nil {
		return []string{filepath.ToSlash(path) + ": scan failed: " + err.Error()}
	}
	return violations
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + (v % 10))
		v /= 10
	}
	return string(buf[i:])
}
