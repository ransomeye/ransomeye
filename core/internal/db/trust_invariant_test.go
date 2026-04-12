package db

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var trustInvariantAllowedConnectConfig = map[string]struct{}{
	"common.go": {},
	"pool.go":   {},
}

func TestNoDirectPgxOrSQLBypass(t *testing.T) {
	root := repoRootForTrustTest(t)
	scanRoots := []string{
		filepath.Join(root, "core"),
		filepath.Join(root, "agents"),
		filepath.Join(root, "installer"),
	}
	var violations []string
	for _, scanRoot := range scanRoots {
		if _, err := os.Stat(scanRoot); os.IsNotExist(err) {
			continue
		}
		_ = filepath.Walk(scanRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if skipTrustInvariantDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) != ".go" {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			violations = append(violations, scanGoFileForTrustViolations(root, path)...)
			return nil
		})
	}
	if len(violations) > 0 {
		t.Fatalf("direct DB bypass patterns detected:\n%s", strings.Join(violations, "\n"))
	}
}

func repoRootForTrustTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../<repo>/core/internal/db/trust_invariant_test.go -> repo root is ../../../
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func skipTrustInvariantDir(name string) bool {
	switch name {
	case "vendor", "node_modules", "target", ".git", "__pycache__", ".venv":
		return true
	default:
		return false
	}
}

func scanGoFileForTrustViolations(repoRoot, path string) []string {
	base := filepath.Base(path)
	rel, err := filepath.Rel(repoRoot, path)
	if err != nil {
		rel = path
	}
	relSlash := filepath.ToSlash(rel)

	var out []string
	f, err := os.Open(path)
	if err != nil {
		return []string{relSlash + ": open: " + err.Error()}
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "//") {
			continue
		}
		if strings.Contains(line, "pgx.Connect(") {
			out = append(out, relSlash+":"+itoaTrust(lineNo)+": pgx.Connect(")
		}
		if strings.Contains(line, "pgxpool.NewWithConfig(") {
			if !(strings.HasPrefix(relSlash, "core/internal/db/") && base == "pool.go") {
				out = append(out, relSlash+":"+itoaTrust(lineNo)+": pgxpool.NewWithConfig(")
			}
		}
		if strings.Contains(line, "sql.Open(") {
			out = append(out, relSlash+":"+itoaTrust(lineNo)+": sql.Open(")
		}
		if strings.Contains(line, "pgx.ConnectConfig(") {
			_, allowed := trustInvariantAllowedConnectConfig[base]
			if !allowed || !strings.HasPrefix(relSlash, "core/internal/db/") {
				out = append(out, relSlash+":"+itoaTrust(lineNo)+": pgx.ConnectConfig(")
			}
		}
	}
	if err := sc.Err(); err != nil {
		return []string{relSlash + ": scan: " + err.Error()}
	}
	return out
}

func itoaTrust(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + (v % 10))
		v /= 10
	}
	return string(buf[i:])
}
