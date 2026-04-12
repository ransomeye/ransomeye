//go:build reproducible_build

package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReproducibleBuild(t *testing.T) {
	root, err := repoRootForReproBuildTest()
	if err != nil {
		t.Fatalf("repoRootForReproBuildTest: %v", err)
	}

	ok, err := hasFreshReproStamp(root)
	if err != nil {
		t.Fatalf("hasFreshReproStamp: %v", err)
	}
	if ok {
		return
	}

	script := filepath.Join(root, "scripts", "verify-reproducible-build.sh")
	cmd := exec.Command("bash", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "RANSOMEYE_REPO_ROOT="+root)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify reproducible build: %v\n%s", err, output)
	}
}

func hasFreshReproStamp(root string) (bool, error) {
	stampPath, err := reproStampPath(root)
	if err != nil {
		return false, err
	}

	raw, err := os.ReadFile(stampPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	expected, err := currentWorktreeHash(root)
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(string(raw)) == expected, nil
}

func reproStampPath(root string) (string, error) {
	sum := sha256.Sum256([]byte(root))
	return filepath.Join(os.TempDir(), "ransomeye-repro-stamp."+hex.EncodeToString(sum[:])), nil
}

func currentWorktreeHash(root string) (string, error) {
	headOut, err := exec.Command("git", "rev-parse", "HEAD").CombinedOutput()
	if err != nil {
		return "", execError("git rev-parse HEAD", err, headOut)
	}

	statusCmd := exec.Command("git", "status", "--porcelain=v1", "--untracked-files=all")
	statusCmd.Dir = root
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		return "", execError("git status --porcelain=v1 --untracked-files=all", err, statusOut)
	}

	sum := sha256.Sum256(append(headOut, statusOut...))
	return hex.EncodeToString(sum[:]), nil
}

func execError(name string, err error, output []byte) error {
	msg := strings.TrimSpace(string(output))
	if msg == "" {
		return err
	}
	return &execFailure{name: name, err: err, output: msg}
}

type execFailure struct {
	name   string
	err    error
	output string
}

func (e *execFailure) Error() string {
	return e.name + ": " + e.err.Error() + ": " + e.output
}

func repoRootForReproBuildTest() (string, error) {
	if root := os.Getenv("RANSOMEYE_REPO_ROOT"); root != "" {
		return root, nil
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
