package compliance

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const prdChecksumFilename = "prd.sha256"

func init() {
	Register("PRD-00", "PRD-INTEGRITY",
		"PRD directory must match the immutable checksum manifest",
		ValidatePRDIntegrity)
}

func ValidatePRDIntegrity() error {
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		return nil
	}
	repoRoot, err := findRepoRootWithPRD()
	if err != nil {
		return err
	}

	manifestPath := filepath.Join(repoRoot, "prd_project_mishka", prdChecksumFilename)
	expected, err := loadChecksums(manifestPath)
	if err != nil {
		return err
	}

	for file, expectedHash := range expected {
		if strings.Contains(file, "PRD-25") {
			return fmt.Errorf("INVALID_PRD_SCOPE: PRD-25 not allowed in V0.0")
		}
		actual, err := sha256File(filepath.Join(repoRoot, "prd_project_mishka", file))
		if err != nil {
			return err
		}
		if actual != expectedHash {
			return fmt.Errorf("PRD_TAMPER_DETECTED: %s", file)
		}
	}
	return nil
}

func loadChecksums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("missing PRD checksum manifest: %s", path)
		}
		return nil, fmt.Errorf("open PRD checksum manifest: %w", err)
	}
	defer f.Close()

	expected := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Lines are "<64-hex-hash>  <relative path with spaces>.md" — do not split on spaces in the filename.
		if len(line) < 66 {
			return nil, fmt.Errorf("invalid PRD checksum manifest line: %q", line)
		}
		hashHex := line[:64]
		if line[64] != ' ' {
			return nil, fmt.Errorf("invalid PRD checksum manifest line: %q", line)
		}
		relPath := strings.TrimSpace(line[65:])
		if relPath == "" {
			return nil, fmt.Errorf("invalid PRD checksum manifest line: %q", line)
		}

		name := filepath.Base(relPath)
		if strings.Contains(name, "PRD-25") {
			return nil, fmt.Errorf("INVALID_PRD_SCOPE: PRD-25 not allowed in V0.0")
		}
		if filepath.Ext(name) != ".md" {
			return nil, fmt.Errorf("unexpected PRD manifest entry: %s", relPath)
		}
		expected[name] = hashHex
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan PRD checksum manifest: %w", err)
	}
	if len(expected) == 0 {
		return nil, fmt.Errorf("empty PRD checksum manifest: %s", path)
	}
	return expected, nil
}

func findRepoRootWithPRD() (string, error) {
	if root := strings.TrimSpace(os.Getenv("RANSOMEYE_REPO_ROOT")); root != "" {
		if info, err := os.Stat(filepath.Join(root, "prd_project_mishka")); err == nil && info.IsDir() {
			return root, nil
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}

	for {
		if info, err := os.Stat(filepath.Join(wd, "prd_project_mishka")); err == nil && info.IsDir() {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			break
		}
		wd = parent
	}

	return "", errors.New("unable to locate repository root with prd_project_mishka directory")
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("missing PRD file: %s", filepath.Base(path))
		}
		return "", fmt.Errorf("open PRD file %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash PRD file %s: %w", filepath.Base(path), err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
