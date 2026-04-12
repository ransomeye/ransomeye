package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "validate":
		validateCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: ransomeye validate --full")
}

func validateCmd(args []string) {
	full := false
	for _, a := range args {
		if a == "--full" {
			full = true
		}
	}
	if !full {
		fmt.Fprintln(os.Stderr, "reject: only `ransomeye validate --full` is supported")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	repoRoot, err := findRepoRootWithDir("prd")
	if err != nil {
		fail(err)
	}

	if err := validatePRDIntegrity(repoRoot); err != nil {
		fail(err)
	}

	if err := validateTLSConfig(); err != nil {
		fail(err)
	}

	if err := validateWORMKeyExists("/etc/ransomeye/worm_signing.key"); err != nil {
		fail(err)
	}

	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		fail(errors.New("POSTGRES_DSN env var not set"))
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fail(err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		fail(fmt.Errorf("postgres ping failed: %w", err))
	}

	if err := validateDBSchemaVersion(ctx, pool, repoRoot); err != nil {
		fail(err)
	}

	if err := validateMerkleDailyRootExists(ctx, pool); err != nil {
		fail(err)
	}

	if err := validateNginxConfig(); err != nil {
		fail(err)
	}

	fmt.Println("[OK] ransomeye validate --full passed")
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "[FAIL] %v\n", err)
	os.Exit(1)
}

func findRepoRootWithDir(dirName string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if st, err := os.Stat(filepath.Join(wd, dirName)); err == nil && st.IsDir() {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			break
		}
		wd = parent
	}
	return "", fmt.Errorf("unable to locate repo root containing %s", dirName)
}

func validatePRDIntegrity(repoRoot string) error {
	manifestPath := filepath.Join(repoRoot, "prd_project_mishka", "prd.sha256")
	f, err := os.Open(manifestPath)
	if err != nil {
		return fmt.Errorf("open prd checksum manifest: %w", err)
	}
	defer f.Close()

	manifest := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("invalid prd.sha256 line: %q", line)
		}

		expected := strings.ToLower(strings.TrimSpace(fields[0]))
		filename := filepath.Base(strings.TrimSpace(fields[1]))
		if !strings.HasSuffix(filename, ".md") {
			return fmt.Errorf("unexpected prd manifest entry: %s", filename)
		}
		if _, err := hex.DecodeString(expected); err != nil {
			return fmt.Errorf("invalid prd manifest hash for %s: %w", filename, err)
		}
		if _, exists := manifest[filename]; exists {
			return fmt.Errorf("duplicate prd manifest entry: %s", filename)
		}
		manifest[filename] = expected
	}
	if err := sc.Err(); err != nil {
		return err
	}

	actualFiles, err := filepath.Glob(filepath.Join(repoRoot, "prd_project_mishka", "*.md"))
	if err != nil {
		return fmt.Errorf("list prd files: %w", err)
	}
	if len(actualFiles) == 0 {
		return errors.New("no PRD markdown files found")
	}

	for _, path := range actualFiles {
		filename := filepath.Base(path)
		expected, ok := manifest[filename]
		if !ok {
			return fmt.Errorf("PRD manifest missing entry: %s", filename)
		}
		actual, err := sha256FileHex(path)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("PRD hash mismatch: %s expected=%s actual=%s", filename, expected, actual)
		}
	}

	for filename := range manifest {
		if _, err := os.Stat(filepath.Join(repoRoot, "prd_project_mishka", filename)); err != nil {
			return fmt.Errorf("PRD manifest references missing file: %s", filename)
		}
	}

	return nil
}

func sha256FileHex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validateTLSConfig() error {
	candidates := [][2]string{
		{"/etc/ransomeye/server.crt", "/etc/ransomeye/server.key"},
		{"/opt/ransomeye/core/certs/server.crt", "/opt/ransomeye/core/certs/server.key"},
	}

	var lastErr error
	for _, pair := range candidates {
		certPath, keyPath := pair[0], pair[1]
		if st, err := os.Stat(certPath); err != nil || st.IsDir() {
			continue
		}
		if _, err := os.Stat(keyPath); err != nil {
			continue
		}

		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			lastErr = fmt.Errorf("tls key pair load failed (%s,%s): %w", certPath, keyPath, err)
			continue
		}
		if len(cert.Certificate) == 0 {
			lastErr = fmt.Errorf("tls certificate chain empty (%s)", certPath)
			continue
		}

		_ = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		}
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("TLS cert/key pair not found or not loadable")
}

func validateWORMKeyExists(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("WORM signing key missing: %w", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("WORM signing key is not a regular file: %s", path)
	}
	perm := st.Mode().Perm()
	if perm&0o077 != 0 {
		return fmt.Errorf("WORM signing key permissions too open: %#o", perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("WORM signing key read failed: %w", err)
	}
	return validateWORMKeyMaterial(raw)
}

func validateWORMKeyMaterial(raw []byte) error {
	const seedSize = 32
	if len(raw) != seedSize {
		return fmt.Errorf(
			"WORM signing key must be exactly %d bytes (raw Ed25519 seed), got %d",
			seedSize,
			len(raw),
		)
	}
	if bytes.HasPrefix(raw, []byte("-----BEGIN")) {
		return fmt.Errorf("WORM signing key must be raw bytes only (PEM-like prefix rejected)")
	}
	if bytesAllSame(raw) {
		return fmt.Errorf("WORM signing key rejected: weak or predictable seed")
	}
	if bytesSequentialFromZero(raw) || bytesSequentialFromOne(raw) {
		return fmt.Errorf("WORM signing key rejected: weak or predictable seed")
	}
	return nil
}

func bytesAllSame(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for i := 1; i < len(b); i++ {
		if b[i] != b[0] {
			return false
		}
	}
	return true
}

func bytesSequentialFromZero(b []byte) bool {
	for i, x := range b {
		if x != byte(i) {
			return false
		}
	}
	return true
}

func bytesSequentialFromOne(b []byte) bool {
	for i, x := range b {
		if x != byte(i+1) {
			return false
		}
	}
	return true
}

func validateDBSchemaVersion(ctx context.Context, pool *pgxpool.Pool, repoRoot string) error {
	expectedVersions, err := loadExpectedMigrationVersions(repoRoot)
	if err != nil {
		return err
	}

	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("schema_migrations version query failed: %w", err)
	}
	defer rows.Close()

	var actualVersions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("scan schema_migrations version: %w", err)
		}
		actualVersions = append(actualVersions, version)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate schema_migrations versions: %w", err)
	}

	if len(actualVersions) != len(expectedVersions) {
		return fmt.Errorf(
			"schema_migrations count mismatch: got %d want %d",
			len(actualVersions),
			len(expectedVersions),
		)
	}
	for i, expected := range expectedVersions {
		if actualVersions[i] != expected {
			return fmt.Errorf(
				"schema_migrations version mismatch at position %d: got %d want %d",
				i,
				actualVersions[i],
				expected,
			)
		}
	}

	return nil
}

func loadExpectedMigrationVersions(repoRoot string) ([]int, error) {
	entries, err := os.ReadDir(filepath.Join(repoRoot, "migrations"))
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	versions := make([]int, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		name := entry.Name()
		if len(name) < 3 {
			return nil, fmt.Errorf("invalid migration filename: %s", name)
		}
		version, err := strconv.Atoi(name[:3])
		if err != nil {
			return nil, fmt.Errorf("parse migration version from %s: %w", name, err)
		}
		versions = append(versions, version)
	}
	if len(versions) == 0 {
		return nil, errors.New("no migration files found")
	}

	sort.Ints(versions)
	for i, version := range versions {
		expected := i + 1
		if version != expected {
			return nil, fmt.Errorf("missing migration version %03d", expected)
		}
	}

	return versions, nil
}

func validateMerkleDailyRootExists(ctx context.Context, pool *pgxpool.Pool) error {
	var merkleRoot string
	err := pool.QueryRow(ctx, `
SELECT merkle_root
FROM merkle_daily_roots
ORDER BY computed_at DESC
LIMIT 1
`).Scan(&merkleRoot)
	if err != nil {
		return fmt.Errorf("merkle_daily_roots query failed: %w", err)
	}
	if strings.TrimSpace(merkleRoot) == "" || len(merkleRoot) != 64 {
		return fmt.Errorf("merkle_root invalid/empty")
	}
	if _, err := hex.DecodeString(merkleRoot); err != nil {
		return fmt.Errorf("merkle_root invalid hex: %w", err)
	}
	return nil
}

func validateNginxConfig() error {
	cmd := exec.Command("nginx", "-t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed: %v\n%s", err, string(out))
	}

	confPath := "/etc/nginx/conf.d/ransomeye.conf"
	if st, err := os.Stat(confPath); err == nil && st.Mode().IsRegular() {
		b, err := os.ReadFile(confPath)
		if err == nil {
			s := string(b)
			if !strings.Contains(s, "ssl_protocols TLSv1.3") {
				return fmt.Errorf("nginx config missing `ssl_protocols TLSv1.3`")
			}
			if !strings.Contains(s, "proxy_ssl_name NGINX_UPSTREAM_TARGET") && !strings.Contains(s, "proxy_ssl_server_name off") {
				return fmt.Errorf("nginx config missing upstream SNI correction (`proxy_ssl_name NGINX_UPSTREAM_TARGET;` or `proxy_ssl_server_name off;`)")
			}
			if strings.Contains(s, "unsafe-inline") {
				return fmt.Errorf("nginx config CSP contains `unsafe-inline`")
			}
		}
	}

	return nil
}
