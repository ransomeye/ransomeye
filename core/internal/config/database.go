package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"ransomeye/core/internal/db"
)

const canonicalDBCertsPath = "/opt/ransomeye/core/certs"

// resolveDBCertsBasePath returns the directory containing ca-chain.crt, client.crt, client.key.
func resolveDBCertsBasePath(devMode bool) (string, error) {
	basePath := canonicalDBCertsPath
	if devMode {
		keyPath := filepath.Join(basePath, "client.key")
		needFallback := false
		if _, err := os.Stat(keyPath); err != nil {
			needFallback = true
		} else if _, err := os.ReadFile(keyPath); err != nil {
			needFallback = true
		}
		if needFallback {
			log.Println("[DEV MODE] using local PostgreSQL TLS certificates")
			basePath = "configs/db-certs"
		}
	}
	if !devMode && basePath != canonicalDBCertsPath {
		log.Fatalf("[FATAL] non-canonical DB cert path in production")
	}
	return basePath, nil
}

// alignPGEnvTLS sets PGSSLROOTCERT / PGSSLCERT / PGSSLKEY for db.LoadConfigFromEnv and libpq-compatible tools.
func alignPGEnvTLS(basePath string) (sslroot, sslcert, sslkey string, err error) {
	sslroot = filepath.Join(basePath, "ca-chain.crt")
	sslcert = filepath.Join(basePath, "client.crt")
	sslkey = filepath.Join(basePath, "client.key")
	_ = os.Setenv("PGSSLROOTCERT", sslroot)
	_ = os.Setenv("PGSSLCERT", sslcert)
	_ = os.Setenv("PGSSLKEY", sslkey)
	return sslroot, sslcert, sslkey, nil
}

func quoteLibpqPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "''"
	}
	if !strings.ContainsAny(p, " '\\") {
		return p
	}
	return "'" + strings.ReplaceAll(p, "'", "''") + "'"
}

// ensureDSNIncludesTLSFileParams appends sslrootcert/sslcert/sslkey when missing (keyword or postgres URL DSN).
func ensureDSNIncludesTLSFileParams(dsn, sslroot, sslcert, sslkey string) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return "", fmt.Errorf("empty dsn")
	}
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", fmt.Errorf("parse postgres url: %w", err)
		}
		q := u.Query()
		changed := false
		if q.Get("sslrootcert") == "" {
			q.Set("sslrootcert", sslroot)
			changed = true
		}
		if q.Get("sslcert") == "" {
			q.Set("sslcert", sslcert)
			changed = true
		}
		if q.Get("sslkey") == "" {
			q.Set("sslkey", sslkey)
			changed = true
		}
		if !changed {
			return dsn, nil
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	}

	var parts []string
	lower := " " + strings.ToLower(dsn) + " "
	if !strings.Contains(lower, " sslrootcert=") {
		parts = append(parts, "sslrootcert="+quoteLibpqPath(sslroot))
	}
	if !strings.Contains(lower, " sslcert=") {
		parts = append(parts, "sslcert="+quoteLibpqPath(sslcert))
	}
	if !strings.Contains(lower, " sslkey=") {
		parts = append(parts, "sslkey="+quoteLibpqPath(sslkey))
	}
	if len(parts) == 0 {
		return dsn, nil
	}
	return strings.TrimSpace(dsn) + " " + strings.Join(parts, " "), nil
}

// BuildPostgresDSN selects the Core→PostgreSQL DSN.
//
// Precedence:
//  1. If POSTGRES_DSN is set (e.g. from EnvironmentFile), validate it and ensure TLS file params exist;
//     credentials embedded in POSTGRES_DSN are authoritative — discrete POSTGRES_PASSWORD is not applied.
//  2. Otherwise build from common.yaml host/port + POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB (legacy installer path).
//
// Also sets PGSSLROOTCERT / PGSSLCERT / PGSSLKEY to the resolved cert directory.
func BuildPostgresDSN() (string, error) {
	cfg := MustGetVerified()
	devMode := os.Getenv("RANSOMEYE_DEV_MODE") == "true"
	basePath, err := resolveDBCertsBasePath(devMode)
	if err != nil {
		return "", err
	}
	sslroot, sslcert, sslkey, err := alignPGEnvTLS(basePath)
	if err != nil {
		return "", err
	}

	if existing := strings.TrimSpace(os.Getenv("POSTGRES_DSN")); existing != "" {
		merged, err := ensureDSNIncludesTLSFileParams(existing, sslroot, sslcert, sslkey)
		if err != nil {
			return "", err
		}
		if err := db.ValidateInboundPostgresDSN(merged); err != nil {
			return "", err
		}
		return merged, nil
	}

	// Legacy discrete-env path (installer): defaults match historical single-node bootstrap.
	const coreDBUser = "ransomeye"
	const coreDBPassword = "ransomeye@12345"

	user := getEnvOrDefault("POSTGRES_USER", coreDBUser)
	password := getEnvOrDefault("POSTGRES_PASSWORD", coreDBPassword)
	dbname := getEnvOrDefault("POSTGRES_DB", "ransomeye")
	if strings.TrimSpace(password) == "" {
		password = coreDBPassword
	}

	host := cfg.Database.Host
	port := cfg.Database.Port
	out := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=verify-full sslrootcert=%s sslcert=%s sslkey=%s",
		host, port, user, password, dbname,
		quoteLibpqPath(sslroot), quoteLibpqPath(sslcert), quoteLibpqPath(sslkey),
	)
	if err := db.ValidateInboundPostgresDSN(out); err != nil {
		return "", err
	}
	return out, nil
}

func getEnvOrDefault(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}
