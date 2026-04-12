package db

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ErrPostgresDSNTLS is returned when an inbound POSTGRES_DSN is not loopback verify-full (deployment contract only).
var ErrPostgresDSNTLS = errors.New("postgres dsn tls policy violation")

var (
	reKeywordHost    = regexp.MustCompile(`(?i)\bhost=([^\s]+)`)
	reKeywordSSLMode = regexp.MustCompile(`(?i)\bsslmode=([^\s]+)`)
	// Libpq file-based TLS params are merged into POSTGRES_DSN for tooling/validation, but pgx.ParseConfig
	// may try to read client key material during parse. Strip these before identity-only parse; TLS still
	// comes from db.Config + preparePgxConnConfig (PGSSL* / buildTLSConfig).
	reSSLFileKeywordParam = regexp.MustCompile(`(?i)\s*\bssl(?:rootcert|cert|key)\s*=\s*(?:'(?:[^']|'')*'|\S+)`)
)

// ValidateInboundPostgresDSN rejects any non-verify-full sslmode, unix-socket host paths, and non-loopback hosts.
func ValidateInboundPostgresDSN(dsn string) error {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return fmt.Errorf("%w: empty dsn", ErrPostgresDSNTLS)
	}

	if strings.Contains(dsn, "://") {
		return validatePostgresURL(dsn)
	}
	return validateKeywordDSN(dsn)
}

func validatePostgresURL(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("%w: parse url: %v", ErrPostgresDSNTLS, err)
	}
	h := u.Hostname()
	if h == "" {
		return fmt.Errorf("%w: url dsn must include host %s", ErrPostgresDSNTLS, LoopbackHost)
	}
	if h != LoopbackHost {
		return fmt.Errorf("%w: host must be %s, got %q", ErrPostgresDSNTLS, LoopbackHost, h)
	}
	mode := strings.TrimSpace(strings.ToLower(u.Query().Get("sslmode")))
	if mode == "" {
		return fmt.Errorf("%w: sslmode=verify-full is required", ErrPostgresDSNTLS)
	}
	if mode != "verify-full" {
		// SECURITY: sslmode here validates the deployer-facing contract only, not wire cryptography.
		// TLS 1.3 + certificate verification is enforced exclusively via pgx.ConnConfig.TLSConfig.
		return fmt.Errorf("%w: sslmode must be verify-full for deployment contract, got %q", ErrPostgresDSNTLS, mode)
	}
	return nil
}

func validateKeywordDSN(dsn string) error {
	hostToks := reKeywordHost.FindStringSubmatch(dsn)
	if len(hostToks) < 2 {
		return fmt.Errorf("%w: keyword dsn must include host=%s", ErrPostgresDSNTLS, LoopbackHost)
	}
	host := stripConnQuotes(strings.TrimSpace(hostToks[1]))
	if strings.HasPrefix(host, "/") {
		return fmt.Errorf("%w: unix socket host= is forbidden, use host=%s port=%d", ErrPostgresDSNTLS, LoopbackHost, LoopbackPort)
	}
	if host != LoopbackHost {
		return fmt.Errorf("%w: host must be %s, got %q", ErrPostgresDSNTLS, LoopbackHost, host)
	}

	modeToks := reKeywordSSLMode.FindStringSubmatch(dsn)
	if len(modeToks) < 2 {
		return fmt.Errorf("%w: sslmode=verify-full is required", ErrPostgresDSNTLS)
	}
	mode := strings.TrimSpace(strings.ToLower(stripConnQuotes(modeToks[1])))
	if mode != "verify-full" {
		// SECURITY: sslmode is NOT relied upon for TLS enforcement (see pgx.ConnConfig.TLSConfig).
		return fmt.Errorf("%w: sslmode must be verify-full for deployment contract, got %q", ErrPostgresDSNTLS, mode)
	}
	return nil
}

func stripConnQuotes(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "\\'", "'")
	}
	return s
}

// StripLibpqSSLFileParamsFromDSN removes sslrootcert/sslcert/sslkey from a keyword or postgres URL DSN.
// The full DSN (including those params) should still be validated with ValidateInboundPostgresDSN before
// calling this when enforcing the deployment TLS contract.
func StripLibpqSSLFileParamsFromDSN(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return dsn
	}
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return dsn
		}
		q := u.Query()
		q.Del("sslrootcert")
		q.Del("sslcert")
		q.Del("sslkey")
		u.RawQuery = q.Encode()
		return strings.TrimSpace(u.String())
	}
	out := reSSLFileKeywordParam.ReplaceAllString(dsn, " ")
	return strings.TrimSpace(out)
}

// PostgresConnStringForPgxParseOnly builds the libpq keyword string passed to pgx.ParseConfig.
//
// SECURITY: sslmode is NOT relied upon for TLS enforcement.
// TLS 1.3 + certificate verification is enforced exclusively via pgx.ConnConfig.TLSConfig.
// sslmode=verify-full exists only for PostgreSQL/libpq compatibility on the parse path.
func PostgresConnStringForPgxParseOnly(cfg Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "host=%s port=%d ", LoopbackHost, LoopbackPort)
	b.WriteString(fmt.Sprintf("user=%s ", quoteLibpqConnWord(cfg.User)))
	if strings.TrimSpace(cfg.Password) != "" {
		b.WriteString(fmt.Sprintf("password=%s ", quoteLibpqConnWord(cfg.Password)))
	}
	b.WriteString(fmt.Sprintf("dbname=%s ", quoteLibpqConnWord(cfg.Database)))
	b.WriteString("sslmode=verify-full")
	return strings.TrimSpace(b.String())
}

func quoteLibpqConnWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " '") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
