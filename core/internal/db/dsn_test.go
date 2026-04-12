package db

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestRejectNonTLSDSN(t *testing.T) {
	t.Parallel()
	err := ValidateInboundPostgresDSN("sslmode=disable")
	if err == nil {
		t.Fatal("expected error for sslmode=disable")
	}
	if !errors.Is(err, ErrPostgresDSNTLS) {
		t.Fatalf("expected ErrPostgresDSNTLS wrapping, got %v", err)
	}
}

func TestRejectNilTLSConfig(t *testing.T) {
	t.Parallel()
	cfg := pgx.ConnConfig{}
	err := ValidateTLSConfig(&cfg)
	if err == nil {
		t.Fatal("expected error for nil TLSConfig")
	}
}

func TestValidateInboundPostgresDSN(t *testing.T) {
	t.Parallel()
	goodURL := "postgres://ransomeye:pw@127.0.0.1:5432/ransomeye_core?sslmode=verify-full"
	if err := ValidateInboundPostgresDSN(goodURL); err != nil {
		t.Fatalf("valid url: %v", err)
	}
	goodKV := "host=127.0.0.1 port=5432 user=u dbname=d sslmode=verify-full"
	if err := ValidateInboundPostgresDSN(goodKV); err != nil {
		t.Fatalf("valid kv: %v", err)
	}

	cases := []string{
		"postgres://u@127.0.0.1/db?sslmode=disable",
		"host=127.0.0.1 sslmode=disable",
		"host=127.0.0.1 sslmode=prefer",
		"host=127.0.0.1 sslmode=require",
		"host=/var/run/postgresql dbname=postgres sslmode=verify-full",
		"user=x dbname=y sslmode=verify-full",
		"postgres://u@example.com:5432/db?sslmode=verify-full",
	}
	for _, c := range cases {
		if err := ValidateInboundPostgresDSN(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestStripLibpqSSLFileParamsFromDSN(t *testing.T) {
	// Not parallel: pgx.ParseConfig merges libpq env; we clear PGSSL* for a hermetic parse.
	t.Setenv("PGSSLROOTCERT", "")
	t.Setenv("PGSSLCERT", "")
	t.Setenv("PGSSLKEY", "")
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSSLSERVERNAME", "")
	kw := "host=127.0.0.1 port=5432 user=r dbname=ransomeye password=secret sslmode=verify-full sslrootcert=/x/ca.crt sslcert=/x/c.crt sslkey=/x/c.key"
	stripped := StripLibpqSSLFileParamsFromDSN(kw)
	if strings.Contains(stripped, "sslrootcert") || strings.Contains(stripped, "sslcert") || strings.Contains(stripped, "sslkey") {
		t.Fatalf("keyword strip left TLS file params: %q", stripped)
	}
	pc, err := pgx.ParseConfig(stripped)
	if err != nil {
		t.Fatalf("parse stripped keyword dsn: %v", err)
	}
	if pc.User != "r" || pc.Database != "ransomeye" || pc.Password != "secret" {
		t.Fatalf("identity mismatch: user=%q db=%q pw=%q", pc.User, pc.Database, pc.Password)
	}

	u := "postgres://ransomeye:p%40w@127.0.0.1:5432/ransomeye?sslmode=verify-full&sslrootcert=/a&sslcert=/b&sslkey=/c"
	strippedURL := StripLibpqSSLFileParamsFromDSN(u)
	if strings.Contains(strippedURL, "sslrootcert") {
		t.Fatalf("url strip failed: %q", strippedURL)
	}
	pu, err := pgx.ParseConfig(strippedURL)
	if err != nil {
		t.Fatalf("parse stripped url dsn: %v", err)
	}
	if pu.User != "ransomeye" || pu.Password != "p@w" || pu.Database != "ransomeye" {
		t.Fatalf("url identity mismatch: user=%q db=%q pw=%q", pu.User, pu.Database, pu.Password)
	}
}

func TestPostgresConnStringForPgxParseOnly(t *testing.T) {
	t.Parallel()
	s := PostgresConnStringForPgxParseOnly(Config{
		User:     "u",
		Password: "p",
		Database: "db",
	})
	if err := ValidateInboundPostgresDSN(s); err != nil {
		t.Fatalf("built dsn invalid: %v", err)
	}
	if err := ValidateInboundPostgresDSN(s + " "); err != nil {
		t.Fatalf("trim should not matter: %v", err)
	}
}
