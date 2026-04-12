package dbbootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePgHbaStrict_AllowsMinimalCompliantFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pg_hba.conf")
	content := strings.TrimSpace(`
# comment
local all ransomeye_admin peer
hostssl ransomeye ransomeye 127.0.0.1/32 scram-sha-256
hostssl ransomeye ransomeye_readonly 127.0.0.1/32 scram-sha-256
`) + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePgHbaStrict(p); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePgHbaStrict_RejectsTrust(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pg_hba.conf")
	content := `
local all ransomeye_admin peer
hostssl ransomeye ransomeye 127.0.0.1/32 trust
hostssl ransomeye ransomeye_readonly 127.0.0.1/32 scram-sha-256
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePgHbaStrict(p); err == nil || !strings.Contains(err.Error(), "non-compliant") {
		t.Fatalf("expected non-compliant error, got %v", err)
	}
}

func TestValidatePgHbaStrict_RejectsHostNonSSL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pg_hba.conf")
	content := `
local all ransomeye_admin peer
host ransomeye ransomeye 127.0.0.1/32 scram-sha-256
hostssl ransomeye ransomeye_readonly 127.0.0.1/32 scram-sha-256
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePgHbaStrict(p); err == nil || !strings.Contains(err.Error(), "hostssl") {
		t.Fatalf("expected hostssl error, got %v", err)
	}
}

func TestValidatePgHbaStrict_RejectsPostgresCertRule(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pg_hba.conf")
	content := `
local all ransomeye_admin peer
hostssl ransomeye ransomeye 127.0.0.1/32 scram-sha-256
hostssl ransomeye ransomeye_readonly 127.0.0.1/32 scram-sha-256
hostssl all postgres 127.0.0.1/32 cert
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePgHbaStrict(p); err == nil || !strings.Contains(err.Error(), "non-compliant") {
		t.Fatalf("expected non-compliant error for postgres cert rule, got %v", err)
	}
}

func TestValidatePgHbaStrict_RejectsWrongAddress(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pg_hba.conf")
	content := `
local all ransomeye_admin peer
hostssl ransomeye ransomeye 0.0.0.0/0 scram-sha-256
hostssl ransomeye ransomeye_readonly 127.0.0.1/32 scram-sha-256
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePgHbaStrict(p); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidatePgHbaStrict_AllowsBundledInstanceFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pg_hba.conf")
	content := strings.TrimSpace(`
local   all             postgres                               peer
local   all             ransomeye_admin                        peer
hostssl all             all                    127.0.0.1/32             scram-sha-256 clientcert=verify-ca
hostnossl all           all                    127.0.0.1/32             reject
host    all             all                    0.0.0.0/0                reject
host    all             all                    ::0/0                    reject
`) + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePgHbaStrict(p); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePgHbaStrict_RejectsMissingRequiredRules(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pg_hba.conf")
	content := `
local all ransomeye_admin peer
hostssl ransomeye ransomeye 127.0.0.1/32 scram-sha-256
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePgHbaStrict(p); err == nil || !strings.Contains(err.Error(), "missing required") {
		t.Fatalf("expected missing rules error, got %v", err)
	}
}
