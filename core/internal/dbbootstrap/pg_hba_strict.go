package dbbootstrap

import (
	"fmt"
	"os"
	"strings"

	dbbase "ransomeye/core/internal/db"
)

// ValidatePgHbaStrict parses pg_hba.conf field-by-field (no regex) and enforces an exact allowlist only.
// Allowed rules (exact token match, optional clientcert= on hostssl):
//
//	local all postgres peer (optional OS superuser break-glass)
//	local all ransomeye_admin peer
//	hostssl ransomeye ransomeye <loopback>/32 scram-sha-256 [clientcert=…]
//	hostssl ransomeye ransomeye_readonly <loopback>/32 scram-sha-256 [clientcert=…]
//	host / hostnossl lines that are all-all reject hardening only
func ValidatePgHbaStrict(hbaPath string) error {
	if strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true" {
		fmt.Printf("[DEV MODE] skipping pg_hba strict validation for %s\n", hbaPath)
		return nil
	}
	raw, err := os.ReadFile(hbaPath)
	if err != nil {
		return fmt.Errorf("read pg_hba %q: %w", hbaPath, err)
	}
	content := string(raw)
	var (
		hasLocalAdmin bool
		hasAppRW      bool
		hasAppRO      bool
	)
	for lineNum, line := range strings.Split(content, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		fields := strings.Fields(trim)
		if len(fields) < 4 {
			return fmt.Errorf("[FATAL] pg_hba.conf violation: non-compliant rule detected: %s (line %d: too few fields)", trim, lineNum+1)
		}
		ft := fields[0]
		switch ft {
		case "local":
			if !allowedLocalRule(fields) {
				return fmt.Errorf("[FATAL] pg_hba.conf violation: non-compliant rule detected: %s", trim)
			}
			if len(fields) >= 3 && fields[2] == "ransomeye_admin" {
				hasLocalAdmin = true
			}
		case "hostssl":
			if allowedHostSSLAllAllMTLS(fields) {
				hasAppRW = true
				hasAppRO = true
				break
			}
			if !allowedHostSSLRule(fields) {
				return fmt.Errorf("[FATAL] pg_hba.conf violation: non-compliant rule detected: %s", trim)
			}
			for _, rawDB := range strings.Split(fields[1], ",") {
				dbTok := strings.TrimSpace(rawDB)
				switch {
				case (dbTok == "ransomeye" || dbTok == dbbase.DefaultDatabase) && fields[2] == "ransomeye":
					hasAppRW = true
				case (dbTok == "ransomeye" || dbTok == dbbase.DefaultDatabase) && fields[2] == "ransomeye_readonly":
					hasAppRO = true
				}
			}
		case "host", "hostnossl", "hostgssenc", "hostnogssenc":
			if !allowedRejectHardeningRule(fields) {
				return fmt.Errorf("[FATAL] pg_hba.conf violation: non-compliant rule detected: %s (TCP must use hostssl only)", trim)
			}
		default:
			return fmt.Errorf("[FATAL] pg_hba.conf violation: non-compliant rule detected: %s", trim)
		}
	}
	if !hasLocalAdmin || !hasAppRW || !hasAppRO {
		return fmt.Errorf("[FATAL] pg_hba.conf violation: missing required allowlist rules (local admin, app rw, app ro)")
	}
	return nil
}

func allowedLocalRule(f []string) bool {
	if len(f) != 4 {
		return false
	}
	if f[0] != "local" || f[1] != "all" || f[3] != "peer" {
		return false
	}
	return f[2] == "ransomeye_admin" || f[2] == "postgres"
}

// allowedHostSSLAllAllMTLS accepts the bundled installer rule:
// hostssl all all 127.0.0.1/32 scram-sha-256 clientcert=verify-ca
func allowedHostSSLAllAllMTLS(f []string) bool {
	if len(f) < 6 {
		return false
	}
	if f[0] != "hostssl" || f[1] != "all" || f[2] != "all" || f[3] != dbbase.LoopbackHost+"/32" || f[4] != "scram-sha-256" {
		return false
	}
	for _, tok := range f[5:] {
		lt := strings.ToLower(strings.TrimSpace(tok))
		if lt == "clientcert=verify-ca" || lt == "clientcert=1" {
			return true
		}
	}
	return false
}

func hostSSLClientCertOptionsOK(extra []string) bool {
	for _, tok := range extra {
		t := strings.TrimSpace(tok)
		if t == "" {
			continue
		}
		lt := strings.ToLower(t)
		if strings.HasPrefix(lt, "clientcert=") {
			continue
		}
		return false
	}
	return true
}

func allowedHostSSLRule(f []string) bool {
	if len(f) < 5 {
		return false
	}
	if f[0] != "hostssl" {
		return false
	}
	if f[3] != dbbase.LoopbackHost+"/32" {
		return false
	}
	method := f[4]
	if method == "trust" || method == "md5" || method == "password" || method == "cert" {
		return false
	}
	if method != "scram-sha-256" {
		return false
	}
	if len(f) > 5 && !hostSSLClientCertOptionsOK(f[5:]) {
		return false
	}
	// Allow comma-separated DATABASE column when every entry is an approved Mishka DB name.
	for _, raw := range strings.Split(f[1], ",") {
		db := strings.TrimSpace(raw)
		if db != "ransomeye" && db != dbbase.DefaultDatabase && db != "ransomeye_core" {
			return false
		}
	}
	switch f[2] {
	case "ransomeye":
		return true
	case "ransomeye_readonly":
		return true
	default:
		return false
	}
}

// allowedRejectHardeningRule permits host/hostnossl only for explicit reject of all DBs/users (defence in depth).
func allowedRejectHardeningRule(f []string) bool {
	if len(f) < 5 {
		return false
	}
	method := strings.ToLower(strings.TrimSpace(f[len(f)-1]))
	if method != "reject" {
		return false
	}
	return f[1] == "all" && f[2] == "all"
}
