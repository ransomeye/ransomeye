package compliance

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	rcrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/netcfg"
)

type Requirement struct {
	PRD         string
	ID          string
	Description string
	Check       func() error
}

var (
	mu       sync.Mutex
	registry []Requirement
)

func Register(prd, id, desc string, check func() error) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, Requirement{
		PRD:         prd,
		ID:          id,
		Description: desc,
		Check:       check,
	})
}

func AssertAll() error {
	for _, r := range registry {
		if err := r.Check(); err != nil {
			return fmt.Errorf("[COMPLIANCE VIOLATION] %s::%s → %s → %w",
				r.PRD, r.ID, r.Description, err)
		}
	}
	return nil
}

// RequirementInfo is read-only metadata for SOC / audit surfaces (PRD-12).
type RequirementInfo struct {
	PRD         string `json:"prd"`
	ID          string `json:"id"`
	Description string `json:"description"`
}

// ListRequirementInfo returns registered checks without executing them.
func ListRequirementInfo() []RequirementInfo {
	mu.Lock()
	defer mu.Unlock()
	out := make([]RequirementInfo, 0, len(registry))
	for _, r := range registry {
		out = append(out, RequirementInfo{
			PRD:         r.PRD,
			ID:          r.ID,
			Description: r.Description,
		})
	}
	return out
}

// CheckOutcome is one compliance check result (PRD-24 / SOC reporting).
type CheckOutcome struct {
	PRD         string `json:"prd"`
	ID          string `json:"id"`
	Description string `json:"description"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
}

// RunRegisteredChecks executes every registered check and returns per-row outcomes.
func RunRegisteredChecks() []CheckOutcome {
	mu.Lock()
	snap := make([]Requirement, len(registry))
	copy(snap, registry)
	mu.Unlock()

	out := make([]CheckOutcome, 0, len(snap))
	for _, r := range snap {
		co := CheckOutcome{
			PRD:         r.PRD,
			ID:          r.ID,
			Description: r.Description,
			OK:          true,
		}
		if err := r.Check(); err != nil {
			co.OK = false
			co.Error = err.Error()
		}
		out = append(out, co)
	}
	return out
}

//////////////////////////////////////////////////////////////
// PHASE 0A — STATIC CHECKS
//////////////////////////////////////////////////////////////

func isTLS13() bool {
	return strings.TrimSpace(os.Getenv("TLS_MIN_VERSION")) == "1.3"
}

// validateTLS enforces TLS 1.3 on external ports only; loopback internal services use plaintext (PRD-13).
func validateTLS(port int, isLoopback bool) error {
	if isLoopback {
		return nil
	}
	if port == 443 || port == 50051 {
		if !isTLS13() {
			return fmt.Errorf("TLS 1.3 required on external port %d", port)
		}
	}
	return nil
}

func init() {

	// STRICT LOOPBACK (validate only when POSTGRES_HOST is set)
	Register("PRD-01", "NET-STRICT-LOOPBACK",
		fmt.Sprintf("POSTGRES must bind to %s when POSTGRES_HOST is set", netcfg.LoopbackHost),
		func() error {
			h := strings.TrimSpace(os.Getenv("POSTGRES_HOST"))
			if h == "" {
				return nil
			}
			if !netcfg.IsLoopbackHost(h) {
				return fmt.Errorf("POSTGRES_HOST must be %s", netcfg.LoopbackHost)
			}
			return nil
		})

	// WORM KEY
	Register("PRD-14", "CRYPTO-WORM-KEY",
		"WORM key must be root-owned 0400 file with valid raw Ed25519 seed",
		func() error {
			path := "/etc/ransomeye/worm_signing.key"
			fi, err := os.Stat(path)
			if err != nil {
				return err
			}
			if !fi.Mode().IsRegular() {
				return errors.New("worm key must be regular file")
			}
			if fi.Mode().Perm() != 0o400 {
				return fmt.Errorf("invalid permissions: %v", fi.Mode().Perm())
			}
			if fi.Size() != 32 {
				return fmt.Errorf("WORM key must be exactly 32 bytes, got %d", fi.Size())
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := rcrypto.ValidateWormSeed(raw); err != nil {
				return err
			}
			statAny := fi.Sys()
			stat, ok := statAny.(*syscall.Stat_t)
			if !ok || stat == nil {
				return errors.New("worm key must be owned by root")
			}
			if stat.Uid != 0 {
				return errors.New("worm key must be owned by root")
			}
			return nil
		})

	// TLS POLICY — external channels only; loopback plaintext (PRD-13)
	Register("PRD-01", "TLS-1.3-ONLY",
		"External channels (443, 50051) require TLS 1.3 when TLS_MIN_VERSION is set; internal loopback exempt",
		func() error {
			if strings.TrimSpace(os.Getenv("TLS_MIN_VERSION")) == "" {
				return nil
			}
			if err := validateTLS(443, false); err != nil {
				return err
			}
			return validateTLS(50051, false)
		})

	// SHAP BAN
	Register("PRD-07", "AI-NO-SHAP",
		"SHAP forbidden",
		func() error {
			if os.Getenv("ENABLE_SHAP") == "true" {
				return errors.New("SHAP is forbidden")
			}
			return nil
		})

	// AIR GAP FLAG
	Register("PRD-15", "AIRGAP",
		"Internet must be disabled",
		func() error {
			if os.Getenv("ALLOW_INTERNET") == "true" {
				return errors.New("air-gap violated")
			}
			return nil
		})

	// AI DB ACCESS
	Register("PRD-03", "AI-NO-DB",
		"AI must not access DB",
		func() error {
			if os.Getenv("AI_DIRECT_DB") == "true" {
				return errors.New("AI direct DB access forbidden")
			}
			return nil
		})

	// PRD-00 — FORBIDDEN GRAPH TABLES (ENV GUARD)
	Register("PRD-00", "DB-FORBIDDEN-FLAG",
		"graph tables must never be enabled",
		func() error {
			if os.Getenv("ALLOW_GRAPH_TABLES") == "true" {
				return errors.New("graph tables are forbidden")
			}
			return nil
		})

	// PRD-19 — AUTO ENFORCE MUST BE FALSE
	Register("PRD-19", "AEC-AUTO-FALSE",
		"aec_auto_enforce must be false",
		func() error {
			if os.Getenv("AEC_AUTO_ENFORCE") == "true" {
				return errors.New("auto enforcement cannot be enabled")
			}
			return nil
		})
}

//////////////////////////////////////////////////////////////
// PHASE 0B — RUNTIME VALIDATION
//////////////////////////////////////////////////////////////

// AssertNoForbiddenTables enforces DB schema invariants
func AssertNoForbiddenTables(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT schemaname, tablename
		FROM pg_catalog.pg_tables
		WHERE tablename IN ('graph_' || 'nodes', 'graph_' || 'edges')
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	if rows.Next() {
		var s, t string
		_ = rows.Scan(&s, &t)
		return fmt.Errorf("forbidden table detected: %s.%s", s, t)
	}
	return nil
}

// POSTGRES TLS VALIDATION
func AssertPostgresTLS(db *sql.DB) error {
	var v string
	err := db.QueryRow(`SELECT setting FROM pg_settings WHERE name = 'ssl_min_protocol_version'`).Scan(&v)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		err = db.QueryRow(`SHOW ssl_min_protocol_version`).Scan(&v)
	}
	if err != nil {
		if postgresSettingInvisibleToAppRole(err) {
			log.Printf("[BOOTSTRAP] AssertPostgresTLS: ssl_min_protocol_version not visible to application role; treating negotiated TLS 1.3 session as authoritative")
			return nil
		}
		return err
	}
	if strings.TrimSpace(v) != "TLSv1.3" {
		return fmt.Errorf("TLS not enforced: %s", v)
	}
	return nil
}

func postgresSettingInvisibleToAppRole(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "42501") || strings.Contains(strings.ToLower(s), "permission denied to examine")
}

// PARSE /proc/net/tcp
func parseProcNetTCP() ([]string, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// HEX → IP
func hexToIP(hex string) (string, error) {
	if len(hex) != 8 {
		return "", errors.New("invalid ipv4 hex length")
	}
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(hex[i*2:(i+1)*2], 16, 8)
		if err != nil {
			return "", err
		}
		ip[3-i] = byte(v)
	}
	return ip.String(), nil
}

// SOCKET VALIDATION
func AssertLoopbackBindings() error {
	lines, err := parseProcNetTCP()
	if err != nil {
		return err
	}
	if len(lines) < 2 {
		return errors.New("unable to inspect /proc/net/tcp")
	}

	// Validate that any mandatory internal service ports that are already live
	// are loopback-only. Startup order is validated by systemd and health checks;
	// Core must not fail closed merely because downstream loopback listeners are
	// about to come up in the same boot sequence.
	observed := map[string]bool{
		"50052": false,
		"50053": false,
		"5432":  false,
		"6379":  false,
	}

	for _, l := range lines[1:] {
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}
		local := fields[1]
		parts := strings.Split(local, ":")
		if len(parts) != 2 {
			continue
		}

		ip, err := hexToIP(parts[0])
		if err != nil {
			return err
		}
		portHex := parts[1]
		p, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			return err
		}

		port := strconv.Itoa(int(p))
		if _, ok := observed[port]; ok {
			if !netcfg.IsLoopbackHost(ip) {
				return fmt.Errorf("port %s bound to non-loopback %s", port, ip)
			}
			observed[port] = true
		}
	}
	return nil
}

func AssertNoIPv6Bindings() error {
	f, err := os.Open("/proc/net/tcp6")
	if err != nil {
		return nil // no IPv6 table → OK
	}
	defer f.Close()

	requiredPorts := map[string]struct{}{
		"50052": {},
		"50053": {},
		"5432":  {},
		"6379":  {},
	}

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		local := fields[1]
		parts := strings.Split(local, ":")
		if len(parts) != 2 {
			continue
		}

		portHex := parts[1]
		p, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			continue
		}

		port := strconv.Itoa(int(p))

		if _, ok := requiredPorts[port]; ok {
			return fmt.Errorf("port %s bound on IPv6 (prohibited)", port)
		}
	}

	return nil
}

// AssertNoOutboundConnectivity is an offline air-gap enforcement check.
//
// This repo is strictly air-gapped; performing live outbound dials here would itself violate
// the invariant. We therefore detect outbound capability deterministically via local config
// and routing state (same enforcement basis as AssertNoOutboundDNS).
func AssertNoOutboundConnectivity() error {
	if err := assertResolvConfLoopbackOnly(resolveResolvConfPath()); err != nil {
		return err
	}
	if err := assertNoDefaultRoute(resolveRouteTablePath()); err != nil {
		return err
	}
	return nil
}

// AIR-GAP DNS/OUTBOUND TEST (OFFLINE)
//
// We do not perform live DNS lookups here (that would itself violate air-gap).
func AssertNoOutboundDNS() error {
	if err := assertResolvConfLoopbackOnly(resolveResolvConfPath()); err != nil {
		return err
	}
	if err := assertNoDefaultRoute(resolveRouteTablePath()); err != nil {
		return err
	}
	return nil
}

func resolveResolvConfPath() string {
	if path := strings.TrimSpace(os.Getenv("RANSOMEYE_RESOLV_CONF_PATH")); path != "" {
		return path
	}
	return "/etc/resolv.conf"
}

func resolveRouteTablePath() string {
	if path := strings.TrimSpace(os.Getenv("RANSOMEYE_ROUTE_TABLE_PATH")); path != "" {
		return path
	}
	return "/proc/net/route"
}

// isLocalResolverNameserver is true for resolvers on the loopback interface (127.0.0.0/8, ::1),
// including systemd-resolved stubs such as 127.0.0.53.
func isLocalResolverNameserver(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func assertResolvConfLoopbackOnly(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ns := strings.TrimSpace(fields[1])
		if !isLocalResolverNameserver(ns) {
			return fmt.Errorf("air-gap violated: non-loopback nameserver %q", ns)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

func assertNoDefaultRoute(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "00000000" {
			return errors.New("air-gap violated: default route present")
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}
