package db

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// VerifyTLSConnectionState enforces handshake completion, TLS 1.3, and presence of a server leaf (fail-closed).
func VerifyTLSConnectionState(conn *tls.Conn) error {
	if conn == nil {
		return fmt.Errorf("[FATAL] TLS violation: nil connection")
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		return fmt.Errorf("[FATAL] TLS handshake incomplete")
	}
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("[FATAL] TLS violation: expected TLS1.3, got %x", state.Version)
	}
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("[FATAL] no peer certificate")
	}
	return nil
}

// VerifyPostgresServerLeafFingerprint compares the SHA-256 of the server leaf DER to the configured fingerprint (64-char lowercase hex).
func VerifyPostgresServerLeafFingerprint(state tls.ConnectionState, expectedFingerprintHex string) error {
	expected := strings.ToLower(strings.TrimSpace(expectedFingerprintHex))
	if expected == "" {
		return fmt.Errorf("PostgreSQL expected server fingerprint not configured")
	}
	if len(expected) != 64 {
		return fmt.Errorf("invalid expected PostgreSQL server fingerprint (want 64 hex chars)")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return fmt.Errorf("invalid expected PostgreSQL server fingerprint: %w", err)
	}
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificate presented")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("PostgreSQL certificate fingerprint mismatch")
	}
	return nil
}

// VerifyServerLeafSAN requires the PostgreSQL server leaf to include exact loopback IP SAN and forbids other IP SANs and wildcard DNS SANs.
func VerifyServerLeafSAN(state *tls.ConnectionState) error {
	if state == nil {
		return fmt.Errorf("[FATAL] TLS SAN violation: nil connection state")
	}
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("[FATAL] TLS SAN violation: no peer certificates")
	}
	leaf := certs[0]
	want4 := net.IPv4(127, 0, 0, 1)
	for _, name := range leaf.DNSNames {
		if name == "" {
			continue
		}
		if strings.Contains(name, "*") {
			return fmt.Errorf("[FATAL] PostgreSQL cert SAN violation: wildcard DNS SAN %q forbidden", name)
		}
		if name != LoopbackHost {
			return fmt.Errorf("[FATAL] PostgreSQL cert SAN violation: unexpected DNS SAN %q", name)
		}
	}
	var sawLoopbackIP bool
	for _, ip := range leaf.IPAddresses {
		if ip4 := ip.To4(); ip4 != nil && ip4.Equal(want4) {
			sawLoopbackIP = true
			continue
		}
		if len(ip) > 0 {
			return fmt.Errorf("[FATAL] PostgreSQL cert SAN violation: unexpected IP SAN %s", ip)
		}
	}
	if !sawLoopbackIP {
		return fmt.Errorf("[FATAL] PostgreSQL cert SAN violation: %s missing", LoopbackHost)
	}
	return nil
}
