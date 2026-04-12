package db

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestFingerprintMismatch(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("fake-leaf-bytes")}
	st := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	}
	err := VerifyPostgresServerLeafFingerprint(st, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
}
