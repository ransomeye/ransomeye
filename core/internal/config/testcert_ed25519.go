package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// MustEd25519SelfSignedCertForTest returns a minimal self-signed CA cert carrying pub for VerifyCommonConfig tests.
func MustEd25519SelfSignedCertForTest(t testing.TB, pub ed25519.PublicKey, priv ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mishka-test-config-signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// PEMEd25519SelfSignedCertForTest returns PEM bytes for tests that need a file path.
func PEMEd25519SelfSignedCertForTest(t testing.TB, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
	t.Helper()
	cert := MustEd25519SelfSignedCertForTest(t, pub, priv)
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return b
}
