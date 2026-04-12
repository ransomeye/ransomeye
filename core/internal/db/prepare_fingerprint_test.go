package db

import (
	"strings"
	"testing"
)

func TestMissingFingerprintFailsPrepare(t *testing.T) {
	_, err := preparePgxConnConfig(Config{
		User:          "u",
		Database:      "d",
		SSLRootCert:   DefaultSSLRootCert,
		SSLClientCert: DefaultSSLClientCert,
		SSLClientKey:  DefaultSSLClientKey,
		TLSServerName: DefaultTLSServerName,
	})
	if err == nil {
		t.Fatal("expected error when ExpectedPostgresServerFingerprint is empty")
	}
	if !strings.Contains(err.Error(), "Missing PostgreSQL fingerprint") {
		t.Fatalf("unexpected error: %v", err)
	}
}
