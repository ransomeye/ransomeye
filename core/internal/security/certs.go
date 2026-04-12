package security

import (
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"

	coreconfig "ransomeye/core/internal/config"
)

const canonicalServerCertPath = "/etc/ransomeye/server.crt"

// ResolveCoreServerCertPath selects the Core server certificate path. In dev mode, falls back to
// configs/server.crt (+ configs/server.key presence) when the canonical /etc path is unavailable
// or unreadable. Production always uses the canonical path only.
func ResolveCoreServerCertPath(devMode bool) (certPath, keyPath string, err error) {
	certPath = canonicalServerCertPath
	keyPath = ""
	if devMode {
		needFallback := false
		if _, err := os.Stat(certPath); err != nil {
			needFallback = true
		} else if _, err := os.ReadFile(certPath); err != nil {
			needFallback = true
		}
		if needFallback {
			log.Println("[DEV MODE] using local development certificate")
			certPath = "configs/server.crt"
			keyPath = "configs/server.key"
			if _, err := os.Stat(certPath); err != nil {
				return "", "", fmt.Errorf("dev cert missing: %w", err)
			}
			if _, err := os.Stat(keyPath); err != nil {
				return "", "", fmt.Errorf("dev key missing: %w", err)
			}
			return certPath, keyPath, nil
		}
	}
	if !devMode && certPath != canonicalServerCertPath {
		log.Fatalf("[FATAL] non-canonical certificate path in production")
	}
	return certPath, keyPath, nil
}

// VerifyCoreServerCertificateAttestation validates server.crt against the fingerprint in signed
// config. In dev mode with a local configs/ certificate, only PEM well-formedness is checked so
// development can proceed without re-signing common.yaml for every generated cert.
func VerifyCoreServerCertificateAttestation(devMode bool, certPath, expectedFingerprint string) error {
	if devMode && strings.HasPrefix(certPath, "configs/") {
		raw, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return fmt.Errorf("parse %s: no PEM certificate found", certPath)
		}
		log.Println("[DEV MODE] server certificate PEM validated (fingerprint attestation relaxed for local dev cert)")
		return nil
	}
	return coreconfig.VerifyServerCertificateFile(certPath, expectedFingerprint)
}
