// enrollment_append_record: append one canonical enrollment registry record (PRD-04) signed by enrollment authority.
// Usage (root): go run . <agent_uuid> <leaf_cert.pem> <system_identity_hash_hex> <enrollment_authority_pkcs8.pem>
// Prints one JSON object line to add inside "records":[...] (no trailing comma handling).
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

const signingCtx = "ransomeye:v1:identity:agent_enrollment"

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: enrollment_append_record <agent_uuid> <leaf_cert.pem> <system_identity_hash_hex> <enrollment_authority.key.pem>")
		os.Exit(2)
	}
	agentID := strings.TrimSpace(os.Args[1])
	certPEM, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sysHash := strings.ToLower(strings.TrimSpace(os.Args[3]))
	keyPEM, err := os.ReadFile(os.Args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Fprintln(os.Stderr, "cert PEM")
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fp := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fp[:])

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		fmt.Fprintln(os.Stderr, "key PEM")
		os.Exit(1)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		fmt.Fprintln(os.Stderr, "want Ed25519 private key")
		os.Exit(1)
	}

	// Must match identity.canonicalEnrollmentRecordBytes (no signature field).
	payload := fmt.Sprintf(`{"agent_id":%q,"cert_fingerprint":%q,"system_identity_hash":%q}`,
		agentID, fpHex, sysHash)
	sum := sha256.Sum256([]byte(payload))
	signingInput := make([]byte, 0, len(signingCtx)+sha256.Size)
	signingInput = append(signingInput, []byte(signingCtx)...)
	signingInput = append(signingInput, sum[:]...)
	sig := ed25519.Sign(priv, signingInput)

	out := fmt.Sprintf(`{"agent_id":%q,"cert_fingerprint":%q,"system_identity_hash":%q,"signature":%q}`,
		agentID, fpHex, sysHash, hex.EncodeToString(sig))
	fmt.Print(out)
}
