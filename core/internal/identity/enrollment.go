package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	coreconfig "ransomeye/core/internal/config"
)

// EnrollmentRecord is a single installer-issued agent binding (PRD-04 §3.2, §9.2).
type EnrollmentRecord struct {
	AgentID            uuid.UUID
	CertFingerprint    [32]byte
	SystemIdentityHash [32]byte
	Signature          []byte
}

const (
	enrollmentSigningContext   = "ransomeye:v1:identity:agent_enrollment"
	enrollmentRegistryPath     = "/etc/ransomeye/enrollment/registry.json"
	enrollmentAuthorityPubPath = "/etc/ransomeye/pki/enrollment_authority.pub"
)

type enrollmentFile struct {
	Records []enrollmentRecordWire `json:"records"`
}

type enrollmentRecordWire struct {
	AgentID            string `json:"agent_id"`
	CertFingerprint    string `json:"cert_fingerprint"`
	SystemIdentityHash string `json:"system_identity_hash"`
	Signature          string `json:"signature"`
}

// canonicalEnrollmentRecordBytes is deterministic JSON for PRD-02 signing input (excludes signature).
func canonicalEnrollmentRecordBytes(agentID string, certFPHex, sysIDHex string) []byte {
	s := fmt.Sprintf(`{"agent_id":%q,"cert_fingerprint":%q,"system_identity_hash":%q}`,
		agentID, strings.ToLower(strings.TrimSpace(certFPHex)), strings.ToLower(strings.TrimSpace(sysIDHex)))
	return []byte(s)
}

// VerifyEnrollment loads the signed enrollment registry, verifies each record's Ed25519 signature
// per PRD-02 (signing_context || SHA-256(canonical_payload_bytes)), resolves agentID, compares
// the presented leaf fingerprint, and compares record system_identity_hash to the
// verified signed config in memory. Any failure is fail-closed.
func VerifyEnrollment(agentID uuid.UUID, certFingerprint [32]byte) error {
	pub, err := loadEnrollmentAuthorityPublicKey()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(enrollmentRegistryPath)
	if err != nil {
		return fmt.Errorf("enrollment registry: %w", err)
	}
	wires, err := deriveAndVerifyRecordWires(raw, pub)
	if err != nil {
		return err
	}
	runtimeHash, err := loadRuntimeSystemIdentityHashFromSignedConfig()
	if err != nil {
		return err
	}
	wantID := strings.ToLower(agentID.String())
	for _, w := range wires {
		recID := strings.ToLower(strings.TrimSpace(w.AgentID))
		if recID != wantID {
			continue
		}
		rec, err := wireToRecord(w)
		if err != nil {
			return err
		}
		if rec.CertFingerprint != certFingerprint {
			return errors.New("enrollment cert_fingerprint mismatch")
		}
		if rec.SystemIdentityHash != runtimeHash {
			return errors.New("enrollment system_identity_hash mismatch")
		}
		return nil
	}
	return errors.New("enrollment record not found for agent_id")
}

var canonicalRecordRegex = regexp.MustCompile(`^\{"agent_id":"([0-9a-f\-]{36})","cert_fingerprint":"([0-9a-f]{64})","system_identity_hash":"([0-9a-f]{64})","signature":"([0-9a-f]{128})"\}$`)

func deriveAndVerifyRecordWires(raw []byte, pub ed25519.PublicKey) ([]enrollmentRecordWire, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("enrollment registry must be UTF-8")
	}
	// Canonical JSON invariants for this artifact class: no whitespace and integer-only.
	if bytes.ContainsAny(raw, " \t\r\n") {
		return nil, errors.New("enrollment registry non-canonical whitespace")
	}

	text := string(raw)
	if !strings.HasPrefix(text, `{"records":[`) || !strings.HasSuffix(text, `]}`) {
		return nil, errors.New("enrollment registry invalid root shape")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(text, `{"records":[`), `]}`)
	if body == "" {
		return []enrollmentRecordWire{}, nil
	}
	parts := splitTopLevelObjects(body)
	out := make([]enrollmentRecordWire, 0, len(parts))
	for _, obj := range parts {
		m := canonicalRecordRegex.FindStringSubmatch(obj)
		if len(m) != 5 {
			return nil, errors.New("enrollment record non-canonical form")
		}
		agentID := m[1]
		certFP := m[2]
		sysID := m[3]
		sigHex := m[4]
		payload := canonicalEnrollmentRecordBytes(agentID, certFP, sysID)
		sum := sha256.Sum256(payload)
		signingInput := make([]byte, 0, len(enrollmentSigningContext)+sha256.Size)
		signingInput = append(signingInput, []byte(enrollmentSigningContext)...)
		signingInput = append(signingInput, sum[:]...)
		sig, err := hex.DecodeString(sigHex)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, errors.New("enrollment signature invalid")
		}
		if !ed25519.Verify(pub, signingInput, sig) {
			return nil, errors.New("enrollment record signature verification failed")
		}
		out = append(out, enrollmentRecordWire{
			AgentID:            agentID,
			CertFingerprint:    certFP,
			SystemIdentityHash: sysID,
			Signature:          sigHex,
		})
	}
	return out, nil
}

func splitTopLevelObjects(body string) []string {
	var out []string
	start := 0
	depth := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				out = append(out, body[start:i+1])
			}
		}
	}
	return out
}

func loadEnrollmentAuthorityPublicKey() (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(enrollmentAuthorityPubPath)
	if err != nil {
		return nil, fmt.Errorf("enrollment authority public key: %w", err)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, errors.New("enrollment authority public key must be 32 raw bytes")
}

func loadRuntimeSystemIdentityHashFromSignedConfig() ([32]byte, error) {
	var out [32]byte
	cfg, err := coreconfig.LoadVerifiedCommonConfig(coreconfig.InstalledCommonConfigPath, coreconfig.IntermediateCACertPath)
	if err != nil {
		return out, fmt.Errorf("verified signed config: %w", err)
	}
	canonicalConfigBytes, err := coreconfig.CanonicalIdentityJSONBytes(cfg)
	if err != nil {
		return out, fmt.Errorf("canonical config: %w", err)
	}
	rootCAPEM, err := os.ReadFile(cfg.Security.CACertPath)
	if err != nil {
		return out, fmt.Errorf("root CA: %w", err)
	}
	rootCABlock, _ := pem.Decode(rootCAPEM)
	if rootCABlock == nil {
		return out, errors.New("root CA PEM block missing")
	}
	dbFingerprint, err := hex.DecodeString(strings.TrimSpace(cfg.Database.ExpectedServerFingerprint))
	if err != nil || len(dbFingerprint) != 32 {
		return out, errors.New("database fingerprint invalid")
	}
	wormPub, err := os.ReadFile("/etc/ransomeye/worm_signing.pub")
	if err != nil {
		return out, fmt.Errorf("worm public key: %w", err)
	}
	if len(wormPub) != ed25519.PublicKeySize {
		return out, errors.New("worm public key invalid")
	}
	rootFingerprint := sha256.Sum256(rootCABlock.Bytes)
	mat := make([]byte, 0, len(canonicalConfigBytes)+len(rootFingerprint)+len(dbFingerprint)+len(wormPub))
	mat = append(mat, canonicalConfigBytes...)
	mat = append(mat, rootFingerprint[:]...)
	mat = append(mat, dbFingerprint...)
	mat = append(mat, wormPub...)
	sum := sha256.Sum256(mat)
	copy(out[:], sum[:])
	return out, nil
}

func wireToRecord(w enrollmentRecordWire) (EnrollmentRecord, error) {
	var rec EnrollmentRecord
	id, err := uuid.Parse(strings.TrimSpace(w.AgentID))
	if err != nil {
		return rec, fmt.Errorf("enrollment agent_id: %w", err)
	}
	rec.AgentID = id
	cfp, err := hex.DecodeString(strings.TrimSpace(w.CertFingerprint))
	if err != nil || len(cfp) != 32 {
		return rec, errors.New("enrollment cert_fingerprint invalid")
	}
	copy(rec.CertFingerprint[:], cfp)
	sih, err := hex.DecodeString(strings.TrimSpace(w.SystemIdentityHash))
	if err != nil || len(sih) != 32 {
		return rec, errors.New("enrollment system_identity_hash invalid")
	}
	copy(rec.SystemIdentityHash[:], sih)
	sig, err := hex.DecodeString(strings.TrimSpace(w.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return rec, errors.New("enrollment signature invalid")
	}
	rec.Signature = sig
	return rec, nil
}

func verifyEnrollmentRecordSignature(pub ed25519.PublicKey, rec EnrollmentRecord) error {
	agentStr := strings.ToLower(rec.AgentID.String())
	canon := canonicalEnrollmentRecordBytes(agentStr, hex.EncodeToString(rec.CertFingerprint[:]), hex.EncodeToString(rec.SystemIdentityHash[:]))
	sum := sha256.Sum256(canon)
	signingInput := make([]byte, 0, len(enrollmentSigningContext)+sha256.Size)
	signingInput = append(signingInput, []byte(enrollmentSigningContext)...)
	signingInput = append(signingInput, sum[:]...)
	if !ed25519.Verify(pub, signingInput, rec.Signature) {
		return errors.New("enrollment record signature verification failed")
	}
	return nil
}
