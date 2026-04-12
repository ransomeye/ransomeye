package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	WormSigningKeyPath = "/etc/ransomeye/worm_signing.key"

	pemRejectPrefix = "-----BEGIN"

	aesKeySize   = 32
	gcmNonceSize = 12
)

// ResolveWormSigningKeyPath returns the canonical path, or RANSOMEYE_WORM_SIGNING_KEY_PATH when RANSOMEYE_DEV_MODE=true (tests only).
func ResolveWormSigningKeyPath() string {
	if os.Getenv("RANSOMEYE_DEV_MODE") == "true" {
		if p := strings.TrimSpace(os.Getenv("RANSOMEYE_WORM_SIGNING_KEY_PATH")); p != "" {
			return p
		}
	}
	return WormSigningKeyPath
}

func validateWormSeed(raw []byte, rejectWeak bool) error {
	if len(raw) != ed25519.SeedSize {
		return fmt.Errorf("WORM key must be exactly %d bytes (raw Ed25519 seed)", ed25519.SeedSize)
	}
	if bytes.HasPrefix(raw, []byte(pemRejectPrefix)) {
		return fmt.Errorf("WORM key must be raw bytes only (PEM-like prefix rejected)")
	}
	if rejectWeak && isWeakWormSeed(raw) {
		return fmt.Errorf("WORM key rejected: weak or predictable seed pattern")
	}
	return nil
}

// ValidateWormSeed rejects PEM-shaped blobs, weak test patterns, and non-32-byte inputs.
func ValidateWormSeed(raw []byte) error {
	return validateWormSeed(raw, true)
}

func isWeakWormSeed(seed []byte) bool {
	if len(seed) != ed25519.SeedSize {
		return true
	}
	allSame := true
	for i := 1; i < len(seed); i++ {
		if seed[i] != seed[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}
	seq0 := true
	for i := 0; i < len(seed); i++ {
		if seed[i] != byte(i) {
			seq0 = false
			break
		}
	}
	if seq0 {
		return true
	}
	seq1 := true
	for i := 0; i < len(seed); i++ {
		if seed[i] != byte(i+1) {
			seq1 = false
			break
		}
	}
	return seq1
}

// WormSigningKeyMaterialOK is true iff the resolved key file is readable and passes ValidateWormSeed (runtime health).
func WormSigningKeyMaterialOK() bool {
	_, err := readValidatedWormSeed(ResolveWormSigningKeyPath(), os.Getenv("RANSOMEYE_DEV_MODE") != "true")
	return err == nil
}

type WORM struct {
	signingKey ed25519.PrivateKey
	aesKey     [aesKeySize]byte
}

func validateWormKeyMetadata(fi os.FileInfo, requireRootOwner bool) error {
	if fi == nil {
		return fmt.Errorf("WORM signing key metadata missing")
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("WORM signing key is not a regular file")
	}
	if fi.Mode().Perm() != 0o400 {
		return fmt.Errorf("WORM signing key permissions must be exactly 0400")
	}
	if requireRootOwner {
		if err := validateRootOwner(fi); err != nil {
			return err
		}
	}
	return nil
}

func readValidatedWormSeed(path string, requireRootOwner bool) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("WORM signing key missing at %s: %w", path, err)
	}
	if err := validateWormKeyMetadata(fi, requireRootOwner); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("WORM signing key read failed: %w", err)
	}
	if err := validateWormSeed(raw, requireRootOwner); err != nil {
		return nil, err
	}
	return raw, nil
}

// ReadValidatedWormSeed enforces raw-seed format and exact 0400 permissions.
// Callers operating on the canonical production key path should also require root ownership.
func ReadValidatedWormSeed(path string, requireRootOwner bool) ([]byte, error) {
	return readValidatedWormSeed(path, requireRootOwner)
}

// MustLoadSigningKey loads the Ed25519 signing key from /etc/ransomeye/worm_signing.key
// (or RANSOMEYE_WORM_SIGNING_KEY_PATH when RANSOMEYE_DEV_MODE=true).
// Fail-closed: any error results in log.Fatalf.
func MustLoadSigningKey() ed25519.PrivateKey {
	keyPath := ResolveWormSigningKeyPath()
	if os.Getenv("RANSOMEYE_DEV_MODE") != "true" && keyPath != WormSigningKeyPath {
		log.Fatalf("[FATAL] non-canonical WORM key path in production")
	}
	raw, err := readValidatedWormSeed(keyPath, os.Getenv("RANSOMEYE_DEV_MODE") != "true")
	if err != nil {
		log.Fatalf("[FATAL] WORM signing key invalid: %v", err)
	}
	return ed25519.NewKeyFromSeed(raw)
}

// NewWORM constructs a WORM crypto module.
// aesKey must be 32 bytes (AES-256).
func NewWORM(signingKey ed25519.PrivateKey, aesKey []byte) (*WORM, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size: %d", len(signingKey))
	}
	if len(aesKey) != aesKeySize {
		return nil, fmt.Errorf("invalid AES-256 key size: %d", len(aesKey))
	}
	var k [aesKeySize]byte
	copy(k[:], aesKey)
	return &WORM{
		signingKey: signingKey,
		aesKey:     k,
	}, nil
}

// EncryptEvidence encrypts payload using AES-256-GCM.
// A fresh 12-byte CSPRNG nonce is generated per call.
func (w *WORM) EncryptEvidence(payload []byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(w.aesKey[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	// Seal appends tag to ciphertext; no AAD in V0.0 for raw payload sealing.
	ciphertext = gcm.Seal(nil, nonce, payload, nil)
	return ciphertext, nonce, nil
}

// SignEvidence computes an Ed25519 signature over a digest that includes agent_id, event_id, event_type.
// Digest: SHA-256( agentID || 0x00 || eventID || 0x00 || eventType || 0x00 || logicalClock(be) || 0x00 || payload )
// Reproducible across versions.
func (w *WORM) SignEvidence(payload []byte, logicalClock int64, agentID, eventID, eventType string) ([]byte, error) {
	sum := evidenceDigest(payload, logicalClock, agentID, eventID, eventType)
	sig := ed25519.Sign(w.signingKey, sum)
	return sig, nil
}

// evidenceDigest returns SHA-256( agentID || 0x00 || eventID || 0x00 || eventType || 0x00 || logicalClock(be) || 0x00 || payload ).
func evidenceDigest(payload []byte, logicalClock int64, agentID, eventID, eventType string) []byte {
	h := sha256.New()
	h.Write([]byte(agentID))
	h.Write([]byte{0x00})
	h.Write([]byte(eventID))
	h.Write([]byte{0x00})
	h.Write([]byte(eventType))
	h.Write([]byte{0x00})
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(logicalClock))
	h.Write(b[:])
	h.Write([]byte{0x00})
	h.Write(payload)
	return h.Sum(nil)
}

// VerifyEvidence verifies an Ed25519 signature over the same digest as SignEvidence.
// Use before DB insert; reject invalid events (fail closed).
func (w *WORM) VerifyEvidence(payload []byte, logicalClock int64, agentID, eventID, eventType string, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	pub, ok := w.signingKey.Public().(ed25519.PublicKey)
	if !ok {
		return false
	}
	sum := evidenceDigest(payload, logicalClock, agentID, eventID, eventType)
	return ed25519.Verify(pub, sum, sig)
}

// PublicKey returns the Ed25519 public half of the WORM signing key.
func (w *WORM) PublicKey() ed25519.PublicKey {
	pub, _ := w.signingKey.Public().(ed25519.PublicKey)
	return pub
}

// SignChainedMerkleDigest signs a 32-byte intraday Merkle chained digest (see ComputeChainedRoot).
func (w *WORM) SignChainedMerkleDigest(digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("chained merkle digest must be 32 bytes")
	}
	return ed25519.Sign(w.signingKey, digest), nil
}

// VerifyChainedMerkleDigest verifies SignChainedMerkleDigest.
func (w *WORM) VerifyChainedMerkleDigest(digest, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize || len(digest) != sha256.Size {
		return false
	}
	return ed25519.Verify(w.PublicKey(), digest, sig)
}

func HashLeaf(content []byte) []byte {
	sum := sha256.Sum256(content)
	return sum[:]
}

// ComputeChainedRoot returns H(prevRoot || currentRoot). Used to extend and verify the Merkle chain.
func ComputeChainedRoot(prevRoot, currentRoot []byte) []byte {
	combined := make([]byte, 0, len(prevRoot)+len(currentRoot))
	combined = append(combined, prevRoot...)
	combined = append(combined, currentRoot...)
	return HashLeaf(combined)
}

func VerifyChainedRoot(prevRoot, currentRoot, finalRoot []byte) bool {
	combined := make([]byte, 0, len(prevRoot)+len(currentRoot))
	combined = append(combined, prevRoot...)
	combined = append(combined, currentRoot...)

	expected := HashLeaf(combined)

	if len(expected) != len(finalRoot) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, finalRoot) == 1
}

// VerifyRoot verifies an Ed25519 signature over the given root.
func VerifyRoot(root []byte, sig []byte, pub ed25519.PublicKey) bool {
	return ed25519.Verify(pub, root, sig)
}

// ConstantTimeEqual returns true iff a and b have the same length and content (constant-time).
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
