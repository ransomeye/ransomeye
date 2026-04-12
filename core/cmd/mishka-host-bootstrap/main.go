// mishka-host-bootstrap: provision canonical CONFIG/trust_snapshot v1 for host acceptance (Postgres + env hints).
//
// Usage (after fresh DB migrations, with POSTGRES_DSN set for mTLS):
//
//	go run ./core/cmd/mishka-host-bootstrap
//
// Prints JSON lines for /etc/ransomeye/core.env append: AUTHORITY_BINDINGS, optional SNAPSHOTS, EXECUTION_CONTEXT_HASH.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"ransomeye/core/internal/storage/authority"
)

func deriveKeyID(keyType, scopeID string, keyEpoch int64, pub ed25519.PublicKey) string {
	h := sha256.New()
	_, _ = h.Write([]byte(keyType))
	_, _ = h.Write([]byte(scopeID))
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], uint64(keyEpoch))
	_, _ = h.Write(be[:])
	_, _ = h.Write(pub)
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	dsn := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "POSTGRES_DSN required")
		os.Exit(2)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer pool.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	agentID := strings.TrimSpace(os.Getenv("MISHKA_BOOTSTRAP_AGENT_UUID"))
	if agentID == "" {
		// Deterministic lab agent UUID used across gateway tests (stable host reprovision).
		agentID = "11111111-1111-4111-8111-111111111111"
	}
	agentParsed, err := uuid.Parse(agentID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent uuid:", err)
		os.Exit(1)
	}
	emitterIDHex := hex.EncodeToString(agentParsed[:])

	const trustVersion = "v1"
	keyEpoch := int64(1)
	keyRecordSigningContext := "key_record_v1"
	keyID := deriveKeyID("AGENT", emitterIDHex, keyEpoch, pub)

	recordPayload := map[string]any{
		"allowed_signing_contexts": []any{"ransomeye:v1:telemetry:event", "config_snapshot_v1", keyRecordSigningContext, "trust_snapshot_v1"},
		"authority_scope":          "emitter",
		"issuer_key_id":            keyID,
		"key_epoch":                keyEpoch,
		"key_id":                   keyID,
		"key_type":                 "AGENT",
		"public_key":               hex.EncodeToString(pub),
		"scope_id":                 emitterIDHex,
		"signing_context":          keyRecordSigningContext,
		"status":                   "ACTIVE",
	}
	canonicalKeyRecordPayload, err := authority.JCSCanonicalJSONBytes(recordPayload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	keyRecordHash := sha256.Sum256(canonicalKeyRecordPayload)
	keyRecordSigningInput := append([]byte(keyRecordSigningContext), keyRecordHash[:]...)
	keyRecordSignature := ed25519.Sign(priv, keyRecordSigningInput)
	keyRecord := map[string]any{
		"allowed_signing_contexts": recordPayload["allowed_signing_contexts"],
		"authority_scope":          "emitter",
		"issuer_key_id":            keyID,
		"key_epoch":                keyEpoch,
		"key_id":                   keyID,
		"key_type":                 "AGENT",
		"public_key":               hex.EncodeToString(pub),
		"scope_id":                 emitterIDHex,
		"signing_context":          keyRecordSigningContext,
		"signature":                hex.EncodeToString(keyRecordSignature),
		"status":                   "ACTIVE",
	}
	trustPayload := map[string]any{
		"key_epoch":             keyEpoch,
		"key_id":                keyID,
		"key_records":           []any{keyRecord},
		"signing_context":       "trust_snapshot_v1",
		"verification_scope_id": "mishka_host_phase1",
	}
	canonicalTrustPayload, err := authority.JCSCanonicalJSONBytes(trustPayload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	trustPayloadHash := sha256.Sum256(canonicalTrustPayload)
	trustSigningInput := append([]byte("trust_snapshot_v1"), trustPayloadHash[:]...)
	trustSignature := ed25519.Sign(priv, trustSigningInput)

	if _, err := pool.Exec(ctx, `
DELETE FROM authority_snapshots
WHERE authority_type = 'CONFIG' AND authority_id = 'trust_snapshot'`); err != nil {
		fmt.Fprintln(os.Stderr, "delete old trust:", err)
		os.Exit(1)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO authority_snapshots (authority_type, authority_id, authority_version, canonical_payload_text, payload_hash, signature)
VALUES ('CONFIG', 'trust_snapshot', $1, $2, $3, $4)`,
		trustVersion,
		string(canonicalTrustPayload),
		trustPayloadHash[:],
		trustSignature,
	); err != nil {
		fmt.Fprintln(os.Stderr, "insert trust:", err)
		os.Exit(1)
	}

	bindings, _ := json.Marshal([]map[string]string{{
		"type":    "CONFIG",
		"id":      "trust_snapshot",
		"version": trustVersion,
	}})
	snapshots, _ := json.Marshal([]map[string]string{{
		"type":                     "CONFIG",
		"id":                       "trust_snapshot",
		"version":                  trustVersion,
		"canonical_payload_text":   string(canonicalTrustPayload),
		"payload_hash_hex":         hex.EncodeToString(trustPayloadHash[:]),
		"signature_hex":            hex.EncodeToString(trustSignature),
	}})

	exec := sha256.Sum256(trustPayloadHash[:])
	fmt.Printf("# mishka-host-bootstrap %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("RANSOMEYE_PRD13_AUTHORITY_BINDINGS_JSON=%s\n", string(bindings))
	fmt.Printf("RANSOMEYE_PRD13_AUTHORITY_SNAPSHOTS_JSON=%s\n", string(snapshots))
	fmt.Printf("RANSOMEYE_EXECUTION_CONTEXT_HASH=%s\n", hex.EncodeToString(exec[:]))
	fmt.Printf("# AGENT private key (hex 128 chars = 64-byte Ed25519 private key) for agent_id=%s — configure agent or discard if unused\n", agentID)
	fmt.Printf("MISHKA_BOOTSTRAP_AGENT_ED25519_PRIV_HEX=%x\n", priv.Seed())
}
