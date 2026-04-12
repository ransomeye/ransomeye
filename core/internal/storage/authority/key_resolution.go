package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	trustAuthorityType = "CONFIG"
	trustAuthorityID   = "trust_snapshot"
)

type trustSnapshotDoc struct {
	SigningContext      string      `json:"signing_context"`
	KeyID               string      `json:"key_id"`
	KeyEpoch            int64       `json:"key_epoch"`
	VerificationScopeID string       `json:"verification_scope_id"`
	KeyRecords          []keyRecord  `json:"key_records"`
}

type keyRecord struct {
	KeyID                 string   `json:"key_id"`
	KeyType               string   `json:"key_type"` // ROOT|CLUSTER|NODE|AGENT|PROBE|ADAPTER
	ScopeID               string   `json:"scope_id"`
	AuthorityScope        string   `json:"authority_scope"`
	KeyEpoch              int64    `json:"key_epoch"`
	PublicKey             string   `json:"public_key"` // hex ed25519 public key
	AllowedSigningContexts []string `json:"allowed_signing_contexts"`
	IssuerKeyID           string   `json:"issuer_key_id"`
	Status                string   `json:"status"` // ACTIVE|RETIRED|REVOKED
	SigningContext        string   `json:"signing_context"`
	SignatureHex          string   `json:"signature"`
	// ExpiryLogicalClock is optional (PRD-04); when set, PRD-08 §6.6 requires ingest to reject
	// signals whose logical_clock exceeds this bound.
	ExpiryLogicalClock *uint64 `json:"expiry_logical_clock,omitempty"`
}

// PublicKeyResolver defines the interface for resolving emitter keys from trust material.
type PublicKeyResolver interface {
	ResolveEmitterPublicKey(ctx context.Context, keyID string, keyEpoch int64, requiredSigningContext string) (ed25519.PublicKey, error)
}

// DBPublicKeyResolver implements PublicKeyResolver using a Postgres database.
type DBPublicKeyResolver struct {
	Pool *pgxpool.Pool
}

func (r *DBPublicKeyResolver) ResolveEmitterPublicKey(ctx context.Context, keyID string, keyEpoch int64, requiredSigningContext string) (ed25519.PublicKey, error) {
	return ResolveEmitterPublicKey(ctx, r.Pool, keyID, keyEpoch, requiredSigningContext)
}

// ResolveBatchCommitPublicKey resolves the verifying key from committed authority snapshots only.
//
// Rule:
// - A batch MUST have exactly one bound trust snapshot (type=CONFIG, id=trust_snapshot)
// - key_id must resolve to exactly one ACTIVE key record with matching key_epoch.
// - key_id derivation must match PRD-04 §4.1.
// - issuer linkage must be valid (ROOT self-signed allowed via issuer_key_id == key_id).
// - allowed_signing_contexts must include "batch_commit_record_v1" for the verifying key.
// - any missing/ambiguous/revoked/invalid key material -> fail-closed.
func ResolveBatchCommitPublicKey(ctx context.Context, pool *pgxpool.Pool, partitionID int64, batchCommitSeq int64, keyID string, keyEpoch int64) (ed25519.PublicKey, error) {
	return resolveBoundTrustSnapshotPublicKey(ctx, pool, partitionID, batchCommitSeq, keyID, keyEpoch, BatchCommitSigningContext)
}

// ResolveEmitterPublicKey resolves the verifying key from the latest committed authority snapshot.
// Used for pre-queue validation where batch binding does not yet exist.
func ResolveEmitterPublicKey(ctx context.Context, pool *pgxpool.Pool, keyID string, keyEpoch int64, requiredSigningContext string) (ed25519.PublicKey, error) {
	if pool == nil {
		return nil, FailType1("INPUT_ERROR", errors.New("nil pool"))
	}
	if strings.TrimSpace(keyID) == "" || keyEpoch <= 0 {
		return nil, FailType1("INPUT_ERROR", errors.New("invalid key_id or key_epoch"))
	}
	if strings.TrimSpace(requiredSigningContext) == "" {
		return nil, FailType1("INPUT_ERROR", errors.New("required signing_context missing"))
	}

	// Load the latest committed trust_snapshot.
	// In production, there should typically be one authoritative version at any time.
	var payload string
	var payloadHash []byte
	var sig []byte
	if err := pool.QueryRow(ctx, `
SELECT canonical_payload_text, payload_hash, signature
FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2
ORDER BY authority_version DESC LIMIT 1`,
		trustAuthorityType, trustAuthorityID,
	).Scan(&payload, &payloadHash, &sig); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, FailType3("INTEGRITY_FAILURE", errors.New("trust snapshot missing"))
		}
		return nil, FailType2("STATE_INCONSISTENCY", err)
	}

	doc, keyIndex, err := parseAndValidateTrustSnapshot(payload, payloadHash, sig)
	if err != nil {
		return nil, err
	}
	_ = doc

	// Verify the committed trust_snapshot signature using committed trust material inside the snapshot only.
	if err := verifyTrustSnapshotSignature(keyIndex, []byte(payload), sig); err != nil {
		return nil, FailType3("SIGNATURE_MISMATCH", err)
	}

	target, ok := keyIndex[keyID]
	if !ok {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("missing key material for key_id"))
	}
	if target.KeyEpoch != keyEpoch {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("key_epoch mismatch for key_id"))
	}
	if target.Status != "ACTIVE" {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("key material revoked/retired/inapplicable"))
	}
	if !containsString(target.AllowedSigningContexts, requiredSigningContext) {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("signing_context not allowed for key"))
	}

	// Verify signed key record chain rooted in committed trust snapshot only.
	visited := make(map[string]struct{}, 8)
	if err := verifyKeyRecordRecursive(keyIndex, target.KeyID, visited); err != nil {
		return nil, FailType3("INTEGRITY_FAILURE", err)
	}

	pubBytes, err := hex.DecodeString(target.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("public_key invalid"))
	}
	return ed25519.PublicKey(pubBytes), nil
}

// VerifySignalLogicalClockAgainstKeyExpiry enforces PRD-08 §6.6 against an optional PRD-04
// expiry_logical_clock on the resolved key record.
func VerifySignalLogicalClockAgainstKeyExpiry(signalLogicalClock uint64, expiry *uint64) error {
	if expiry == nil {
		return nil
	}
	if signalLogicalClock > *expiry {
		return FailType1("SIGNAL_AUTH_FAILURE", errors.New("logical_clock exceeds key expiry_logical_clock from trust snapshot"))
	}
	return nil
}

// ResolveEmitterPublicKeyByIdentity resolves an emitter verification key from committed trust_snapshot
// using explicit identity binding (key_type + scope_id), not caller-supplied key_id heuristics.
// When boundTrustSnapshotVersion is non-empty (Mishka PRD-13 env bindings), that exact row is loaded;
// otherwise the lexicographically greatest authority_version is used (legacy fallback).
func ResolveEmitterPublicKeyByIdentity(ctx context.Context, pool *pgxpool.Pool, keyType string, emitterID string, requiredSigningContext string, signalLogicalClock uint64, boundTrustSnapshotVersion string) (ed25519.PublicKey, error) {
	if pool == nil {
		return nil, FailType1("INPUT_ERROR", errors.New("nil pool"))
	}
	typ := strings.TrimSpace(strings.ToUpper(keyType))
	if typ != "AGENT" && typ != "PROBE" {
		return nil, FailType1("INPUT_ERROR", errors.New("invalid emitter key_type"))
	}
	id := strings.TrimSpace(strings.ToLower(emitterID))
	if _, err := hex.DecodeString(id); err != nil || len(id) != 32 {
		return nil, FailType1("INPUT_ERROR", errors.New("invalid emitter_id"))
	}
	if strings.TrimSpace(requiredSigningContext) == "" {
		return nil, FailType1("INPUT_ERROR", errors.New("required signing_context missing"))
	}

	var payload string
	var payloadHash []byte
	var sig []byte
	var err error
	boundVer := strings.TrimSpace(boundTrustSnapshotVersion)
	if boundVer != "" {
		err = pool.QueryRow(ctx, `
SELECT canonical_payload_text, payload_hash, signature
FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2 AND authority_version = $3`,
			trustAuthorityType, trustAuthorityID, boundVer,
		).Scan(&payload, &payloadHash, &sig)
	} else {
		err = pool.QueryRow(ctx, `
SELECT canonical_payload_text, payload_hash, signature
FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2
ORDER BY authority_version DESC LIMIT 1`,
			trustAuthorityType, trustAuthorityID,
		).Scan(&payload, &payloadHash, &sig)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, FailType3("INTEGRITY_FAILURE", errors.New("trust snapshot missing"))
		}
		return nil, FailType2("STATE_INCONSISTENCY", err)
	}
	_, keyIndex, err := parseAndValidateTrustSnapshot(payload, payloadHash, sig)
	if err != nil {
		return nil, err
	}
	if err := verifyTrustSnapshotSignature(keyIndex, []byte(payload), sig); err != nil {
		return nil, FailType3("SIGNATURE_MISMATCH", err)
	}

	var matches []keyRecord
	for _, rec := range keyIndex {
		if rec.KeyType != typ {
			continue
		}
		if strings.ToLower(strings.TrimSpace(rec.ScopeID)) != id {
			continue
		}
		if rec.Status != "ACTIVE" {
			continue
		}
		if !containsString(rec.AllowedSigningContexts, requiredSigningContext) {
			continue
		}
		matches = append(matches, rec)
	}
	if len(matches) == 0 {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("missing key material for emitter identity"))
	}
	if len(matches) != 1 {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("ambiguous key material for emitter identity"))
	}
	target := matches[0]
	if err := VerifySignalLogicalClockAgainstKeyExpiry(signalLogicalClock, target.ExpiryLogicalClock); err != nil {
		return nil, err
	}
	visited := make(map[string]struct{}, 8)
	if err := verifyKeyRecordRecursive(keyIndex, target.KeyID, visited); err != nil {
		return nil, FailType3("INTEGRITY_FAILURE", err)
	}
	pubBytes, err := hex.DecodeString(target.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("public_key invalid"))
	}
	return ed25519.PublicKey(pubBytes), nil
}

func resolveBoundTrustSnapshotPublicKey(ctx context.Context, pool *pgxpool.Pool, partitionID int64, batchCommitSeq int64, keyID string, keyEpoch int64, requiredSigningContext string) (ed25519.PublicKey, error) {
	if pool == nil {
		return nil, FailType1("INPUT_ERROR", errors.New("nil pool"))
	}
	if strings.TrimSpace(keyID) == "" || keyEpoch <= 0 {
		return nil, FailType1("INPUT_ERROR", errors.New("invalid key_id or key_epoch"))
	}
	if strings.TrimSpace(requiredSigningContext) == "" {
		return nil, FailType1("INPUT_ERROR", errors.New("required signing_context missing"))
	}

	doc, keyIndex, err := loadBoundTrustSnapshot(ctx, pool, partitionID, batchCommitSeq)
	if err != nil {
		return nil, err
	}
	_ = doc // reserved for future trust snapshot envelope validation

	target, ok := keyIndex[keyID]
	if !ok {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("missing key material for key_id"))
	}
	if target.KeyEpoch != keyEpoch {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("key_epoch mismatch for key_id"))
	}
	if target.Status != "ACTIVE" {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("key material revoked/retired/inapplicable"))
	}
	if !containsString(target.AllowedSigningContexts, requiredSigningContext) {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("signing_context not allowed for key"))
	}

	// Verify signed key record chain rooted in committed trust snapshot only.
	visited := make(map[string]struct{}, 8)
	if err := verifyKeyRecordRecursive(keyIndex, target.KeyID, visited); err != nil {
		return nil, FailType3("INTEGRITY_FAILURE", err)
	}

	pubBytes, err := hex.DecodeString(target.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, FailType3("INTEGRITY_FAILURE", errors.New("public_key invalid"))
	}
	return ed25519.PublicKey(pubBytes), nil
}

func loadBoundTrustSnapshot(ctx context.Context, pool *pgxpool.Pool, partitionID int64, batchCommitSeq int64) (trustSnapshotDoc, map[string]keyRecord, error) {
	// Ensure the batch binds a single trust snapshot.
	rows, err := pool.Query(ctx, `
SELECT authority_type, authority_id, authority_version
FROM batch_commit_authority_bindings
WHERE partition_id = $1 AND batch_commit_seq = $2
  AND authority_type = $3 AND authority_id = $4
ORDER BY authority_version ASC`,
		partitionID, batchCommitSeq, trustAuthorityType, trustAuthorityID,
	)
	if err != nil {
		return trustSnapshotDoc{}, nil, FailType2("STATE_INCONSISTENCY", err)
	}
	defer rows.Close()
	type ref struct{ t, id, v string }
	var refs []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.t, &r.id, &r.v); err != nil {
			return trustSnapshotDoc{}, nil, FailType2("STATE_INCONSISTENCY", err)
		}
		refs = append(refs, r)
	}
	if err := rows.Err(); err != nil {
		return trustSnapshotDoc{}, nil, FailType2("STATE_INCONSISTENCY", err)
	}
	if len(refs) == 0 {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("missing batch trust snapshot binding"))
	}
	if len(refs) != 1 {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("ambiguous batch trust snapshot binding"))
	}

	var payload string
	var payloadHash []byte
	var sig []byte
	if err := pool.QueryRow(ctx, `
SELECT canonical_payload_text, payload_hash, signature
FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2 AND authority_version = $3`,
		refs[0].t, refs[0].id, refs[0].v,
	).Scan(&payload, &payloadHash, &sig); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust snapshot missing"))
		}
		return trustSnapshotDoc{}, nil, FailType2("STATE_INCONSISTENCY", err)
	}
	doc, keyIndex, err := parseAndValidateTrustSnapshot(payload, payloadHash, sig)
	if err != nil {
		return trustSnapshotDoc{}, nil, err
	}

	// Verify the committed trust_snapshot signature using committed trust material inside the snapshot only.
	// This is intentionally self-contained: no external config, no ambient runtime trust.
	if err := verifyTrustSnapshotSignature(keyIndex, []byte(payload), sig); err != nil {
		return trustSnapshotDoc{}, nil, FailType3("SIGNATURE_MISMATCH", err)
	}

	return doc, keyIndex, nil
}

func parseAndValidateTrustSnapshot(payload string, payloadHash []byte, sig []byte) (trustSnapshotDoc, map[string]keyRecord, error) {
	if strings.TrimSpace(payload) == "" {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("empty trust snapshot payload"))
	}
	if len(payloadHash) != 32 {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", fmt.Errorf("trust snapshot payload_hash length %d", len(payloadHash)))
	}
	if len(sig) != ed25519.SignatureSize {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", fmt.Errorf("trust snapshot signature length %d", len(sig)))
	}

	// PRD-01 / PRD-04 / PRD-13 / PRD-15:
	// Fail-closed unless the committed trust_snapshot payload bytes are already RFC 8785 canonical JSON.
	// Canonical bytes are the ONLY basis for payload_hash/signature verification (no trimming, no normalization).
	raw := []byte(payload)
	canonical, err := canonicalizeStrictJSONRFC8785(raw)
	if err != nil {
		return trustSnapshotDoc{}, nil, FailType3("CANONICALIZATION_VIOLATION", errors.New("trust snapshot malformed JSON"))
	}
	if !bytes.Equal(raw, canonical) {
		return trustSnapshotDoc{}, nil, FailType3("CANONICALIZATION_VIOLATION", errors.New("trust snapshot non-canonical JSON"))
	}

	wantPH := sha256.Sum256(canonical)
	if bytesTo32(payloadHash) != wantPH {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust snapshot payload_hash mismatch"))
	}

	var doc trustSnapshotDoc
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", fmt.Errorf("trust snapshot decode: %w", err))
	}
	// Ensure there are no additional JSON values.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust snapshot payload has trailing data"))
	}
	if strings.TrimSpace(doc.VerificationScopeID) == "" {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust snapshot missing verification_scope_id"))
	}
	if len(doc.KeyRecords) == 0 {
		return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("trust snapshot empty key_records"))
	}

	keyIndex := make(map[string]keyRecord, len(doc.KeyRecords)) // key_id -> record (unique)
	for _, kr := range doc.KeyRecords {
		if err := validateKeyRecordShape(kr); err != nil {
			return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", err)
		}
		if err := validateKeyIDDerivation(kr); err != nil {
			return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", err)
		}
		if _, ok := keyIndex[kr.KeyID]; ok {
			return trustSnapshotDoc{}, nil, FailType3("INTEGRITY_FAILURE", errors.New("duplicate key_id in trust snapshot"))
		}
		keyIndex[kr.KeyID] = kr
	}
	return doc, keyIndex, nil
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func validateKeyRecordShape(k keyRecord) error {
	if strings.TrimSpace(k.KeyID) == "" ||
		strings.TrimSpace(k.KeyType) == "" ||
		strings.TrimSpace(k.ScopeID) == "" ||
		strings.TrimSpace(k.AuthorityScope) == "" ||
		k.KeyEpoch <= 0 ||
		strings.TrimSpace(k.PublicKey) == "" ||
		len(k.AllowedSigningContexts) == 0 ||
		strings.TrimSpace(k.IssuerKeyID) == "" ||
		strings.TrimSpace(k.Status) == "" ||
		strings.TrimSpace(k.SigningContext) == "" ||
		strings.TrimSpace(k.SignatureHex) == "" {
		return errors.New("trust snapshot key record invalid")
	}
	switch k.Status {
	case "ACTIVE", "RETIRED", "REVOKED":
	default:
		return errors.New("trust snapshot key status invalid")
	}
	return nil
}

func validateKeyIDDerivation(k keyRecord) error {
	pub, err := hex.DecodeString(k.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("trust snapshot key public_key invalid")
	}
	h := sha256.New()
	_, _ = h.Write([]byte(k.KeyType))
	_, _ = h.Write([]byte(k.ScopeID))
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], uint64(k.KeyEpoch))
	_, _ = h.Write(be[:])
	_, _ = h.Write(pub)
	sum := h.Sum(nil)
	want := hex.EncodeToString(sum)
	if strings.ToLower(strings.TrimSpace(k.KeyID)) != want {
		return errors.New("invalid key_id derivation")
	}
	return nil
}

func verifyKeyRecordRecursive(index map[string]keyRecord, keyID string, visited map[string]struct{}) error {
	if _, ok := visited[keyID]; ok {
		return errors.New("trust snapshot key chain loop")
	}
	visited[keyID] = struct{}{}

	rec, ok := index[keyID]
	if !ok {
		return errors.New("missing issuer")
	}
	if rec.Status != "ACTIVE" {
		return errors.New("revoked or inapplicable key")
	}

	issuerID := rec.IssuerKeyID
	if strings.TrimSpace(issuerID) == "" {
		return errors.New("issuer_key_id missing")
	}

	issuerPub, err := resolveIssuerPublicKey(index, rec, visited)
	if err != nil {
		return err
	}

	payload, err := keyRecordCanonicalPayloadBytes(rec)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	signingInput := append([]byte(rec.SigningContext), sum[:]...)

	sig, err := hex.DecodeString(rec.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("key record signature invalid")
	}
	if !ed25519.Verify(issuerPub, signingInput, sig) {
		return errors.New("key record signature verify failed")
	}
	return nil
}

func resolveIssuerPublicKey(index map[string]keyRecord, rec keyRecord, visited map[string]struct{}) (ed25519.PublicKey, error) {
	issuerID := rec.IssuerKeyID
	if issuerID == rec.KeyID {
		// self-issued root case: still must be verifiable with its own public key.
		pub, err := hex.DecodeString(rec.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("issuer public_key invalid")
		}
		return ed25519.PublicKey(pub), nil
	}

	issuer, ok := index[issuerID]
	if !ok {
		return nil, errors.New("missing issuer")
	}
	if issuer.Status != "ACTIVE" {
		return nil, errors.New("issuer key inactive")
	}
	// Verify issuer record first so its public key is trusted by committed chain only.
	if err := verifyKeyRecordRecursive(index, issuer.KeyID, visited); err != nil {
		return nil, err
	}
	if !containsString(issuer.AllowedSigningContexts, rec.SigningContext) {
		return nil, errors.New("issuer signing_context not allowed")
	}
	pub, err := hex.DecodeString(issuer.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("issuer public_key invalid")
	}
	return ed25519.PublicKey(pub), nil
}

func keyRecordCanonicalPayloadBytes(k keyRecord) ([]byte, error) {
	acs := make([]any, 0, len(k.AllowedSigningContexts))
	for _, s := range k.AllowedSigningContexts {
		acs = append(acs, s)
	}
	obj := map[string]any{
		"allowed_signing_contexts": acs,
		"authority_scope":          k.AuthorityScope,
		"issuer_key_id":            k.IssuerKeyID,
		"key_epoch":                int64(k.KeyEpoch),
		"key_id":                   k.KeyID,
		"key_type":                 k.KeyType,
		"public_key":               k.PublicKey,
		"scope_id":                 k.ScopeID,
		"signing_context":          k.SigningContext,
		"status":                   k.Status,
	}
	return JCSCanonicalJSONBytes(obj)
}

func verifyTrustSnapshotSignature(index map[string]keyRecord, canonicalTrustSnapshotPayload []byte, signature []byte) error {
	var env authoritySnapshotEnvelope
	if err := json.Unmarshal(canonicalTrustSnapshotPayload, &map[string]any{}); err != nil {
		return errors.New("trust snapshot malformed JSON")
	}

	parsed, err := parseAuthoritySnapshotEnvelope(string(canonicalTrustSnapshotPayload))
	if err != nil {
		return errors.New("trust snapshot envelope invalid")
	}
	env = parsed

	rec, ok := index[env.keyID]
	if !ok {
		return errors.New("trust snapshot signer key_id missing from key_records")
	}
	if rec.KeyEpoch != env.keyEpoch {
		return errors.New("trust snapshot signer key_epoch mismatch")
	}
	if rec.Status != "ACTIVE" {
		return errors.New("trust snapshot signer key inactive")
	}
	if !containsString(rec.AllowedSigningContexts, env.signingContext) {
		return errors.New("trust snapshot signing_context not allowed for signer key")
	}

	visited := make(map[string]struct{}, 8)
	if err := verifyKeyRecordRecursive(index, rec.KeyID, visited); err != nil {
		return fmt.Errorf("trust snapshot signer key chain invalid: %w", err)
	}
	pubBytes, err := hex.DecodeString(rec.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("trust snapshot signer public_key invalid")
	}

	sum := sha256.Sum256(canonicalTrustSnapshotPayload)
	signingInput := append([]byte(env.signingContext), sum[:]...)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), signingInput, signature) {
		return errors.New("trust snapshot signature verify failed")
	}
	return nil
}

