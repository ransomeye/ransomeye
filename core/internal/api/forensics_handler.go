package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	corecrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/forensics"
)

type ForensicsHandler struct {
	pool *pgxpool.Pool
}

func NewForensicsHandler(pool *pgxpool.Pool) *ForensicsHandler {
	return &ForensicsHandler{pool: pool}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type exportEvidence struct {
	EvidenceID           string  `json:"evidence_id"`
	TenantID             string  `json:"tenant_id"`
	DetectionID          *string `json:"detection_id,omitempty"`
	EventID              *string `json:"event_id,omitempty"`
	EvidenceType         string  `json:"evidence_type"`
	FilePath             string  `json:"file_path"`
	CanonicalJSONHash    string  `json:"canonical_json_hash"`
	WormFileHash         string  `json:"worm_file_hash"`
	WormEd25519Sig       string  `json:"worm_ed25519_sig"`
	RetentionTier        string  `json:"retention_tier"`
	FileSizeBytes        int64   `json:"file_size_bytes"`
	DroppedPacketsBefore int64   `json:"dropped_packets_before"`
	SealedAt             string  `json:"sealed_at"`
	ExpiresAt            string  `json:"expires_at"`

	// RFC6962 leaf preimage bytes used for inclusion proof generation.
	SocMerkleLeafB64   string `json:"soc_merkle_leaf_b64"`
	MerklePrevRootHash string `json:"merkle_prev_root_hash"`
	MerkleLeafIndex    int    `json:"merkle_leaf_index"`
	DailyDate          string `json:"daily_date"`

	// Sealed blob on disk: nonce(12 bytes) || ciphertext(GCM).
	// Included so auditors can recompute WORM evidenceDigest without AES key.
	SealedBlobB64 string `json:"sealed_blob_b64"`
}

type exportBundle struct {
	Evidence        exportEvidence `json:"evidence"`
	Signature       string         `json:"signature"`
	MerkleProof     []string       `json:"merkle_proof"`
	MerkleRoot      string         `json:"merkle_root"`
	Timestamp       string         `json:"timestamp"`
	BundleSignature string         `json:"bundle_signature"`
}

func (e exportEvidence) canonicalValue() map[string]any {
	out := map[string]any{
		"evidence_id":            e.EvidenceID,
		"tenant_id":              e.TenantID,
		"evidence_type":          e.EvidenceType,
		"file_path":              e.FilePath,
		"canonical_json_hash":    e.CanonicalJSONHash,
		"worm_file_hash":         e.WormFileHash,
		"worm_ed25519_sig":       e.WormEd25519Sig,
		"retention_tier":         e.RetentionTier,
		"file_size_bytes":        json.Number(strconv.FormatInt(e.FileSizeBytes, 10)),
		"dropped_packets_before": json.Number(strconv.FormatInt(e.DroppedPacketsBefore, 10)),
		"sealed_at":              e.SealedAt,
		"expires_at":             e.ExpiresAt,
		"soc_merkle_leaf_b64":    e.SocMerkleLeafB64,
		"merkle_prev_root_hash":  e.MerklePrevRootHash,
		"merkle_leaf_index":      json.Number(strconv.Itoa(e.MerkleLeafIndex)),
		"daily_date":             e.DailyDate,
		"sealed_blob_b64":        e.SealedBlobB64,
	}
	if e.DetectionID != nil {
		out["detection_id"] = *e.DetectionID
	}
	if e.EventID != nil {
		out["event_id"] = *e.EventID
	}
	return out
}

func (b exportBundle) canonicalValue() map[string]any {
	proof := make([]any, 0, len(b.MerkleProof))
	for _, step := range b.MerkleProof {
		proof = append(proof, step)
	}
	return map[string]any{
		"evidence":     b.Evidence.canonicalValue(),
		"signature":    b.Signature,
		"merkle_proof": proof,
		"merkle_root":  b.MerkleRoot,
		"timestamp":    b.Timestamp,
	}
}

// ExportForEvidence returns an auditor/verifier bundle for evidence_id.
//
// Bundle includes:
// - evidence row (from worm_evidence)
// - Merkle inclusion proof (RFC6962) over soc_merkle_leaf leaves for that tenant/day
// - Merkle root + Ed25519 signature from merkle_daily_roots
func (h *ForensicsHandler) ExportForEvidence(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "db pool not available"})
		return
	}

	evidenceIDStr := string(bytes.TrimSpace([]byte(r.PathValue("evidence_id"))))
	evidenceID, err := uuid.Parse(evidenceIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid evidence_id"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	// 1) Load evidence row + its daily_date + merkle_position (for filtering/indexing).
	var (
		tenantID      uuid.UUID
		detectionID   *uuid.UUID
		eventID       *uuid.UUID
		evidenceType  string
		filePath      string
		canonicalHex  string
		wormHex       string
		wormSigB64    string
		retentionTier string
		fileSizeBytes int64
		droppedBefore int64
		sealedAt      time.Time
		expiresAt     time.Time
		socMerkleLeaf []byte
		dailyDate     time.Time
		_             int64
	)

	row := h.pool.QueryRow(ctx, `
SELECT
    we.tenant_id,
    we.detection_id,
    we.event_id,
    we.evidence_type,
    we.file_path,
    we.canonical_json_hash,
    we.worm_file_hash,
    we.ed25519_sig,
    we.retention_tier,
    we.file_size_bytes,
    we.dropped_packets_before,
    we.sealed_at,
    we.expires_at,
    we.soc_merkle_leaf,
    ewl.daily_date,
    ewl.merkle_position
FROM worm_evidence we
JOIN exposure_worm_ledger ewl ON ewl.evidence_id = we.evidence_id AND ewl.tenant_id = we.tenant_id
WHERE we.evidence_id = $1
`, evidenceID)

	// Scan nullable columns with *uuid.UUID and nilable leaf bytes.
	var detIDUUID *uuid.UUID
	var eventIDUUID *uuid.UUID
	var leaf []byte
	var daily time.Time
	var merklePos int64

	err = row.Scan(
		&tenantID,
		&detIDUUID,
		&eventIDUUID,
		&evidenceType,
		&filePath,
		&canonicalHex,
		&wormHex,
		&wormSigB64,
		&retentionTier,
		&fileSizeBytes,
		&droppedBefore,
		&sealedAt,
		&expiresAt,
		&leaf,
		&daily,
		&merklePos,
	)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "evidence_id not found"})
		return
	}
	detectionID = detIDUUID
	eventID = eventIDUUID
	socMerkleLeaf = leaf
	dailyDate = daily
	_ = merklePos

	if len(socMerkleLeaf) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "evidence has no soc_merkle_leaf (cannot export inclusion proof)"})
		return
	}

	// 2) Load Merkle daily root + signature + prev_root_hash for chaining.
	var (
		merkleRootHex string
		prevRootHex   string
		sigB64        string
	)
	err = h.pool.QueryRow(ctx, `
SELECT merkle_root, prev_root_hash, ed25519_sig
FROM merkle_daily_roots
WHERE tenant_id = $1 AND daily_date = $2::date
`, tenantID, dailyDate).Scan(&merkleRootHex, &prevRootHex, &sigB64)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "merkle_daily_roots lookup failed"})
		return
	}

	rootBytes, err := hex.DecodeString(merkleRootHex)
	if err != nil || len(rootBytes) == 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "merkle_root hex decode failed"})
		return
	}
	// Pre-storage admissibility gate: root signature must verify before evidence is admissible.
	merkleRootSig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(merkleRootSig) != ed25519.SignatureSize {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "merkle root signature decode failed"})
		return
	}
	var prevRootBytes []byte
	if strings.TrimSpace(prevRootHex) != "" {
		prevRootBytes, err = hex.DecodeString(prevRootHex)
		if err != nil || len(prevRootBytes) != sha256.Size {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "previous merkle root decode failed"})
			return
		}
	}
	chainedRoot := corecrypto.ComputeChainedRoot(prevRootBytes, rootBytes)
	privKey, err := loadEd25519PrivateKey(corecrypto.WormSigningKeyPath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "signing key unavailable"})
		return
	}
	pubKey, ok := privKey.Public().(ed25519.PublicKey)
	if !ok || !corecrypto.VerifyRoot(chainedRoot, merkleRootSig, pubKey) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "merkle root signature verification failed"})
		return
	}

	// 3) Load all RFC6962 leaves for that tenant/day (ordered by merkle_position) as used for rollup.
	rows, err := h.pool.Query(ctx, `
SELECT w.soc_merkle_leaf
FROM exposure_worm_ledger ewl
JOIN worm_evidence w ON w.evidence_id = ewl.evidence_id AND w.tenant_id = ewl.tenant_id
WHERE ewl.tenant_id = $1
  AND ewl.daily_date = $2::date
  AND w.soc_merkle_leaf IS NOT NULL
ORDER BY ewl.merkle_position ASC
`, tenantID, dailyDate)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load merkle leaves failed"})
		return
	}
	defer rows.Close()

	var leaves [][]byte
	for rows.Next() {
		var leafBytes []byte
		if err := rows.Scan(&leafBytes); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "leaf scan failed"})
			return
		}
		leaves = append(leaves, leafBytes)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "leaf iteration failed"})
		return
	}
	if len(leaves) == 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no leaves for merkle rollup"})
		return
	}

	// Index is relative to the filtered leaf list used to compute the daily root.
	leafIndex := -1
	for i := range leaves {
		if bytes.Equal(leaves[i], socMerkleLeaf) {
			leafIndex = i
			break
		}
	}
	if leafIndex < 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "evidence leaf not present in leaf set"})
		return
	}
	// Pre-storage admissibility gate: content_sha256 must match canonical evidence payload.
	leafHash := sha256.Sum256(socMerkleLeaf)
	if hex.EncodeToString(leafHash[:]) != canonicalHex {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "content_sha256 mismatch (fail closed)"})
		return
	}

	// 4) Generate inclusion proof + validate locally (fail-closed).
	proofSteps := forensics.GenerateInclusionProof(leaves, leafIndex)
	if proofSteps == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "inclusion proof generation failed"})
		return
	}
	if ok := forensics.VerifyInclusionProof(socMerkleLeaf, proofSteps, rootBytes, leafIndex); !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "local inclusion proof verification failed"})
		return
	}
	// Additionally ensure Merkle root matches the recomputation from leaves.
	recomputedRoot, err := forensics.MerkleTreeHash(leaves)
	if err != nil || !bytes.Equal(recomputedRoot, rootBytes) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "merkle_root mismatch (fail closed)"})
		return
	}

	encodedProof := make([]string, 0, len(proofSteps))
	for _, step := range proofSteps {
		if len(step) == 0 {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "empty proof step"})
			return
		}
		encodedProof = append(encodedProof, base64.StdEncoding.EncodeToString(step))
	}

	// 5) Build response bundle.
	var detIDStr *string
	if detectionID != nil {
		s := detectionID.String()
		detIDStr = &s
	}
	var eventIDStr *string
	if eventID != nil {
		s := eventID.String()
		eventIDStr = &s
	}

	ev := exportEvidence{
		EvidenceID:           evidenceID.String(),
		TenantID:             tenantID.String(),
		DetectionID:          detIDStr,
		EventID:              eventIDStr,
		EvidenceType:         evidenceType,
		FilePath:             filePath,
		CanonicalJSONHash:    canonicalHex,
		WormFileHash:         wormHex,
		WormEd25519Sig:       wormSigB64,
		RetentionTier:        retentionTier,
		FileSizeBytes:        fileSizeBytes,
		DroppedPacketsBefore: droppedBefore,
		SealedAt:             sealedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:            expiresAt.UTC().Format(time.RFC3339Nano),

		SocMerkleLeafB64:   base64.StdEncoding.EncodeToString(socMerkleLeaf),
		MerklePrevRootHash: prevRootHex,
		MerkleLeafIndex:    leafIndex,
		DailyDate:          dailyDate.UTC().Format("2006-01-02"),
	}

	// Load sealed blob so offline verification can recompute WORM evidenceDigest.
	sealedBytes, err := os.ReadFile(filePath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sealed blob read failed"})
		return
	}
	ev.SealedBlobB64 = base64.StdEncoding.EncodeToString(sealedBytes)

	b := exportBundle{
		Evidence:    ev,
		Signature:   sigB64,
		MerkleProof: encodedProof,
		MerkleRoot:  merkleRootHex,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	}

	canon, err := forensics.MarshalCanonical(b.canonicalValue())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "bundle canonicalization failed"})
		return
	}
	digest := sha256.Sum256(canon)

	privKey, err = loadEd25519PrivateKey(corecrypto.WormSigningKeyPath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "signing key unavailable"})
		return
	}
	bsig := ed25519.Sign(privKey, digest[:])
	pubKey, ok = privKey.Public().(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pubKey, digest[:], bsig) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "bundle signature self-verify failed"})
		return
	}
	b.BundleSignature = base64.StdEncoding.EncodeToString(bsig)

	// PRD-25: best-effort SOC lineage row (migration 048); export remains authoritative via WORM+merkle bundle.
	if specBytes, mErr := json.Marshal(map[string]any{
		"kind":        "forensics_export",
		"evidence_id": evidenceID.String(),
		"tenant_id":   tenantID.String(),
	}); mErr == nil {
		lineageCtx, lineageCancel := context.WithTimeout(r.Context(), 2*time.Second)
		note := "export_bundle_signed; merkle_root=" + merkleRootHex + "; anchored worm_evidence+soc_merkle; not partition_records QUERY/REPORT commit"
		_, execErr := h.pool.Exec(lineageCtx, `
INSERT INTO mishka_soc_report_lineage (scope, query_spec, result_ref, authority_note)
VALUES ($1, $2::jsonb, $3, $4)
ON CONFLICT (scope, result_ref) DO NOTHING
`, "forensics_export", specBytes, evidenceID.String(), note)
		lineageCancel()
		_ = execErr // best-effort; undefined_table if migration 048 missing — export still succeeds
	}

	writeJSON(w, http.StatusOK, b)
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := corecrypto.ReadValidatedWormSeed(path, true)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(raw), nil
}
