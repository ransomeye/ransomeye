package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"time"
)

// Self-contained forensic verification CLI.
//
// Input: bundle.json from GET /api/v1/forensics/export/{evidence_id}
//
// Fail-closed verification:
// - WORM evidence signature (Ed25519 over evidenceDigest(ciphertext, logical_clock, actor, action_id, action_type))
// - canonical_json_hash (sha256 over soc_merkle_leaf canonical bytes)
// - RFC6962 inclusion proof (ordered tagged audit path)
// - merkle_daily_roots signature (Ed25519 over chained daily digest)
// - bundle_signature (Ed25519 over SHA256(canonical_json(bundle without bundle_signature)))

const (
	leafPrefix      byte = 0x00
	nodePrefix      byte = 0x01
	stepLen              = 1 + sha256.Size
	siblingLeftTag  byte = 0x00
	siblingRightTag byte = 0x01
	gcmNonceSize         = 12
)

func leafHash(data []byte) []byte {
	sum := sha256.New()
	_, _ = sum.Write([]byte{leafPrefix})
	_, _ = sum.Write(data)
	return sum.Sum(nil)
}

func nodeHash(left, right []byte) []byte {
	if len(left) != sha256.Size || len(right) != sha256.Size {
		panic("verify_forensics: nodeHash child length")
	}
	sum := sha256.New()
	_, _ = sum.Write([]byte{nodePrefix})
	_, _ = sum.Write(left)
	_, _ = sum.Write(right)
	return sum.Sum(nil)
}

func verifyInclusionProof(leaf []byte, proof [][]byte, root []byte) bool {
	if len(root) != sha256.Size {
		return false
	}
	cur := leafHash(leaf)
	for _, step := range proof {
		if len(step) != stepLen {
			return false
		}
		tag := step[0]
		sibling := step[1:]
		switch tag {
		case siblingLeftTag:
			cur = nodeHash(sibling, cur)
		case siblingRightTag:
			cur = nodeHash(cur, sibling)
		default:
			return false
		}
	}
	return subtle.ConstantTimeCompare(cur, root) == 1
}

func computeChainedRoot(prevRoot, currentRoot []byte) []byte {
	combined := make([]byte, 0, len(prevRoot)+len(currentRoot))
	combined = append(combined, prevRoot...)
	combined = append(combined, currentRoot...)
	h := sha256.Sum256(combined)
	return h[:]
}

func wormEvidenceDigest(payload []byte, logicalClock int64, agentID, eventID, eventType string) []byte {
	// evidenceDigest returns SHA-256( agentID || 0x00 || eventID || 0x00 || eventType || 0x00 ||
	// logicalClock(be) || 0x00 || payload ).
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

// Canonical JSON encoding copied from core/internal/forensics/canonical_json.go semantics.
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(string(x))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("verify_forensics: non-finite float in canonical json")
		}
		buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case string:
		enc, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(enc)
	case []byte:
		enc, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(enc)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			ke, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(ke)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("verify_forensics: unsupported canonical json type %T", v)
	}
	return nil
}

func decodeJSONUseNumber(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func copyJSONObject(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("public key is not a regular file: %s", path)
	}
	keyRaw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(keyRaw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"public key invalid size: got %d want %d",
			len(keyRaw),
			ed25519.PublicKeySize,
		)
	}
	return ed25519.PublicKey(append([]byte(nil), keyRaw...)), nil
}

func main() {
	var filePath string
	var keyPath string
	flag.StringVar(&filePath, "file", "", "path to export bundle JSON (bundle.json)")
	flag.StringVar(&keyPath, "key", "/etc/ransomeye/worm_signing.pub", "path to Ed25519 public key")
	flag.Parse()

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "missing --file bundle.json")
		os.Exit(2)
	}

	raw, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read bundle: %v\n", err)
		os.Exit(2)
	}

	// Decode using UseNumber to preserve exact numeric tokens for canonical JSON.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		fmt.Fprintf(os.Stderr, "parse bundle.json: %v\n", err)
		os.Exit(2)
	}

	pub, err := loadPublicKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject: load public key: %v\n", err)
		os.Exit(2)
	}

	evidenceAny, ok := obj["evidence"].(map[string]any)
	if !ok {
		fmt.Fprintln(os.Stderr, "reject: missing evidence object")
		os.Exit(2)
	}

	merkleRootHex, _ := obj["merkle_root"].(string)
	if merkleRootHex == "" {
		fmt.Fprintln(os.Stderr, "reject: missing merkle_root")
		os.Exit(2)
	}
	rootBytes, err := hex.DecodeString(merkleRootHex)
	if err != nil || len(rootBytes) != sha256.Size {
		fmt.Fprintf(os.Stderr, "reject: merkle_root invalid hex/len: %v\n", err)
		os.Exit(2)
	}

	sigRootB64, _ := obj["signature"].(string)
	if sigRootB64 == "" {
		fmt.Fprintln(os.Stderr, "reject: missing merkle_daily_roots signature")
		os.Exit(2)
	}
	sigRoot, err := base64.StdEncoding.DecodeString(sigRootB64)
	if err != nil || len(sigRoot) != ed25519.SignatureSize {
		fmt.Fprintln(os.Stderr, "reject: invalid merkle_root signature encoding/length")
		os.Exit(2)
	}

	// Bundle signature over the canonical full bundle with bundle_signature blanked.
	bundleSigB64, _ := obj["bundle_signature"].(string)
	if bundleSigB64 == "" {
		fmt.Fprintln(os.Stderr, "reject: missing bundle_signature")
		os.Exit(2)
	}
	bundleSig, err := base64.StdEncoding.DecodeString(bundleSigB64)
	if err != nil || len(bundleSig) != ed25519.SignatureSize {
		fmt.Fprintln(os.Stderr, "reject: invalid bundle_signature encoding/length")
		os.Exit(2)
	}
	bundleToVerify := copyJSONObject(obj)
	bundleToVerify["bundle_signature"] = ""
	bundleCanon, err := marshalCanonical(bundleToVerify)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject: bundle canonical json encode failed: %v\n", err)
		os.Exit(2)
	}
	bundleDigest := sha256.Sum256(bundleCanon)
	if !ed25519.Verify(pub, bundleDigest[:], bundleSig) {
		fmt.Fprintln(os.Stderr, "reject: bundle_signature invalid")
		os.Exit(2)
	}

	// WORM evidence signature + canonical_json_hash + sealed blob.
	leafB64, _ := evidenceAny["soc_merkle_leaf_b64"].(string)
	if leafB64 == "" {
		fmt.Fprintln(os.Stderr, "reject: missing soc_merkle_leaf_b64")
		os.Exit(2)
	}
	leafBytes, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject: soc_merkle_leaf_b64 decode: %v\n", err)
		os.Exit(2)
	}
	canonicalHashHex, _ := evidenceAny["canonical_json_hash"].(string)
	if canonicalHashHex == "" {
		fmt.Fprintln(os.Stderr, "reject: missing canonical_json_hash")
		os.Exit(2)
	}
	canonicalLeafAny, err := decodeJSONUseNumber(leafBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject: soc_merkle_leaf JSON parse: %v\n", err)
		os.Exit(2)
	}
	canonicalLeafBytes, err := marshalCanonical(canonicalLeafAny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject: soc_merkle_leaf canonical encode: %v\n", err)
		os.Exit(2)
	}
	if !bytes.Equal(canonicalLeafBytes, leafBytes) {
		fmt.Fprintln(os.Stderr, "reject: soc_merkle_leaf is not canonical deterministic JSON")
		os.Exit(2)
	}
	expectedCanonicalHash, err := hex.DecodeString(canonicalHashHex)
	if err != nil || len(expectedCanonicalHash) != sha256.Size {
		fmt.Fprintln(os.Stderr, "reject: canonical_json_hash invalid")
		os.Exit(2)
	}
	calcCanonical := sha256.Sum256(canonicalLeafBytes)
	if subtle.ConstantTimeCompare(calcCanonical[:], expectedCanonicalHash) != 1 {
		fmt.Fprintln(os.Stderr, "reject: canonical_json_hash mismatch")
		os.Exit(2)
	}

	sealedB64, _ := evidenceAny["sealed_blob_b64"].(string)
	if sealedB64 == "" {
		fmt.Fprintln(os.Stderr, "reject: missing sealed_blob_b64")
		os.Exit(2)
	}
	sealedBytes, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil || len(sealedBytes) <= gcmNonceSize {
		fmt.Fprintln(os.Stderr, "reject: sealed_blob_b64 invalid")
		os.Exit(2)
	}
	ciphertext := sealedBytes[gcmNonceSize:]

	wormSigB64, _ := evidenceAny["worm_ed25519_sig"].(string)
	if wormSigB64 == "" {
		fmt.Fprintln(os.Stderr, "reject: missing worm_ed25519_sig")
		os.Exit(2)
	}
	wormSig, err := base64.StdEncoding.DecodeString(wormSigB64)
	if err != nil || len(wormSig) != ed25519.SignatureSize {
		fmt.Fprintln(os.Stderr, "reject: invalid worm_ed25519_sig encoding/length")
		os.Exit(2)
	}

	// Extract actor/action_id/action_type and logical clock from the leaf preimage JSON.
	leafObj, ok := canonicalLeafAny.(map[string]any)
	if !ok {
		fmt.Fprintln(os.Stderr, "reject: soc_merkle_leaf must be a JSON object")
		os.Exit(2)
	}
	actor, _ := leafObj["actor"].(string)
	actionID, _ := leafObj["action_id"].(string)
	actionType, _ := leafObj["type"].(string)
	tsStr, _ := leafObj["timestamp"].(string)
	payloadB64, _ := leafObj["payload"].(string)
	if actor == "" || actionID == "" || actionType == "" || tsStr == "" {
		fmt.Fprintln(os.Stderr, "reject: soc_merkle_leaf missing required fields")
		os.Exit(2)
	}
	if payloadB64 == "" {
		fmt.Fprintln(os.Stderr, "reject: soc_merkle_leaf missing payload (forensic actor attribution)")
		os.Exit(2)
	}
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject: timestamp parse: %v\n", err)
		os.Exit(2)
	}
	logicalClock := ts.UnixNano()
	digest := wormEvidenceDigest(ciphertext, logicalClock, actor, actionID, actionType)
	if !ed25519.Verify(pub, digest, wormSig) {
		fmt.Fprintln(os.Stderr, "reject: worm evidence signature invalid")
		os.Exit(2)
	}

	// Actor hardening requirement: payload must include source_ip attribution.
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject: leaf payload base64 decode: %v\n", err)
		os.Exit(2)
	}
	var payloadObj map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadObj); err != nil {
		fmt.Fprintf(os.Stderr, "reject: leaf payload JSON parse: %v\n", err)
		os.Exit(2)
	}
	sourceIP, _ := payloadObj["source_ip"].(string)
	if sourceIP == "" {
		fmt.Fprintln(os.Stderr, "reject: actor attribution missing source_ip")
		os.Exit(2)
	}

	// Inclusion proof (RFC6962).
	merkleProofAny, ok := obj["merkle_proof"].([]any)
	if !ok {
		fmt.Fprintln(os.Stderr, "reject: missing merkle_proof array")
		os.Exit(2)
	}
	if merkleProofAny == nil {
		fmt.Fprintln(os.Stderr, "reject: missing merkle_proof")
		os.Exit(2)
	}

	proofSteps := make([][]byte, 0, len(merkleProofAny))
	for i, sAny := range merkleProofAny {
		s, ok := sAny.(string)
		if !ok || s == "" {
			fmt.Fprintf(os.Stderr, "reject: merkle_proof[%d] empty/malformed\n", i)
			os.Exit(2)
		}
		step, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(step) != stepLen {
			fmt.Fprintf(os.Stderr, "reject: merkle_proof[%d] decode/len failed: %v\n", i, err)
			os.Exit(2)
		}
		proofSteps = append(proofSteps, step)
	}

	// recompute leaf hash (requirement) — leafHash is used inside verifyInclusionProof,
	// but we compute it explicitly to keep the audit story explicit.
	_ = leafHash(leafBytes)

	if !verifyInclusionProof(leafBytes, proofSteps, rootBytes) {
		fmt.Fprintln(os.Stderr, "reject: merkle inclusion proof invalid (or root mismatch)")
		os.Exit(2)
	}

	// Merkle daily roots chained signature.
	prevRootHex, _ := evidenceAny["merkle_prev_root_hash"].(string)
	var prevRoot []byte
	if prevRootHex != "" {
		prevRoot, err = hex.DecodeString(prevRootHex)
		if err != nil || len(prevRoot) != sha256.Size {
			fmt.Fprintln(os.Stderr, "reject: merkle_prev_root_hash invalid")
			os.Exit(2)
		}
	} else {
		prevRoot = nil
	}
	chainedDigest := computeChainedRoot(prevRoot, rootBytes)
	if len(chainedDigest) != sha256.Size {
		fmt.Fprintln(os.Stderr, "reject: chained digest wrong length")
		os.Exit(2)
	}
	if !ed25519.Verify(pub, chainedDigest, sigRoot) {
		fmt.Fprintln(os.Stderr, "reject: merkle daily roots signature invalid")
		os.Exit(2)
	}

	// Success.
	ts2 := time.Now().UTC().Format(time.RFC3339Nano)
	fmt.Printf("ACCEPT %s\n", ts2)
}
