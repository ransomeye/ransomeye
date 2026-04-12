package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/storage/authority"
	pb "ransomeye/proto/ransomeyepb"
)

const mishkaProtocolVersionV1 = uint32(1)

var signalReplayGate = checkSignalReplayGuard
var signalCommitBatch = authority.CommitPartitionBatch
var signalResolveAuthority = resolvePRD13AuthorityAndContextSignal
var signalCommitRequiresDBPool = true
var signalResolvePublicKey = resolveSignalEmitterPublicKey

// SendSignal performs cryptographic admission only; durable Mishka authority is written exclusively through
// storage/authority.CommitPartitionBatch (single transactional kernel). This handler does not embed a second storage truth.
func (h *Handlers) SendSignal(ctx context.Context, req *pb.SignalEnvelope) (*pb.SignalAck, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}

	// PRD-08 stage 1 prerequisite: canonical payload bytes exist and are canonical.
	canonicalPayload, err := CanonicalizeStrictJSONRFC8785Like(req.GetCanonicalPayloadJson())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: invalid_canonical")
	}
	if !bytes.Equal(canonicalPayload, req.GetCanonicalPayloadJson()) {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: invalid_canonical")
	}

	// PRD-03: protocol_version is explicit.
	if req.GetProtocolVersion() != mishkaProtocolVersionV1 {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: schema_version mismatch")
	}

	// PRD-08 stages 2–3 (PRD-02 order): identity fields before signing_context validation.
	// PRD-03 identity fields: fixed width, lowercase hex.
	systemID, err := parseLowerHexFixed(req.GetSystemId(), 32)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: invalid_identity")
	}
	if req.GetIdentityVersion() != 1 {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: invalid_identity")
	}
	emitterType := req.GetEmitterType()
	if emitterType != pb.EmitterType_EMITTER_TYPE_AGENT && emitterType != pb.EmitterType_EMITTER_TYPE_PROBE {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: invalid_identity")
	}
	emitterID, err := parseLowerHexFixed(req.GetEmitterId(), 16)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: invalid_identity")
	}

	bootSessionID, err := parseLowerHexFixed(req.GetBootSessionId(), 32)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: invalid_identity")
	}

	// PRD-08 stage 3: signing_context present; allowed set is enforced when resolving the emitter key.
	if strings.TrimSpace(req.GetSigningContext()) == "" {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: invalid_signing_context")
	}

	// PRD-08 stage 4 prerequisite: recompute payload_hash and partition_context.
	wantPayloadHash := sha256.Sum256(canonicalPayload)
	gotPayloadHash, err := parseLowerHexFixed(req.GetPayloadHash(), 32)
	if err != nil || !bytes.Equal(gotPayloadHash, wantPayloadHash[:]) {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: hash_mismatch")
	}

	identityBytes := buildIdentityBytes(systemID, byte(req.GetIdentityVersion()), emitterType, emitterID)
	pc := sha256.Sum256(append(append([]byte(nil), canonicalPayload...), identityBytes...))
	wantPartitionContext := pc[:16]
	gotPartitionContext, err := parseLowerHexFixed(req.GetPartitionContext(), 16)
	if err != nil || !bytes.Equal(gotPartitionContext, wantPartitionContext) {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: hash_mismatch")
	}

	// PRD-03 signature bytes are required to be Ed25519 size; verification is deferred to the later slice
	// where identity->key binding is validated against signed namespace/trust material.
	if len(req.GetSignature()) != ed25519.SignatureSize {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: auth_failure")
	}

	messageID, err := parseLowerHexFixed(req.GetMessageId(), 32)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: hash_mismatch")
	}
	recomputedMID, err := ComputeSignalMessageID(req)
	if err != nil || recomputedMID != req.GetMessageId() {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: hash_mismatch")
	}
	signingInput, err := ComputeSignalSigningInput(req)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: auth_failure")
	}
	pubKey, err := signalResolvePublicKey(ctx, h, req.GetEmitterType(), req.GetEmitterId(), req.GetSigningContext(), req.GetLogicalClock())
	if err != nil {
		if mapped := statusFromAuthorityFailure(err); mapped != nil {
			return nil, mapped
		}
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: auth_failure")
	}
	if !ed25519.Verify(pubKey, signingInput, req.GetSignature()) {
		return nil, status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: auth_failure")
	}

	if h.dbPool == nil && signalCommitRequiresDBPool {
		return nil, status.Error(codes.FailedPrecondition, "REJECT: authoritative storage unavailable")
	}
	if len(h.prd13CommitKey) != ed25519.PrivateKeySize || strings.TrimSpace(h.prd13CommitKeyID) == "" || h.prd13CommitEpoch <= 0 {
		return nil, status.Error(codes.FailedPrecondition, "REJECT: prd13 commit signing key missing")
	}

	logicalShardID, err := parsePRD13LogicalShardID()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "REJECT_BEFORE_QUEUE: invalid_logical_shard_id")
	}
	partitionID := prd13PartitionID()
	if partitionID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "REJECT_BEFORE_QUEUE: invalid_partition_id")
	}

	if err := signalReplayGate(ctx, h.dbPool, partitionID, logicalShardID, emitterID, bootSessionID, req.GetLogicalClock(), messageID); err != nil {
		return nil, err
	}

	authorityRefs, authoritySnapshots, execHash, err := signalResolveAuthority()
	if err != nil {
		if mapped := statusFromAuthorityFailure(err); mapped != nil {
			return nil, mapped
		}
		return nil, status.Error(codes.Internal, "REJECT: authority context resolution failed")
	}
	if err := authority.RequireSingleTrustSnapshotBindingForSignal(authorityRefs); err != nil {
		if mapped := statusFromAuthorityFailure(err); mapped != nil {
			return nil, mapped
		}
		return nil, status.Error(codes.Internal, "REJECT: authority binding validation failed")
	}
	if err := authority.AssertCommittedTrustSnapshotsMatchSignalBoundClosure(ctx, h.dbPool, authoritySnapshots); err != nil {
		if mapped := statusFromAuthorityFailure(err); mapped != nil {
			return nil, mapped
		}
		return nil, status.Error(codes.Internal, "REJECT: trust snapshot DB closure check failed")
	}

	logicalClock := req.GetLogicalClock()
	schemaVersion := signalSchemaVersionFromProtocolVersion(req.GetProtocolVersion())
	schemaTransformHash := authority.SchemaTransformHash(schemaVersion, execHash)
	payloadHash := wantPayloadHash
	recordID := append([]byte(nil), messageID...)
	emitterIDCopy := append([]byte(nil), emitterID...)
	bootSessionIDCopy := append([]byte(nil), bootSessionID...)
	partitionContextCopy := append([]byte(nil), gotPartitionContext...)
	signatureCopy := append([]byte(nil), req.GetSignature()...)

	opts := authority.CommitOptions{
		PartitionID:          partitionID,
		PartitionEpoch:       0,
		ExecutionContextHash: execHash,
		PrivateKey:           h.prd13CommitKey,
		KeyID:                h.prd13CommitKeyID,
		KeyEpoch:             h.prd13CommitEpoch,
		AuthorityRefs:        authorityRefs,
		AuthoritySnapshots:   authoritySnapshots,
		Records: []authority.RecordDraft{{
			RecordType:            "SIGNAL",
			RecordVersion:         "signal_record_v1",
			StageOrder:            1,
			RecordID:              recordID,
			MessageID:             messageID,
			AgentID:               emitterIDCopy,
			BootSessionID:         bootSessionIDCopy,
			LogicalClock:          &logicalClock,
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadText:  nil,
			CanonicalPayloadBytes: canonicalPayload,
			CanonicalPayloadHash:  wantPayloadHash,
			PayloadHash:           &payloadHash,
			Signature:             signatureCopy,
			PartitionContext:      partitionContextCopy,
			SchemaVersion:         &schemaVersion,
			SchemaTransformHash:   &schemaTransformHash,
		}},
		ReplayGuard: []authority.ReplayGuardAdmittedRow{{
			LogicalShardID: logicalShardID,
			EmitterID:      emitterIDCopy,
			BootSessionID:  bootSessionIDCopy,
			LogicalClock:   logicalClock,
			MessageID:      messageID,
		}},
	}
	if err := signalCommitBatch(ctx, h.dbPool, opts); err != nil {
		if mapped := statusFromAuthorityFailure(err); mapped != nil {
			return nil, mapped
		}
		if isReplayDuplicateConflict(err) {
			return nil, status.Error(codes.PermissionDenied, "REJECT: REJECT_DUPLICATE")
		}
		return nil, status.Error(codes.Unavailable, "REJECT: authoritative handoff failed")
	}

	_ = systemID
	_ = identityBytes
	return &pb.SignalAck{Accepted: true, ServerClock: h.localClock.Load()}, nil
}

func resolveSignalEmitterPublicKey(ctx context.Context, h *Handlers, emitterType pb.EmitterType, emitterID string, signingContext string, logicalClock uint64) (ed25519.PublicKey, error) {
	var keyType string
	switch emitterType {
	case pb.EmitterType_EMITTER_TYPE_AGENT:
		keyType = "AGENT"
	case pb.EmitterType_EMITTER_TYPE_PROBE:
		keyType = "PROBE"
	default:
		return nil, authority.FailType1("INPUT_ERROR", errors.New("invalid emitter_type"))
	}
	if h == nil || h.dbPool == nil {
		return nil, authority.FailType2("STATE_INCONSISTENCY", errors.New("authoritative key resolver unavailable"))
	}
	return authority.ResolveEmitterPublicKeyByIdentity(ctx, h.dbPool, keyType, emitterID, signingContext, logicalClock, boundTrustSnapshotVersionFromEnv())
}

func boundTrustSnapshotVersionFromEnv() string {
	raw := strings.TrimSpace(os.Getenv(prd13AuthorityBindingsEnv))
	if raw == "" {
		return ""
	}
	var refs []authorityRefJSON
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return ""
	}
	for _, r := range refs {
		if strings.TrimSpace(strings.ToUpper(r.Type)) == "CONFIG" && strings.TrimSpace(r.ID) == "trust_snapshot" {
			return strings.TrimSpace(r.Version)
		}
	}
	return ""
}

func statusFromAuthorityFailure(err error) error {
	f, ok := authority.FailureAs(err)
	if !ok {
		return nil
	}
	switch f.Type {
	case authority.FailureType1InputError:
		if f.Code == "SIGNAL_AUTH_FAILURE" {
			return status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: auth_failure")
		}
		return status.Error(codes.InvalidArgument, "REJECT_BEFORE_QUEUE: "+f.Error())
	case authority.FailureType2StateInconsistency:
		return status.Error(codes.Unavailable, "REJECT: "+f.Error())
	case authority.FailureType3IntegrityFailure:
		return status.Error(codes.PermissionDenied, "REJECT: "+f.Error())
	default:
		return status.Error(codes.Internal, "REJECT: authority failure")
	}
}

func isReplayDuplicateConflict(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	if pgErr.Code != "23505" {
		return false
	}
	return strings.Contains(strings.ToLower(pgErr.ConstraintName), "replay_guard")
}

func signalSchemaVersionFromProtocolVersion(protocolVersion uint32) string {
	if protocolVersion == mishkaProtocolVersionV1 {
		return "signal_schema_v1"
	}
	return "signal_schema_unknown"
}

func checkSignalReplayGuard(ctx context.Context, pool *pgxpool.Pool, partitionID int64, logicalShardID, emitterID, bootSessionID []byte, logicalClock uint64, messageID []byte) error {
	if pool == nil {
		return status.Error(codes.FailedPrecondition, "REJECT: authoritative replay guard unavailable")
	}
	lastLogicalClock, lastMessageID, found, err := authority.LastCommittedReplayCursor(ctx, pool, partitionID, logicalShardID, emitterID, bootSessionID)
	if err != nil {
		return status.Error(codes.Unavailable, "REJECT: committed replay cursor read failed")
	}
	if !found {
		if logicalClock != 0 {
			return status.Error(codes.PermissionDenied, "REJECT: REJECT_GAP")
		}
		return nil
	}
	switch {
	case logicalClock < lastLogicalClock:
		return status.Error(codes.PermissionDenied, "REJECT: REJECT_REGRESSION")
	case logicalClock == lastLogicalClock:
		if bytes.Equal(lastMessageID, messageID) {
			return status.Error(codes.PermissionDenied, "REJECT: REJECT_DUPLICATE")
		}
		return status.Error(codes.PermissionDenied, "REJECT: REJECT_DUPLICATE")
	case logicalClock > lastLogicalClock+1:
		return status.Error(codes.PermissionDenied, "REJECT: REJECT_GAP")
	default:
		return nil
	}
}

type authorityRefJSON struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

type authoritySnapshotJSON struct {
	Type                 string `json:"type"`
	ID                   string `json:"id"`
	Version              string `json:"version"`
	CanonicalPayloadText string `json:"canonical_payload_text"`
	PayloadHashHex       string `json:"payload_hash_hex"`
	SignatureHex         string `json:"signature_hex"`
}

const prd13ExecutionContextHashEnv = "RANSOMEYE_EXECUTION_CONTEXT_HASH"
const prd13AuthorityBindingsEnv = "RANSOMEYE_PRD13_AUTHORITY_BINDINGS_JSON"
const prd13AuthoritySnapshotsEnv = "RANSOMEYE_PRD13_AUTHORITY_SNAPSHOTS_JSON"

func resolvePRD13AuthorityAndContextSignal() ([]authority.AuthorityRef, []authority.SnapshotUpsert, [32]byte, error) {
	refs, err := parseAuthorityBindingsEnvSignal()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	snaps, hashes, err := parseAuthoritySnapshotsEnvSignal()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	if len(refs) == 0 {
		return nil, nil, [32]byte{}, authority.FailType1("MISSING_AUTHORITY_SET", errors.New("authority bindings missing"))
	}
	if err := authority.RequireSingleTrustSnapshotBindingForSignal(refs); err != nil {
		return nil, nil, [32]byte{}, err
	}
	keys := make([]string, 0, len(refs))
	for _, r := range refs {
		keys = append(keys, r.Type+"\x00"+r.ID+"\x00"+r.Version)
	}
	sort.Strings(keys)
	sum := sha256.New()
	for _, k := range keys {
		h, ok := hashes[k]
		if !ok {
			return nil, nil, [32]byte{}, authority.FailType2("STATE_INCONSISTENCY", fmt.Errorf("missing payload_hash for bound authority %s", k))
		}
		_, _ = sum.Write(h[:])
	}
	var execHash [32]byte
	copy(execHash[:], sum.Sum(nil))
	if envExec, provided, envErr := parseExecutionContextHashSignal(); envErr != nil {
		return nil, nil, [32]byte{}, envErr
	} else if provided && envExec != execHash {
		return nil, nil, [32]byte{}, authority.FailType1("INPUT_ERROR", errors.New("execution_context_hash mismatch"))
	} else if provided {
		execHash = envExec
	}
	return refs, snaps, execHash, nil
}

func parseExecutionContextHashSignal() ([32]byte, bool, error) {
	raw := strings.TrimSpace(os.Getenv(prd13ExecutionContextHashEnv))
	if raw == "" {
		return authority.ZeroHash32, false, nil
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 32 {
		return [32]byte{}, false, authority.FailType1("INPUT_ERROR", fmt.Errorf("%s must be 64 hex chars", prd13ExecutionContextHashEnv))
	}
	var out [32]byte
	copy(out[:], b)
	return out, true, nil
}

func parseAuthorityBindingsEnvSignal() ([]authority.AuthorityRef, error) {
	raw := strings.TrimSpace(os.Getenv(prd13AuthorityBindingsEnv))
	if raw == "" {
		return nil, nil
	}
	var in []authorityRefJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, authority.FailType1("INPUT_ERROR", fmt.Errorf("%s invalid json: %w", prd13AuthorityBindingsEnv, err))
	}
	out := make([]authority.AuthorityRef, 0, len(in))
	for _, r := range in {
		if strings.TrimSpace(r.Type) == "" || strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Version) == "" {
			return nil, authority.FailType1("INPUT_ERROR", fmt.Errorf("%s missing type/id/version", prd13AuthorityBindingsEnv))
		}
		out = append(out, authority.AuthorityRef{Type: r.Type, ID: r.ID, Version: r.Version})
	}
	return out, nil
}

func parseAuthoritySnapshotsEnvSignal() ([]authority.SnapshotUpsert, map[string][32]byte, error) {
	raw := strings.TrimSpace(os.Getenv(prd13AuthoritySnapshotsEnv))
	if raw == "" {
		return nil, map[string][32]byte{}, nil
	}
	var in []authoritySnapshotJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, nil, authority.FailType1("INPUT_ERROR", fmt.Errorf("%s invalid json: %w", prd13AuthoritySnapshotsEnv, err))
	}
	out := make([]authority.SnapshotUpsert, 0, len(in))
	hashes := make(map[string][32]byte, len(in))
	for _, s := range in {
		if strings.TrimSpace(s.Type) == "" || strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.Version) == "" {
			return nil, nil, authority.FailType1("INPUT_ERROR", fmt.Errorf("%s missing type/id/version", prd13AuthoritySnapshotsEnv))
		}
		ph, err := hex.DecodeString(strings.TrimSpace(s.PayloadHashHex))
		if err != nil || len(ph) != 32 {
			return nil, nil, authority.FailType1("INPUT_ERROR", fmt.Errorf("%s payload_hash_hex invalid", prd13AuthoritySnapshotsEnv))
		}
		sig, err := hex.DecodeString(strings.TrimSpace(s.SignatureHex))
		if err != nil || len(sig) == 0 {
			return nil, nil, authority.FailType1("INPUT_ERROR", fmt.Errorf("%s signature_hex invalid", prd13AuthoritySnapshotsEnv))
		}
		sum := sha256.Sum256([]byte(s.CanonicalPayloadText))
		if !bytes.Equal(sum[:], ph) {
			return nil, nil, authority.FailType1("PAYLOAD_HASH_MISMATCH", fmt.Errorf("%s payload_hash mismatch for %s/%s/%s", prd13AuthoritySnapshotsEnv, s.Type, s.ID, s.Version))
		}
		var ph32 [32]byte
		copy(ph32[:], ph)
		hashes[s.Type+"\x00"+s.ID+"\x00"+s.Version] = ph32
		out = append(out, authority.SnapshotUpsert{
			Type:                 s.Type,
			ID:                   s.ID,
			Version:              s.Version,
			CanonicalPayloadText: s.CanonicalPayloadText,
			PayloadHash:          ph32,
			Signature:            sig,
		})
	}
	return out, hashes, nil
}

func parseLowerHexFixed(raw string, wantBytes int) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("missing")
	}
	// Enforce lowercase hex without normalization (PRD-03).
	if strings.ToLower(s) != s {
		return nil, errors.New("not lowercase")
	}
	if len(s) != wantBytes*2 {
		return nil, errors.New("length")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != wantBytes {
		return nil, errors.New("decode")
	}
	return b, nil
}

// ComputeSignalMessageID returns PRD-03 message_id (SHA-256 hex) for a populated SignalEnvelope.
func ComputeSignalMessageID(req *pb.SignalEnvelope) (string, error) {
	if req == nil {
		return "", errors.New("nil request")
	}
	obj := map[string]any{
		"protocol_version":       int64(req.GetProtocolVersion()),
		"signing_context":        req.GetSigningContext(),
		"system_id":              req.GetSystemId(),
		"identity_version":       int64(req.GetIdentityVersion()),
		"emitter_type":           int64(req.GetEmitterType()),
		"emitter_id":             req.GetEmitterId(),
		"boot_session_id":        req.GetBootSessionId(),
		"logical_clock":          req.GetLogicalClock(),
		"partition_context":      req.GetPartitionContext(),
		"payload_hash":           req.GetPayloadHash(),
		"canonical_payload_json": string(req.GetCanonicalPayloadJson()),
	}
	raw, err := encodeCanonicalJSONRFC8785Like(obj)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (h *Handlers) recomputeMessageID(req *pb.SignalEnvelope) (string, error) {
	return ComputeSignalMessageID(req)
}

// ComputeSignalSigningInput returns the Ed25519 message bytes bound to signing_context (PRD-03 / PRD-08).
func ComputeSignalSigningInput(req *pb.SignalEnvelope) ([]byte, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	payloadHash, err := parseLowerHexFixed(req.GetPayloadHash(), 32)
	if err != nil {
		return nil, err
	}
	partitionContext, err := parseLowerHexFixed(req.GetPartitionContext(), 16)
	if err != nil {
		return nil, err
	}
	bootSessionID, err := parseLowerHexFixed(req.GetBootSessionId(), 32)
	if err != nil {
		return nil, err
	}
	emitterID, err := parseLowerHexFixed(req.GetEmitterId(), 16)
	if err != nil {
		return nil, err
	}
	systemID, err := parseLowerHexFixed(req.GetSystemId(), 32)
	if err != nil {
		return nil, err
	}
	identityBytes := buildIdentityBytes(systemID, byte(req.GetIdentityVersion()), req.GetEmitterType(), emitterID)
	logicalClock := req.GetLogicalClock()
	var logicalClockBytes [8]byte
	for i := 0; i < 8; i++ {
		logicalClockBytes[7-i] = byte(logicalClock >> (i * 8))
	}
	out := make([]byte, 0, len(req.GetSigningContext())+32+len(identityBytes)+16+32+8)
	out = append(out, req.GetSigningContext()...)
	out = append(out, payloadHash...)
	out = append(out, identityBytes...)
	out = append(out, partitionContext...)
	out = append(out, bootSessionID...)
	out = append(out, logicalClockBytes[:]...)
	return out, nil
}

func (h *Handlers) recomputeSigningInput(req *pb.SignalEnvelope) ([]byte, error) {
	return ComputeSignalSigningInput(req)
}

func buildIdentityBytes(systemID []byte, identityVersion byte, emitterType pb.EmitterType, emitterID []byte) []byte {
	// PRD-03: identity_bytes = system_id || identity_version || emitter_type || emitter_id
	out := make([]byte, 0, 32+1+1+16)
	out = append(out, systemID...)
	out = append(out, identityVersion)
	switch emitterType {
	case pb.EmitterType_EMITTER_TYPE_AGENT:
		out = append(out, 0x01)
	case pb.EmitterType_EMITTER_TYPE_PROBE:
		out = append(out, 0x02)
	default:
		out = append(out, 0x00)
	}
	out = append(out, emitterID...)
	return out
}

// CanonicalizeStrictJSONRFC8785Like performs a strict parse + deterministic re-encoding sufficient for
// enforcing "canonical JSON bytes" at the schema boundary (PRD-07 / PRD-08).
//
// It fails closed on malformed JSON, trailing data, or unsupported types.
func CanonicalizeStrictJSONRFC8785Like(input []byte) ([]byte, error) {
	if len(bytes.TrimSpace(input)) == 0 {
		return nil, errors.New("empty")
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("invalid json")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing json")
	}
	return encodeCanonicalJSONRFC8785Like(v)
}

func encodeCanonicalJSONRFC8785Like(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, errors.New("invalid json")
			}
			out = append(out, kb...)
			out = append(out, ':')
			vb, err := encodeCanonicalJSONRFC8785Like(t[k])
			if err != nil {
				return nil, err
			}
			out = append(out, vb...)
		}
		out = append(out, '}')
		return out, nil
	case []any:
		out := []byte{'['}
		for i := range t {
			if i > 0 {
				out = append(out, ',')
			}
			vb, err := encodeCanonicalJSONRFC8785Like(t[i])
			if err != nil {
				return nil, err
			}
			out = append(out, vb...)
		}
		out = append(out, ']')
		return out, nil
	case json.Number:
		// Preserve numeric string form deterministically.
		return []byte(t.String()), nil
	case string, bool, nil:
		b, err := json.Marshal(t)
		if err != nil {
			return nil, errors.New("invalid json")
		}
		return b, nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return nil, errors.New("invalid json")
		}
		return b, nil
	}
}

