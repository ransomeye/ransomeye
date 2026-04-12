package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/config"
	"ransomeye/core/internal/identity"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/integrity"
	"ransomeye/core/internal/pipeline"
	"ransomeye/core/internal/storage/authority"
	pb "ransomeye/proto/ransomeyepb"
)

const telemetrySigningContext = signingContextTelemetryEvent

type TelemetryEnvelope struct {
	MessageID          string
	AgentID            string
	ProbeID            string
	SigningContext     string
	Signature          []byte
	SystemIdentityHash string
	BootSessionID      string
	Payload            []byte
}

// CanonicalizePayload parses the fixed-width telemetry payload and rebuilds it
// with BuildCanonicalV1 so field order, endianness, and byte layout remain
// byte-identical across runs.
func (h *Handlers) CanonicalizePayload(payload []byte) ([]byte, ingest.TelemetryV1View, error) {
	canonical, view, _, err := ingest.CanonicalizePayloadBytes(payload)
	if err != nil {
		return nil, ingest.TelemetryV1View{}, err
	}
	return canonical, view, nil
}

func (h *Handlers) VerifySigningContext(signingContext string) error {
	if strings.TrimSpace(signingContext) == "" {
		return errors.New("signing_context missing")
	}
	// Telemetry ingress accepts exactly one static context for this message class.
	if signingContext != telemetrySigningContext {
		return errors.New("signing_context invalid")
	}
	if !isKnownSigningContext(signingContext) {
		return errors.New("signing_context invalid")
	}
	return nil
}

func SigningContextRegistryList() []string {
	out := []string{
		signingContextSignedConfig,
		signingContextTelemetryEvent,
		signingContextHeartbeat,
		signingContextWormEvidence,
		signingContextWormDailyRoot,
		signingContextActionDispatch,
		signingContextRequestDetect,
		signingContextRequestNarr,
		signingContextPolicyChange,
		signingContextBundleManifest,
		signingContextMigrationMan,
		signingContextDeceptionEvent,
		signingContextProbeFlowBatch,
		signingContextAgentEnroll,
	}
	sort.Strings(out)
	return out
}

func isKnownSigningContext(contextName string) bool {
	switch contextName {
	case signingContextSignedConfig,
		signingContextTelemetryEvent,
		signingContextHeartbeat,
		signingContextWormEvidence,
		signingContextWormDailyRoot,
		signingContextActionDispatch,
		signingContextRequestDetect,
		signingContextRequestNarr,
		signingContextPolicyChange,
		signingContextBundleManifest,
		signingContextMigrationMan,
		signingContextDeceptionEvent,
		signingContextProbeFlowBatch,
		signingContextAgentEnroll:
		return true
	default:
		return false
	}
}

func (h *Handlers) ComputePayloadHash(canonicalPayload []byte) [32]byte {
	return sha256.Sum256(canonicalPayload)
}

func (h *Handlers) ConstructSigningInput(signingContext string, payloadHash [32]byte) []byte {
	signingInput := make([]byte, 0, len(signingContext)+sha256.Size)
	signingInput = append(signingInput, signingContext...)
	signingInput = append(signingInput, payloadHash[:]...)
	return signingInput
}

func (h *Handlers) VerifyEd25519Signature(ctx context.Context, signingInput, signature []byte) error {
	if len(signature) != ed25519.SignatureSize {
		return errors.New("signature invalid")
	}

	cert, err := identity.PeerCertFromContext(ctx)
	if err != nil {
		return errors.New("signature invalid")
	}
	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("signature invalid")
	}
	if !ed25519.Verify(publicKey, signingInput, signature) {
		return errors.New("signature invalid")
	}
	return nil
}

func (h *Handlers) VerifyIdentityHash(systemIdentityHash string) error {
	normalized := strings.TrimSpace(strings.ToLower(systemIdentityHash))
	if normalized == "" {
		return errors.New("system_identity_hash missing")
	}
	if len(normalized) != sha256.Size*2 {
		return errors.New("system_identity_hash invalid")
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return errors.New("system_identity_hash invalid")
	}
	if strings.TrimSpace(strings.ToLower(h.systemIdentityHash)) == "" {
		return errors.New("system_identity_hash unavailable")
	}
	if normalized != strings.ToLower(h.systemIdentityHash) {
		return errors.New("system_identity_hash mismatch")
	}
	return nil
}

func (h *Handlers) ValidateEnvelopeIdentity(agentIDRaw, probeIDRaw string) (string, [16]byte, error) {
	agentID := strings.TrimSpace(agentIDRaw)
	probeID := strings.TrimSpace(probeIDRaw)

	if agentID != "" && probeID != "" {
		return "", [16]byte{}, errors.New("identity xor violation")
	}
	if agentID == "" && probeID == "" {
		return "", [16]byte{}, errors.New("identity missing")
	}

	parseCanonicalUUID := func(v string) ([16]byte, error) {
		parsed, err := uuid.Parse(v)
		if err != nil || parsed.String() != strings.ToLower(v) {
			return [16]byte{}, errors.New("identity invalid")
		}
		return [16]byte(parsed), nil
	}

	if agentID != "" {
		identityBytes, err := parseCanonicalUUID(agentID)
		if err != nil {
			return "", [16]byte{}, err
		}
		return "agent:" + agentID, identityBytes, nil
	}

	identityBytes, err := parseCanonicalUUID(probeID)
	if err != nil {
		return "", [16]byte{}, err
	}
	return "probe:" + probeID, identityBytes, nil
}

func (h *Handlers) VerifySession(ctx context.Context, bootSessionID string, view ingest.TelemetryV1View, identityKey string) error {
	if strings.TrimSpace(bootSessionID) == "" {
		return errors.New("boot_session_id missing")
	}
	parsedBoot, err := uuid.Parse(strings.TrimSpace(bootSessionID))
	if err != nil || parsedBoot.Version() != 4 {
		return errors.New("boot_session_id invalid")
	}
	canonicalBootSessionID, err := uuid.FromBytes(view.BootSessionID[:])
	if err != nil {
		return errors.New("boot_session_id invalid")
	}
	if canonicalBootSessionID.String() != bootSessionID {
		return errors.New("boot_session_id mismatch")
	}

	peerKind, peerID, err := identity.ExtractPeerIdentity(ctx)
	if err != nil {
		return errors.New("peer identity invalid")
	}
	parts := strings.SplitN(identityKey, ":", 2)
	if len(parts) != 2 {
		return errors.New("identity invalid")
	}
	if parts[0] != peerKind || parts[1] != peerID {
		return errors.New("identity mismatch")
	}
	if peerKind == "agent" && view.AgentID.String() != peerID {
		return errors.New("agent_id mismatch")
	}
	if peerKind == "probe" && view.AgentID.String() != peerID {
		return errors.New("probe_id mismatch")
	}
	if h == nil || h.sessions == nil {
		return errors.New("session unavailable")
	}
	tlsBinding, err := identity.TLSBindingKey(ctx)
	if err != nil {
		return errors.New("tls binding invalid")
	}
	if err := h.sessions.TouchByBinding(parts[1], bootSessionID, tlsBinding); err == nil {
		return nil
	}
	if h.sessions.HasFixationConflict(parts[1], bootSessionID, tlsBinding) {
		return errors.New("session fixation detected")
	}
	return errors.New("session invalid")
}

func (h *Handlers) ComputeExpectedMessageID(identityBytes [16]byte, bootSessionID string, logicalClock uint64, canonicalPayload []byte) (string, error) {
	if strings.TrimSpace(bootSessionID) == "" {
		return "", errors.New("boot_session_id missing")
	}
	parsedBootSession, err := uuid.Parse(bootSessionID)
	if err != nil || parsedBootSession.String() != bootSessionID {
		return "", errors.New("boot_session_id invalid")
	}
	payloadHash := sha256.Sum256(canonicalPayload)
	var logicalClockBE [8]byte
	for i := 0; i < 8; i++ {
		logicalClockBE[7-i] = byte(logicalClock >> (i * 8))
	}
	hasher := sha256.New()
	hasher.Write(identityBytes[:])
	hasher.Write(parsedBootSession[:])
	hasher.Write(logicalClockBE[:])
	hasher.Write(payloadHash[:])
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// ReplayPrecheck decides durable replay for ingest/probe paths.
//
// Authoritative Mishka ingest (dbPool != nil AND RANSOMEYE_PRD13_PARTITION_ID > 0): correctness-bearing
// replay is ONLY authority.CommittedTelemetryReplayPayloadHash (committed replay_guard ∩ partition_records ∩ batch_commit).
// replaySeen, on-disk replay JSON, and replayPend are never consulted for that decision.
//
// Non-authoritative transitional mode (dbPool == nil): replaySeen and optional disk JSON define best-effort
// deduplication only — not PRD-13 durability and must not be confused with authority mode.
//
// Misconfiguration (dbPool != nil but partition_id <= 0) fails closed: a database is present but cannot
// anchor committed replay, so we refuse rather than silently falling back to replaySeen.
//
// beginReplay's replayPend remains in-process admission coordination only, not Mishka durability replay.
func (h *Handlers) ReplayPrecheck(ctx context.Context, tenantID, identityID, bootSessionID, messageID string, contentSHA256 [32]byte) (*pb.TelemetryAck, error) {
	replayKey, err := h.replayKey(tenantID, identityID, bootSessionID, messageID)
	if err != nil {
		return nil, err
	}

	if h.dbPool != nil {
		pid := prd13PartitionID()
		if pid <= 0 {
			return nil, errors.New("prd13 partition_id must be > 0 when database pool is configured (authoritative replay requires committed PRD-13 tables)")
		}
		shard, err := parsePRD13LogicalShardID()
		if err != nil {
			return nil, err
		}
		ident := strings.TrimSpace(identityID)
		if ident == "" {
			return nil, errors.New("identity missing for replay check")
		}
		agentUUID, err := uuid.Parse(ident)
		if err != nil {
			return nil, fmt.Errorf("identity uuid: %w", err)
		}
		bootUUID, err := uuid.Parse(strings.TrimSpace(bootSessionID))
		if err != nil {
			return nil, fmt.Errorf("boot_session uuid: %w", err)
		}
		msgBytes, err := authority.TelemetryMessageIDBytes(messageID)
		if err != nil {
			return nil, err
		}
		found, storedPH, err := authority.CommittedTelemetryReplayPayloadHash(ctx, h.dbPool, pid, shard, agentUUID[:], bootUUID[:], msgBytes)
		if err != nil {
			return nil, err
		}
		if found {
			if storedPH != contentSHA256 {
				return nil, errors.New("message_id reused with different payload hash")
			}
			return h.IdempotentAck(h.localClock.Load()), nil
		}
		return nil, nil
	}

	// NON-AUTHORITATIVE: no DB pool — disk-backed or in-process replaySeen only (development / legacy slice).
	h.replayMu.Lock()
	defer h.replayMu.Unlock()
	if h.replaySeen == nil {
		h.replaySeen = make(map[string][32]byte)
	}
	if storedHash, ok := h.replaySeen[replayKey]; ok {
		if storedHash != contentSHA256 {
			return nil, errors.New("message_id reused with different payload hash")
		}
		return h.IdempotentAck(h.localClock.Load()), nil
	}
	return nil, nil
}

func (h *Handlers) replayKey(tenantID, identityID, bootSessionID, messageID string) (string, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(identityID) == "" || strings.TrimSpace(bootSessionID) == "" || strings.TrimSpace(messageID) == "" {
		return "", errors.New("replay key missing")
	}
	return strings.Join([]string{
		strings.TrimSpace(tenantID),
		strings.TrimSpace(identityID),
		strings.TrimSpace(bootSessionID),
		strings.TrimSpace(messageID),
	}, "|"), nil
}

func (h *Handlers) RejectBeforeQueue(reason string) error {
	message := strings.TrimSpace(reason)
	if message == "" {
		message = "pre-queue verification failed"
	}
	return status.Error(codes.PermissionDenied, "REJECT_BEFORE_QUEUE: "+message)
}

func (h *Handlers) Reject(reason string) error {
	message := strings.TrimSpace(reason)
	if message == "" {
		message = "verification failed"
	}
	return status.Error(codes.PermissionDenied, "REJECT: "+message)
}

func (h *Handlers) IdempotentAck(serverClock int64) *pb.TelemetryAck {
	return &pb.TelemetryAck{
		Accepted:    true,
		ServerClock: serverClock,
	}
}

func (h *Handlers) ForwardToQueue(payload *ingest.VerifiedTelemetry, meta ack.Metadata) (uint64, error) {
	if h == nil {
		return 0, status.Error(codes.FailedPrecondition, "handler not initialized")
	}
	if h.ingestQueue != nil {
		return h.ingestQueue.AdmitWithMetadata(payload, meta)
	}
	if h.schedulerEnqueuer == nil {
		return 0, status.Error(codes.FailedPrecondition, "scheduler not initialized")
	}
	if s, ok := h.schedulerEnqueuer.(*pipeline.Scheduler); ok {
		if err := ingest.EnqueueVerifiedTelemetry(s, payload); err != nil {
			return 0, err
		}
		return uint64(payload.LogicalClock), nil
	}
	return 0, ingest.EnqueueVerifiedTelemetry(h.schedulerEnqueuer, payload)
}

// PRD-02 §6.1 / §6.2:
// system_identity_hash = SHA-256(
//
//	canonical_common_config_bytes ||
//	SHA-256(root_ca_certificate_der) ||
//	expected_database_server_fingerprint_bytes ||
//	worm_public_key_bytes
//
// )
func computeSystemIdentityHash(canonicalConfigBytes, rootCACertificateDER []byte, databaseServerFingerprintHex string, wormPublicKey []byte) (string, error) {
	if len(canonicalConfigBytes) == 0 {
		return "", errors.New("canonical common config missing")
	}
	if len(rootCACertificateDER) == 0 {
		return "", errors.New("root CA certificate missing")
	}
	databaseFingerprint, err := hex.DecodeString(strings.TrimSpace(databaseServerFingerprintHex))
	if err != nil {
		return "", errors.New("database fingerprint invalid")
	}
	if len(wormPublicKey) != ed25519.PublicKeySize {
		return "", errors.New("worm public key invalid")
	}

	rootFingerprint := sha256.Sum256(rootCACertificateDER)
	identityMaterial := make([]byte, 0, len(canonicalConfigBytes)+len(rootFingerprint)+len(databaseFingerprint)+len(wormPublicKey))
	identityMaterial = append(identityMaterial, canonicalConfigBytes...)
	identityMaterial = append(identityMaterial, rootFingerprint[:]...)
	identityMaterial = append(identityMaterial, databaseFingerprint...)
	identityMaterial = append(identityMaterial, wormPublicKey...)
	systemIdentityHash := sha256.Sum256(identityMaterial)
	return hex.EncodeToString(systemIdentityHash[:]), nil
}

func loadSystemIdentityHash() (string, error) {
	cfg, err := config.LoadVerifiedCommonConfig("", config.IntermediateCACertPath)
	if err != nil {
		return "", err
	}
	canonicalConfigBytes, err := config.CanonicalIdentityJSONBytes(cfg)
	if err != nil {
		return "", err
	}
	rootCAPEM, err := os.ReadFile(cfg.Security.CACertPath)
	if err != nil {
		return "", err
	}
	rootCABlock, _ := pem.Decode(rootCAPEM)
	if rootCABlock == nil {
		return "", errors.New("root CA PEM block missing")
	}
	wormPublicKey, err := os.ReadFile(integrity.DefaultWormPubPath)
	if err != nil {
		return "", err
	}
	return computeSystemIdentityHash(canonicalConfigBytes, rootCABlock.Bytes, cfg.Database.ExpectedServerFingerprint, wormPublicKey)
}
