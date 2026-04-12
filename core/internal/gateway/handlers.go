package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/backpressure"
	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/identity"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/pipeline"
	"ransomeye/core/internal/storage"
	pb "ransomeye/proto/ransomeyepb"
)

const maxTelemetryPayloadBytes = 64 * 1024

const replayStorePathEnv = "RANSOMEYE_REPLAY_STORE_PATH"

// replayGuardSourceEnv selects where durable replay deduplication state is rehydrated from on startup.
// Value "committed" = PRD-13 replay_guard + batch_commit_records only (no local replay JSON file).
const replayGuardSourceEnv = "RANSOMEYE_REPLAY_GUARD_SOURCE"

const (
	signingContextSignedConfig   = "ransomeye:v1:config:signed_config"
	signingContextTelemetryEvent = "ransomeye:v1:telemetry:event"
	signingContextHeartbeat      = "ransomeye:v1:telemetry:heartbeat"
	signingContextWormEvidence   = "ransomeye:v1:worm:evidence_record"
	signingContextWormDailyRoot  = "ransomeye:v1:worm:daily_root"
	signingContextActionDispatch = "ransomeye:v1:rpc:action_dispatch"
	signingContextRequestDetect  = "ransomeye:v1:rpc:request_detection"
	signingContextRequestNarr    = "ransomeye:v1:rpc:request_narrative"
	signingContextPolicyChange   = "ransomeye:v1:governance:policy_change"
	signingContextBundleManifest = "ransomeye:v1:update:bundle_manifest"
	signingContextMigrationMan   = "ransomeye:v1:migration:manifest"
	signingContextDeceptionEvent = "ransomeye:v1:deception:event"
	signingContextProbeFlowBatch = "ransomeye:v1:probe:flow_batch"
	signingContextAgentEnroll    = "ransomeye:v1:identity:agent_enrollment"
)

var replayPersistCrashHook func(stage string) error

type Handlers struct {
	pb.UnimplementedRansomEyeServiceServer
	pb.UnimplementedProbeServiceServer

	telemetryCh chan *ingest.VerifiedTelemetry
	dispatcher  *enforcement.ActionDispatcher
	sessions    *identity.SessionManager
	dbPool      *pgxpool.Pool

	localClock atomic.Int64

	payloadPool sync.Pool // *[]byte with cap ~64KB

	validator *Validator

	scheduler         *pipeline.Scheduler
	schedulerEnqueuer ingest.VerifiedTelemetryEnqueuer
	ingestQueue       *pipeline.IngestQueue
	ackController     *ack.Controller
	backpressure      *backpressure.Engine
	prd13CommitKey    ed25519.PrivateKey
	prd13CommitKeyID  string
	prd13CommitEpoch  int64

	// telemetryLastLogical: per-agent strict monotonic logical_clock from agent (replay guard, PRD-14).
	telemetryClockMu sync.Mutex
	telemetryLast    map[string]uint64
	probeLastHash    map[string][32]byte

	systemIdentityHash string

	replayMu sync.Mutex
	// replaySeen is a non-authoritative warm cache for legacy/no-DB deployments only. When dbPool + PRD-13
	// partition are set, ReplayPrecheck and observeAckResult do not use it for correctness-bearing decisions.
	replaySeen map[string][32]byte
	replayPend map[string][32]byte
	replayPath string

	actionStreamMu      sync.Mutex
	actionStreams       map[string]*actionStreamWrapper
	lastBackpressure    backpressure.Assessment
	lastBackpressureSet bool
}

func NewHandlers(telemetryCh chan *ingest.VerifiedTelemetry, dispatcher *enforcement.ActionDispatcher, sessions *identity.SessionManager) *Handlers {
	replayPath := strings.TrimSpace(os.Getenv(replayStorePathEnv))
	h := &Handlers{
		telemetryCh:   telemetryCh,
		dispatcher:    dispatcher,
		sessions:      sessions,
		validator:     nil,
		telemetryLast: make(map[string]uint64),
		probeLastHash: make(map[string][32]byte),
		replaySeen:    make(map[string][32]byte),
		replayPend:    make(map[string][32]byte),
		replayPath:    replayPath,
		ackController: ack.NewController(),
		backpressure:  backpressure.NewEngine(),
		actionStreams: make(map[string]*actionStreamWrapper),
	}
	h.ackController.SetObserver(h.observeAckResult)
	if err := h.loadReplayStore(); err != nil {
		panic(err)
	}
	h.payloadPool.New = func() any {
		b := make([]byte, 0, maxTelemetryPayloadBytes)
		return &b
	}
	return h
}

type replayStoreOnDisk struct {
	Version int               `json:"version"`
	Entries map[string]string `json:"entries"`
}

func (h *Handlers) loadReplayStore() error {
	if h == nil {
		return nil
	}
	if ReplayGuardCommittedSource() {
		return nil
	}
	// If a DB pool is already set (unusual at ctor time), never hydrate replay from disk as truth.
	if replayAuthoritativeIngest(h) {
		return nil
	}
	if h.replayPath == "" {
		return nil
	}
	raw, err := os.ReadFile(h.replayPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var store replayStoreOnDisk
	if err := json.Unmarshal(raw, &store); err != nil {
		return err
	}
	if store.Version != 1 {
		return errors.New("unsupported replay store version")
	}
	for replayKey, payloadHashHex := range store.Entries {
		if strings.TrimSpace(replayKey) == "" {
			return errors.New("replay store key invalid")
		}
		payloadHashBytes, err := hex.DecodeString(payloadHashHex)
		if err != nil || len(payloadHashBytes) != 32 {
			return errors.New("replay store payload hash invalid")
		}
		var payloadHash [32]byte
		copy(payloadHash[:], payloadHashBytes)
		h.replaySeen[replayKey] = payloadHash
	}
	return nil
}

func (h *Handlers) persistReplayStoreLocked() error {
	if h == nil || h.replayPath == "" {
		return nil
	}
	store := replayStoreOnDisk{
		Version: 1,
		Entries: make(map[string]string, len(h.replaySeen)),
	}
	for replayKey, payloadHash := range h.replaySeen {
		store.Entries[replayKey] = hex.EncodeToString(payloadHash[:])
	}
	blob, err := json.Marshal(store)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.replayPath), 0o755); err != nil {
		return err
	}
	return persistReplayStoreAtomic(h.replayPath, blob)
}

func persistReplayStoreAtomic(path string, blob []byte) error {
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(blob); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if replayPersistCrashHook != nil {
		if err := replayPersistCrashHook("after_tmp_fsync"); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dirFD, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dirFD.Close()
	if err := dirFD.Sync(); err != nil {
		return fmt.Errorf("fsync replay directory: %w", err)
	}
	return nil
}

func (h *Handlers) SetValidator(v *Validator) {
	h.validator = v
}

func (h *Handlers) SetScheduler(s *pipeline.Scheduler) {
	h.scheduler = s
	h.schedulerEnqueuer = s
	if h.ingestQueue == nil {
		h.ingestQueue = pipeline.NewIngestQueue(1024)
	}
	if h.scheduler != nil {
		h.scheduler.SetAcker(h.ackController)
	}
	if h.scheduler != nil && h.ingestQueue != nil {
		h.scheduler.SetIngestQueue(h.ingestQueue)
	}
}

func (h *Handlers) SetIngestQueue(q *pipeline.IngestQueue) {
	h.ingestQueue = q
	if h.scheduler != nil {
		h.scheduler.SetIngestQueue(q)
	}
}

// BackpressureEngine returns the gateway's admission backpressure engine.
// Pipeline workers may share this engine so that hub backpressure propagates
// to the ingest boundary (RESOURCE_EXHAUSTED) after retry exhaustion.
func (h *Handlers) BackpressureEngine() *backpressure.Engine {
	return h.backpressure
}

func (h *Handlers) observeAckResult(meta ack.Metadata, result ack.Result) {
	if h == nil || meta.ReplayKey == "" {
		return
	}
	h.replayMu.Lock()
	defer h.replayMu.Unlock()
	delete(h.replayPend, meta.ReplayKey)
	if result.State != ack.StateSuccess {
		return
	}
	if replayAuthoritativeIngest(h) {
		return
	}
	h.replaySeen[meta.ReplayKey] = meta.ContentSHA256
	if ReplayGuardCommittedSource() {
		return
	}
	_ = h.persistReplayStoreLocked()
}

// beginReplay coordinates in-process admission (replayPend + ingest queue) so two concurrent RPCs with the
// same replay key do not race the pipeline. It is NOT Mishka durability replay: when replayAuthoritativeIngest
// is true, committed duplicate detection is solely CommittedTelemetryReplayPayloadHash + worker commit, not this map.
func (h *Handlers) beginReplay(meta ack.Metadata) (bool, error) {
	if h == nil || meta.ReplayKey == "" {
		return false, errors.New("replay key missing")
	}
	h.replayMu.Lock()
	defer h.replayMu.Unlock()
	if h.replayPend == nil {
		h.replayPend = make(map[string][32]byte)
	}
	if pendingHash, ok := h.replayPend[meta.ReplayKey]; ok {
		if pendingHash != meta.ContentSHA256 {
			return false, errors.New("message_id reused with different payload hash")
		}
		return true, nil
	}
	if h.ingestQueue != nil {
		pendingMeta, found, err := h.ingestQueue.PendingByReplayKey(meta.ReplayKey)
		if err != nil {
			return false, err
		}
		if found {
			if pendingMeta.ContentSHA256 != meta.ContentSHA256 {
				return false, errors.New("message_id reused with different payload hash")
			}
			h.replayPend[meta.ReplayKey] = meta.ContentSHA256
			return true, nil
		}
	}
	h.replayPend[meta.ReplayKey] = meta.ContentSHA256
	return false, nil
}

func (h *Handlers) waitForCommit(meta ack.Metadata) error {
	if h == nil || h.ackController == nil {
		return errors.New("ack controller unavailable")
	}
	result := h.ackController.Wait(meta)
	if result.State == ack.StateSuccess {
		return nil
	}
	if result.Err != nil {
		return result.Err
	}
	return errors.New("commit failed")
}

func (h *Handlers) SetSchedulerEnqueuer(q ingest.VerifiedTelemetryEnqueuer) {
	h.schedulerEnqueuer = q
}

// ReleaseTelemetryPayload returns canonical payload bytes to the pool.
func (h *Handlers) ReleaseTelemetryPayload(ev *ingest.VerifiedTelemetry) {
	if ev == nil {
		return
	}
	if ev.Payload == nil {
		return
	}
	if cap(ev.Payload) < maxTelemetryPayloadBytes/4 {
		ev.Payload = nil
		return
	}
	b := ev.Payload[:0]
	ev.Payload = nil
	h.payloadPool.Put(&b)
}

func (h *Handlers) SetDBPool(pool *pgxpool.Pool) {
	h.dbPool = pool
	if replayAuthoritativeIngest(h) {
		h.replayMu.Lock()
		// Disk / startup JSON is not durability truth when DB-backed replay is active (cleared on pool bind).
		h.replaySeen = make(map[string][32]byte)
		h.replayMu.Unlock()
	}
}

func (h *Handlers) SetPRD13CommitSigner(privateKey ed25519.PrivateKey, keyID string, keyEpoch int64) {
	h.prd13CommitKey = privateKey
	h.prd13CommitKeyID = strings.TrimSpace(keyID)
	h.prd13CommitEpoch = keyEpoch
}

// ReplayGuardCommittedSource reports whether ingest replay state is rehydrated strictly from committed PRD-13 tables.
func ReplayGuardCommittedSource() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(replayGuardSourceEnv)), "committed")
}

// ReloadCommittedReplayGuard is retained for API compatibility. With a configured DB pool and positive
// partition id, Mishka-authoritative ingest uses ReplayPrecheck against committed PRD-13 tables on every
// request — there is no separate replay cache to warm. Misconfigured db+partition (pool set, id <= 0) fails
// closed because replaySeen must not substitute for committed replay in that case.
func (h *Handlers) ReloadCommittedReplayGuard(ctx context.Context) error {
	if h == nil {
		return errors.New("nil handlers")
	}
	if h.dbPool == nil {
		return errors.New("reload replay guard: db pool not configured")
	}
	if prd13PartitionID() <= 0 {
		return errors.New("reload replay guard: RANSOMEYE_PRD13_PARTITION_ID must be > 0 when db pool is configured")
	}
	_ = ctx
	return nil
}

func prd13PartitionID() int64 {
	s := strings.TrimSpace(os.Getenv("RANSOMEYE_PRD13_PARTITION_ID"))
	if s == "" {
		// Default single-partition Mishka: tests and sterile env must not require env injection.
		return 1
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

// replayAuthoritativeIngest is true for Mishka-authoritative telemetry/probe ingest: committed PRD-13 tables
// are the sole durability truth for replay (ReplayPrecheck). replaySeen, replay JSON, and observeAckResult
// must not define replay in this mode. Requires both a database pool and a positive partition id.
func replayAuthoritativeIngest(h *Handlers) bool {
	return h != nil && h.dbPool != nil && prd13PartitionID() > 0
}

func parsePRD13LogicalShardID() ([]byte, error) {
	s := strings.TrimSpace(os.Getenv("RANSOMEYE_PRD13_LOGICAL_SHARD_ID"))
	if s == "" {
		return make([]byte, 32), nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%s must be 64 hex chars (32 bytes)", "RANSOMEYE_PRD13_LOGICAL_SHARD_ID")
	}
	return b, nil
}

func (h *Handlers) SendTelemetry(ctx context.Context, req *pb.TelemetryEnvelope) (*pb.TelemetryAck, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	log.Printf(
		"[INGEST] SendTelemetry message_id=%q agent_id=%q probe_id=%q boot_session_id=%q payload_len=%d",
		req.GetMessageId(),
		req.GetAgentId(),
		req.GetProbeId(),
		req.GetBootSessionId(),
		len(req.GetPayload()),
	)

	envelope := TelemetryEnvelope{
		MessageID:          req.GetMessageId(),
		AgentID:            req.GetAgentId(),
		ProbeID:            req.GetProbeId(),
		SigningContext:     req.GetSigningContext(),
		Signature:          req.GetSignature(),
		SystemIdentityHash: req.GetSystemIdentityHash(),
		BootSessionID:      req.GetBootSessionId(),
		Payload:            req.GetPayload(),
	}
	// 1) canonical validation
	canonicalPayload, view, wasJSON, err := ingest.CanonicalizePayloadBytes(envelope.Payload)
	if err != nil {
		return nil, h.RejectBeforeQueue(err.Error())
	}

	// 2) identity validation
	identityKey, _, err := h.ValidateEnvelopeIdentity(envelope.AgentID, envelope.ProbeID)
	if err != nil {
		return nil, h.RejectBeforeQueue(err.Error())
	}
	if strings.TrimSpace(envelope.BootSessionID) == "" {
		return nil, h.RejectBeforeQueue("boot_session_id missing")
	}
	bootSessionUUID, err := uuid.Parse(strings.TrimSpace(envelope.BootSessionID))
	if err != nil || bootSessionUUID.Version() != 4 {
		return nil, h.RejectBeforeQueue("boot_session_id invalid")
	}
	if err := h.VerifyIdentityHash(envelope.SystemIdentityHash); err != nil {
		return nil, h.RejectBeforeQueue(err.Error())
	}
	if strings.TrimSpace(envelope.MessageID) == "" {
		return nil, h.RejectBeforeQueue("message_id missing")
	}
	if _, err := uuid.Parse(strings.TrimSpace(envelope.MessageID)); err != nil {
		return nil, h.RejectBeforeQueue("message_id invalid")
	}
	if !wasJSON {
		if err := h.VerifySession(ctx, envelope.BootSessionID, view, identityKey); err != nil {
			return nil, h.RejectBeforeQueue(err.Error())
		}
	}

	// 3) signing_context validation
	if err := h.VerifySigningContext(envelope.SigningContext); err != nil {
		return nil, h.RejectBeforeQueue(err.Error())
	}

	// 4) signature verification (single Ed25519 path)
	payloadHash := h.ComputePayloadHash(canonicalPayload)
	signingInput := h.ConstructSigningInput(envelope.SigningContext, payloadHash)
	if err := h.VerifyEd25519Signature(ctx, signingInput, envelope.Signature); err != nil {
		return nil, h.RejectBeforeQueue(err.Error())
	}

	// 5) replay pre-check (tenant, identity, boot_session, message_id, content_sha256)
	tenantID := strings.TrimSpace(envelope.SystemIdentityHash)
	identityID := strings.TrimSpace(envelope.AgentID)
	if identityID == "" {
		identityID = strings.TrimSpace(envelope.ProbeID)
	}
	replayAck, err := h.ReplayPrecheck(ctx, tenantID, identityID, envelope.BootSessionID, envelope.MessageID, payloadHash)
	if err != nil {
		return nil, h.Reject(err.Error())
	}
	if replayAck != nil {
		return replayAck, nil
	}

	// 6) queue admission / replay join (only after all checks)
	if wasJSON {
		return nil, h.Reject("unsupported telemetry JSON payload for queue admission")
	}
	replayKey, err := h.replayKey(tenantID, identityID, envelope.BootSessionID, envelope.MessageID)
	if err != nil {
		return nil, h.Reject(err.Error())
	}
	meta := ack.Metadata{
		ReplayKey:     replayKey,
		MessageID:     envelope.MessageID,
		ContentSHA256: payloadHash,
	}
	waitOnly, err := h.beginReplay(meta)
	if err != nil {
		return nil, h.Reject(err.Error())
	}
	if waitOnly {
		if waitErr := h.waitForCommit(meta); waitErr != nil {
			return nil, status.Error(codes.Aborted, "REJECT: "+waitErr.Error())
		}
		return &pb.TelemetryAck{Accepted: true, ServerClock: h.localClock.Load()}, nil
	}
	assessment := h.queueAdmissionAssessment(0)
	if !assessment.AdmissionAllowed() {
		return nil, h.rejectAdmission(meta, assessment.AdmissionError())
	}
	witness := h.bumpLamport(int64(view.LogicalClock))

	dbType, err := ingest.DBEventType(view.EventTypeCode)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "REJECT: "+err.Error())
	}
	ts := float64(view.TimestampUnixNano) / 1e9

	p := h.payloadPool.Get().(*[]byte)
	buf := append((*p)[:0], canonicalPayload...)
	sigCopy := append(make([]byte, 0, len(envelope.Signature)), envelope.Signature...)
	ev := &ingest.VerifiedTelemetry{
		Payload:        buf,
		AgentSignature: sigCopy,
		AgentIDStr:     view.AgentID.String(),
		EventType:      dbType,
		SourceType:     "agent",
		TimestampUnix:  ts,
		LogicalClock:   witness,
	}

	seq, err := h.ForwardToQueue(ev, meta)
	if err != nil {
		b := ev.Payload[:0]
		ev.Payload = nil
		h.payloadPool.Put(&b)
		if status.Code(err) == codes.FailedPrecondition {
			h.ackController.Fail(meta, err)
			return nil, err
		}
		return nil, h.rejectAdmission(meta, err)
	}
	if seq == 0 {
		seq = uint64(witness)
	}
	if waitErr := h.waitForCommit(meta); waitErr != nil {
		return nil, status.Error(codes.Aborted, "REJECT: "+waitErr.Error())
	}

	return &pb.TelemetryAck{Accepted: true, ServerClock: witness}, nil
}

func (h *Handlers) Handshake(ctx context.Context, req *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	if h.sessions == nil {
		return nil, status.Error(codes.FailedPrecondition, "session manager not initialized")
	}

	agentIDStr, err := identity.ExtractAgentID(ctx)
	if err != nil {
		return nil, err
	}
	cert, err := identity.PeerCertFromContext(ctx)
	if err != nil {
		return nil, err
	}
	certFP := identity.ExtractCertFingerprint(cert)

	if strings.TrimSpace(req.AgentUuid) == "" {
		return nil, status.Error(codes.Unauthenticated, "agent_uuid missing")
	}
	claimed, err := uuid.Parse(strings.TrimSpace(req.AgentUuid))
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "agent_uuid invalid")
	}
	if strings.ToLower(claimed.String()) != strings.ToLower(agentIDStr) {
		return nil, status.Error(codes.Unauthenticated, "agent_id mismatch")
	}
	if err := identity.VerifyEnrollment(claimed, certFP); err != nil {
		return nil, status.Error(codes.Unauthenticated, "enrollment: "+err.Error())
	}

	tlsBinding, err := identity.TLSBindingKey(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.BootSessionId) == "" {
		return nil, status.Error(codes.Unauthenticated, "boot_session_id missing")
	}
	_, err = uuid.Parse(req.BootSessionId)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "boot_session_id invalid")
	}
	if h.sessions.HasFixationConflict(agentIDStr, req.BootSessionId, tlsBinding) {
		return nil, status.Error(codes.Unauthenticated, "session fixation detected")
	}
	for _, session := range h.sessions.SnapshotSessions() {
		if session.AgentID == agentIDStr && session.BootSessionID == req.BootSessionId && session.TLSBinding != tlsBinding {
			return nil, status.Error(codes.Unauthenticated, "session fixation detected")
		}
		if session.AgentID == agentIDStr && session.BootSessionID == req.BootSessionId {
			return nil, status.Error(codes.Unauthenticated, "duplicate session binding")
		}
	}

	token := h.sessions.CreateSession(agentIDStr, req.BootSessionId, tlsBinding)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "session token generation failed")
	}

	witness := h.bumpLamport(req.LogicalClock)
	return &pb.HandshakeResponse{
		SessionToken: token,
		ServerClock:  witness,
		Accepted:     true,
	}, nil
}

func (h *Handlers) SendHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatAck, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	if h.sessions == nil {
		return nil, status.Error(codes.FailedPrecondition, "session manager not initialized")
	}
	if req.SessionToken == "" {
		return nil, status.Error(codes.Unauthenticated, "missing session_token")
	}
	agentID, err := h.sessions.ValidateSession(req.SessionToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	if req.AgentId == "" || req.AgentId != agentID {
		return nil, status.Error(codes.Unauthenticated, "agent_id mismatch")
	}
	if err := h.sessions.Touch(req.SessionToken); err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	h.queueAdmissionAssessment(0)

	witness := h.bumpLamport(req.LogicalClock)
	return &pb.HeartbeatAck{
		ServerClock:  witness,
		SessionValid: true,
	}, nil
}

func (h *Handlers) SendDPIEvent(_ context.Context, req *pb.DPIDetectionEvent) (*pb.DPIEventAck, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	return nil, status.Error(codes.Unimplemented, "legacy unsigned DPI gRPC ingress disabled; use signed UNIX socket bridge")
}

func (h *Handlers) ReportActionResult(ctx context.Context, result *pb.ActionResult) (*pb.ActionAck, error) {
	if result == nil {
		return nil, status.Error(codes.InvalidArgument, "nil result")
	}
	agentID, err := identity.ExtractAgentID(ctx)
	if err != nil {
		return nil, err
	}
	if result.AgentId == "" || agentID != result.AgentId {
		return nil, status.Error(codes.PermissionDenied, "agent_id spoofing detected")
	}
	if h.dbPool == nil {
		return nil, status.Error(codes.FailedPrecondition, "db pool not initialized")
	}
	if err := storage.LogActionResultTx(ctx, h.dbPool, result); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.ActionAck{Accepted: true}, nil
}

func (h *Handlers) bumpLamport(remote int64) int64 {
	for {
		local := h.localClock.Load()
		next := local
		if remote > next {
			next = remote
		}
		next++
		if h.localClock.CompareAndSwap(local, next) {
			return next
		}
	}
}
