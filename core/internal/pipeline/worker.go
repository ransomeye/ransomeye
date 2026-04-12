package pipeline

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"ransomeye/core/internal/ack"
	"ransomeye/core/internal/backpressure"
	wormcrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/forensics"
	"ransomeye/core/internal/governance"
	"ransomeye/core/internal/health"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/metrics"
	"ransomeye/core/internal/policy"
	"ransomeye/core/internal/storage"
	"ransomeye/core/internal/storage/authority"
)

var detectionSeq atomic.Uint64

const systemTenantID = "00000000-0000-0000-0000-000000000000"

type PayloadReleaser interface {
	ReleaseTelemetryPayload(ev *ingest.VerifiedTelemetry)
}

type SINEFilter interface {
	Filter(ctx context.Context, payload []byte) (allowed bool, err error)
}

type WorkerPool struct {
	Scheduler *Scheduler
	DB        *storage.DB
	Releaser  PayloadReleaser
	WORM      *wormcrypto.WORM
	PRD13CommitKey      ed25519.PrivateKey
	PRD13CommitKeyID    string
	PRD13CommitKeyEpoch int64
	Detector  Detector
	AIRouter  AIEnqueuer
	Enforcer  EnforcementDispatcher
	// EnforcementPolicy, when non-nil, fail-closes automated enforcement dispatch when
	// EvaluateEnforcementDispatch() != BlockNone (pipeline unhealthy or configured SINE not ready).
	EnforcementPolicy *policy.PolicyEvaluator
	SINE              SINEFilter
	Hub       *Hub
	Acker     *ack.Controller

	// BackpressureEngine, when non-nil, is signalled whenever hub fan-out
	// exhausts MaxBackpressureRetries and cleared on a subsequent successful
	// publish. This allows hub backpressure to propagate upstream to the
	// gateway admission boundary.
	BackpressureEngine *backpressure.Engine

	Workers    int
	Source     string // telemetry_events.source (PRD-03 §3.6)
	SourceType string // telemetry_events.source_type (PHASE 2/3)

	persistAllowedFn   func(context.Context, *ingest.VerifiedTelemetry) (string, error)
	persistDetectionFn func(context.Context, string, *ingest.VerifiedTelemetry, DetectionEvent) error
	sealForensicOnlyFn func(context.Context, *ingest.VerifiedTelemetry) error
	persistenceHooks   PersistenceHooks
}

// PersistenceHooks exists for deterministic failure-injection validation.
// Nil hooks preserve production behavior.
type PersistenceHooks struct {
	AfterTelemetryInsert func(context.Context, pgx.Tx, string) error
	WriteSealedTempFile  func(string, []byte, os.FileMode) error
}

type AIEnqueuer interface {
	TryEnqueue(eventID string, agentID string, payload []byte, logicalClock int64)
}

type EnforcementDispatcher interface {
	Dispatch(enforcement.DispatchRequest) error
}

func (p *WorkerPool) SetPersistAllowedFunc(fn func(context.Context, *ingest.VerifiedTelemetry) (string, error)) {
	if p == nil {
		return
	}
	p.persistAllowedFn = fn
}

func (p *WorkerPool) SetPersistenceHooks(hooks PersistenceHooks) {
	if p == nil {
		return
	}
	p.persistenceHooks = hooks
}

func (p *WorkerPool) SetPersistDetectionFunc(fn func(context.Context, string, *ingest.VerifiedTelemetry, DetectionEvent) error) {
	if p == nil {
		return
	}
	p.persistDetectionFn = fn
}

func (p *WorkerPool) Run(ctx context.Context) error {
	if p.Scheduler == nil {
		return errors.New("nil scheduler")
	}
	if p.DB == nil {
		return errors.New("nil DB")
	}
	if p.Releaser == nil {
		return errors.New("nil payload releaser")
	}
	if p.WORM == nil {
		return errors.New("nil WORM crypto")
	}

	workers := p.Workers
	if workers <= 0 {
		workers = 1
	}

	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for idx := 1; idx <= workers; idx++ {
		workerID := idx
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("[INGEST] worker started source=%s worker=%d", p.Source, workerID)
			if err := p.workerLoop(ctx, workerID); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		wg.Wait()
		return ctx.Err()
	}
}

func (p *WorkerPool) workerLoop(ctx context.Context, workerID int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		ev, err := p.Scheduler.DequeueNext()
		if err != nil {
			health.UpdateSystemState(func(s *health.SystemState) {
				s.PipelineHealthy = false
			})
			continue
		}
		if ev == nil {
			// Scheduler might be empty or paused; tight loop forbidden
			time.Sleep(50 * time.Microsecond)
			continue
		}
		if ev.Sequence == 0 || ev.Payload == nil {
			continue
		}
		
		log.Printf("[WORKER] received event source=%s worker=%d sequence=%d agent_id=%s event_type=%s logical_clock=%d", p.Source, workerID, ev.Sequence, ev.Payload.AgentIDStr, ev.Payload.EventType, ev.Payload.LogicalClock)
		
		// handleOne is responsible for commitAck and resolveQueue on success.
		// If it returns ErrBackpressure, the event is NOT resolved and will be 
		// re-delivered.
		err = p.handleOne(ctx, ev)

		if err == nil {
			health.UpdateSystemState(func(s *health.SystemState) {
				if !s.PipelineHealthy {
					s.PipelineHealthy = true
				}
			})
			continue
		}

		log.Printf("[WORKER] handle event failed source=%s worker=%d sequence=%d err=%v", p.Source, workerID, ev.Sequence, err)
		health.UpdateSystemState(func(s *health.SystemState) {
			s.PipelineHealthy = false
		})
	}
}

func (p *WorkerPool) handleOne(ctx context.Context, event *Event) error {
	if event == nil || event.Payload == nil {
		return nil
	}
	sequence := event.Sequence
	meta := event.Ack
	ev := event.Payload
	view, parseErr := ingest.ParseTelemetryV1(ev.Payload)
	if parseErr != nil {
		p.failAck(meta, parseErr)
		_ = p.resolveQueue(sequence)
		p.Releaser.ReleaseTelemetryPayload(ev)
		return parseErr
	}

	var finding DetectionEvent
	sineEligible := true
	if p.Detector != nil {
		detection, err := p.Detector.Evaluate(ev)
		if err != nil {
			p.failAck(meta, err)
			_ = p.resolveQueue(sequence)
			p.Releaser.ReleaseTelemetryPayload(ev)
			return err
		}
		finding = detection
		sineEligible = detection.SinePass
	}

	allowed := true
	var err error
	if p.SINE != nil && sineEligible {
		allowed, err = p.SINE.Filter(ctx, ev.Payload)
		if err != nil {
			sealErr := p.sealBlockedEvent(ctx, ev)
			health.MarkSystemDegraded("SINE_DOWN")
			p.failAck(meta, err)
			_ = p.resolveQueue(sequence)
			p.Releaser.ReleaseTelemetryPayload(ev)
			if sealErr != nil {
				return sealErr
			}
			return err
		}
	}
	if !allowed {
		err := p.sealBlockedEvent(ctx, ev)
		p.failAck(meta, err)
		_ = p.resolveQueue(sequence)
		p.Releaser.ReleaseTelemetryPayload(ev)
		return err
	}

	// 1) Persistence: Mandatory and idempotent.
	eventID, err := p.persistAllowedEvent(ctx, sequence, meta, ev)
	if err != nil {
		p.failAck(meta, err)
		// DO NOT resolveQueue for transient DB errors; allow re-delivery.
		// However, for permanent constraints (e.g. content_sha mismatch), 
		// persistAllowedEvent returns error which should probably resolve if unrecoverable.
		// For now, assume retry is safer unless explicit permanent failure.
		p.Releaser.ReleaseTelemetryPayload(ev)
		return err
	}

	// Deterministic detector + policy live in-process; do not gate persistence on optional AI sidecar health.
	if p.Detector != nil && finding.Decision == "malicious" {
		if detectErr := p.persistDetection(ctx, eventID, ev, finding); detectErr != nil {
			p.failAck(meta, detectErr)
			p.Releaser.ReleaseTelemetryPayload(ev)
			return detectErr
		}
	}

	// Successful persistence for this event means the hot path is healthy for this decision; do not let
	// stale PipelineHealthy=false from unrelated duplicate-replay races block enforcement dispatch here.
	health.UpdateSystemState(func(s *health.SystemState) {
		s.PipelineHealthy = true
	})

	// 2) Enqueue Side-Effects: Best-effort or bounded backpressure.
	if p.AIRouter != nil && sineEligible {
		aiPayload, payloadErr := buildAIEvaluationPayload(ev, finding)
		if payloadErr == nil {
			p.AIRouter.TryEnqueue(eventID, ev.AgentIDStr, aiPayload, ev.LogicalClock)
		}
	}
	if p.Enforcer != nil {
		dispatchReq, dispatchErr := enforcement.BuildDispatchRequest(
			ev.AgentIDStr,
			view.EventID.String(),
			int64(view.LogicalClock),
			ingest.TimestampUTC(view.TimestampUnixNano).Unix(),
			ev.Payload,
			finding.Confidence,
			finding.PolicyDecision,
		)
		if dispatchErr == nil {
			skipDispatch := false
			if p.EnforcementPolicy != nil && finding.PolicyDecision.Allowed {
				if br := p.EnforcementPolicy.EvaluateEnforcementDispatch(); br != policy.BlockNone {
					skipDispatch = true
					metrics.IncEnforcementBlocked(1)
					log.Printf("[ENFORCEMENT] dispatch blocked by runtime gate reason=%s agent_id=%s source=%s",
						policy.FormatEnforcementDispatchBlock(br), ev.AgentIDStr, p.Source)
				}
			}
			if !skipDispatch {
				_ = p.Enforcer.Dispatch(dispatchReq)
			}
		}
	}

	// 3) Hub Publication (MANDATORY before Commit):
	// Hub pressure MUST propagate back to the gateway.
	if p.Hub != nil {
		if p.Detector != nil {
			if finding.Decision == "malicious" {
				if hubErr := p.emitDetectionFinding(eventID, ev, finding); hubErr != nil {
					p.failAck(meta, hubErr)
					p.Releaser.ReleaseTelemetryPayload(ev)
					// If ErrBackpressure, workerLoop will NOT resolve and we will retry.
					return hubErr
				}
			}
		} else {
			if hubErr := p.emitLegacyDetectionEvent(eventID, ev); hubErr != nil {
				p.failAck(meta, hubErr)
				p.Releaser.ReleaseTelemetryPayload(ev)
				return hubErr
			}
		}
	}

	// 4) Success Path: ONLY resolve and commit after ALL steps succeed.
	p.commitAck(meta)
	_ = p.resolveQueue(sequence)
	p.Releaser.ReleaseTelemetryPayload(ev)
	return nil
}

func (p *WorkerPool) ProcessOne(ctx context.Context, ev *ingest.VerifiedTelemetry) error {
	return p.handleOne(ctx, &Event{Payload: ev})
}

func (p *WorkerPool) emitLegacyDetectionEvent(eventID string, ev *ingest.VerifiedTelemetry) error {
	if p == nil || p.Hub == nil || ev == nil {
		return nil
	}
	view, err := ingest.ParseTelemetryV1(ev.Payload)
	if err != nil {
		return nil
	}
	t := ingest.TimestampUTC(view.TimestampUnixNano)
	seq := int64(detectionSeq.Add(1))
	
	st := ev.SourceType
	if st == "" {
		st = p.SourceType
	}

	env := GetEventEnvelope(seq, "detection", eventID, ev.AgentIDStr, "detection", st, eventID, "detected", t, int64(view.LogicalClock), PriorityCritical)
	defer env.Release()
	// incremented tracks whether this particular call has incremented the
	// pressure counter. Decrement is only valid when we previously incremented;
	// an unrelated success must never decrement pressure from a different source.
	incremented := false
	var publishErr error
	for i := 0; i < MaxBackpressureRetries; i++ {
		publishErr = p.Hub.TryPublish(env)
		if publishErr == nil {
			if incremented && p.BackpressureEngine != nil {
				p.BackpressureEngine.DecrementPressure()
			}
			return nil
		}
		if !incremented && p.BackpressureEngine != nil {
			p.BackpressureEngine.IncrementPressure("hub subscriber backpressure")
			incremented = true
		}
	}
	// Retries exhausted: pressureCounter was already incremented on the first
	// failure; it stays elevated until a future call from this source succeeds.
	return publishErr
}

func (p *WorkerPool) emitDetectionFinding(eventID string, ev *ingest.VerifiedTelemetry, finding DetectionEvent) error {
	if p == nil || p.Hub == nil || ev == nil {
		return nil
	}
	view, err := ingest.ParseTelemetryV1(ev.Payload)
	if err != nil {
		return nil
	}
	finding.ID = eventID
	finding.Timestamp = ingest.TimestampUTC(view.TimestampUnixNano)
	seq := int64(detectionSeq.Add(1))
	env := GetDetectionEventEnvelope(seq, eventID, ev.AgentIDStr, finding.Timestamp, finding, ev.LogicalClock)
	defer env.Release()
	incremented := false
	var publishErr error
	for i := 0; i < MaxBackpressureRetries; i++ {
		publishErr = p.Hub.TryPublish(env)
		if publishErr == nil {
			if incremented && p.BackpressureEngine != nil {
				p.BackpressureEngine.DecrementPressure()
			}
			return nil
		}
		if !incremented && p.BackpressureEngine != nil {
			p.BackpressureEngine.IncrementPressure("hub subscriber backpressure")
			incremented = true
		}
	}
	return publishErr
}

type sealedEvidence struct {
	evidenceID    string
	filePath      string
	retentionTier string
	canonicalHex  string
	wormHex       string
	sigB64        string
	blobSize      int64
}

func (p *WorkerPool) persistAllowedEvent(ctx context.Context, sequence uint64, meta ack.Metadata, ev *ingest.VerifiedTelemetry) (string, error) {
	if p.persistAllowedFn != nil {
		return p.persistAllowedFn(ctx, ev)
	}
	return p.insertTelemetryAndWORM(ctx, sequence, meta, ev)
}

func (p *WorkerPool) persistDetection(ctx context.Context, eventID string, ev *ingest.VerifiedTelemetry, finding DetectionEvent) error {
	if p.persistDetectionFn != nil {
		return p.persistDetectionFn(ctx, eventID, ev, finding)
	}
	if p.DB == nil || p.DB.Pool == nil {
		return errors.New("db not initialized")
	}
	if ev == nil {
		return errors.New("nil event")
	}

	tenantID, err := p.lookupTenantID(ctx, ev.AgentIDStr)
	if err != nil {
		return err
	}

	signalsRaw, err := json.Marshal(map[string]any{
		"decision":         finding.Decision,
		"sine_pass":        finding.SinePass,
		"score":            clampOpenUnitInterval(finding.Confidence),
		"model_prediction": clampUnitInterval(finding.ModelPrediction),
		"entropy_score":    clampUnitInterval(finding.EntropyScore),
		"burst_score":      clampUnitInterval(finding.BurstScore),
		"process_anomaly":  clampUnitInterval(finding.ProcessAnomaly),
	})
	if err != nil {
		return err
	}

	loo := make(map[string]float64, len(finding.Explanation))
	for _, item := range finding.Explanation {
		loo[item.Feature] = item.Impact
	}
	looRaw, err := json.Marshal(loo)
	if err != nil {
		return err
	}

	bayesianRaw, err := json.Marshal(map[string]any{
		"policy_action":     finding.PolicyDecision.Action,
		"policy_allowed":    finding.PolicyDecision.Allowed,
		"sequence_decision": finding.Decision,
	})
	if err != nil {
		return err
	}

	detectedAt := finding.Timestamp.UTC()
	if detectedAt.IsZero() {
		detectedAt = time.Now().UTC()
	}

	const qIns = `
INSERT INTO detections (
    detection_id, tenant_id, agent_id, event_id, detected_at, timestamp,
    posterior_prob, aec_class, threat_type, signals, loo_importance,
    bayesian_intermediate, prior_used, lambda_used, model_hash, logical_clock
)
VALUES (
    gen_random_uuid(),
    $1::uuid,
    $2::uuid,
    $3::uuid,
    $4::timestamptz,
    $5::timestamptz,
    $6::numeric,
    $7::smallint,
    $8::text,
    $9::jsonb,
    $10::jsonb,
    $11::jsonb,
    $12::numeric,
    $13::numeric,
    $14::text,
    $15::bigint
)
`
	tx, err := p.DB.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := setTenantContext(ctx, tx, tenantID); err != nil {
		return err
	}

	if _, err := tx.Exec(
		ctx,
		qIns,
		tenantID,
		ev.AgentIDStr,
		eventID,
		detectedAt,
		detectedAt,
		clampOpenUnitInterval(finding.Confidence),
		aecClassFromFinding(finding),
		"malicious",
		signalsRaw,
		looRaw,
		bayesianRaw,
		0.1000000000,
		0.850,
		currentModelHash(),
		ev.LogicalClock,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *WorkerPool) sealBlockedEvent(ctx context.Context, ev *ingest.VerifiedTelemetry) error {
	if p.sealForensicOnlyFn != nil {
		return p.sealForensicOnlyFn(ctx, ev)
	}
	return p.sealForensicOnly(ctx, ev)
}

// insertTelemetryAndWORM commits the Mishka-authoritative SIGNAL batch first (partition_records +
// batch_commit_records + replay_guard), then applies legacy SOC/WORM/governance projections in a separate
// transaction. Legacy failures are logged only — they MUST NOT roll back or gate authoritative SIGNAL success.
// Mishka replay/dedup correctness is only the PRD-13 commit boundary, not telemetry_events rows.
func (p *WorkerPool) insertTelemetryAndWORM(ctx context.Context, sequence uint64, meta ack.Metadata, ev *ingest.VerifiedTelemetry) (eventID string, err error) {
	if p.DB == nil || p.DB.Pool == nil {
		return "", errors.New("db not initialized")
	}
	if err := p.validateTelemetryForSealing(ev); err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			log.Printf("[DB] insert failed source=%s agent_id=%s logical_clock=%d err=%v", p.Source, ev.AgentIDStr, ev.LogicalClock, err)
		}
	}()

	src := p.Source
	switch src {
	case "linux_agent", "windows_agent", "dpi_probe", "offline_sync":
	default:
		return "", fmt.Errorf("invalid source %q", src)
	}

	st := ev.SourceType
	if st == "" {
		st = p.SourceType
	}

	tenantID, err := p.lookupTenantID(ctx, ev.AgentIDStr)
	if err != nil {
		return "", err
	}
	if meta.MessageID != "" {
		existingEventID, existing, err := p.lookupExistingEvent(ctx, tenantID, ev.AgentIDStr, meta)
		if err != nil {
			return "", err
		}
		if existing {
			return existingEventID, nil
		}
	}

	eventID = uuid.NewString()
	retentionTier := "hot"
	root, err := wormStorageRoot()
	if err != nil {
		return "", err
	}
	evidenceID := uuid.NewString()
	filePath := filepath.Join(root, tenantID, retentionTier, evidenceID+".sealed")
	sealed, err := p.sealEvidence(ev, eventID, evidenceID, retentionTier, filePath)
	if err != nil {
		return "", err
	}

	txAuth, err := p.DB.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		_ = removeSealedEvidenceFile(sealed.filePath)
		return "", err
	}
	authCommitted := false
	defer func() {
		if authCommitted {
			return
		}
		_ = txAuth.Rollback(ctx)
		_ = removeSealedEvidenceFile(sealed.filePath)
	}()

	if err := setTenantContext(ctx, txAuth, tenantID); err != nil {
		return "", err
	}
	if err := p.appendPRD13CommittedSignal(ctx, txAuth, meta, ev); err != nil {
		return "", err
	}
	if err := txAuth.Commit(ctx); err != nil {
		return "", err
	}
	authCommitted = true

	if err := p.insertLegacyTelemetryProjection(ctx, sequence, tenantID, eventID, ev, meta, sealed, src, st); err != nil {
		log.Printf("[LEGACY] projection after authoritative SIGNAL failed event_id=%s err=%v", eventID, err)
	}
	log.Printf("[DB] insert success source=%s event_id=%s tenant_id=%s agent_id=%s logical_clock=%d", src, eventID, tenantID, ev.AgentIDStr, ev.LogicalClock)
	return eventID, nil
}

// insertLegacyTelemetryProjection writes telemetry_events, worm_evidence, and governance_audit_log.
// It is not part of Mishka authority; callers must already have committed the SIGNAL batch.
func (p *WorkerPool) insertLegacyTelemetryProjection(ctx context.Context, sequence uint64, tenantID, eventID string, ev *ingest.VerifiedTelemetry, meta ack.Metadata, sealed *sealedEvidence, src, st string) error {
	tx, err := p.DB.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := setTenantContext(ctx, tx, tenantID); err != nil {
		return err
	}

	const qIns = `
INSERT INTO telemetry_events (
    event_id, tenant_id, agent_id, event_type, timestamp, logical_clock,
    payload_bytes, agent_ed25519_sig, source, dropped_packets_before
)
VALUES (
    $1::uuid,
    $2::uuid,
    $3::uuid,
    $4::text,
    to_timestamp($5::double precision),
    $6::bigint,
    $7::bytea,
    $8::bytea,
    $9::text,
    $10::bigint
)
`
	if _, err := tx.Exec(ctx, qIns, eventID, tenantID, ev.AgentIDStr, ev.EventType, ev.TimestampUnix, ev.LogicalClock, ev.Payload, ev.AgentSignature, src, ev.DroppedCount); err != nil {
		return err
	}
	if hook := p.persistenceHooks.AfterTelemetryInsert; hook != nil {
		if err := hook(ctx, tx, eventID); err != nil {
			return err
		}
	}

	const qWorm = `
INSERT INTO worm_evidence (
    evidence_id, tenant_id, detection_id, event_id, evidence_type, file_path,
    canonical_json_hash, worm_file_hash, ed25519_sig, retention_tier, file_size_bytes, dropped_packets_before
) VALUES (
    $1::uuid, $2::uuid, NULL, $3::uuid, $4::text, $5::text,
    $6::text, $7::text, $8::text, $9::text, $10::bigint, $11::bigint
)
`
	if _, err := tx.Exec(ctx, qWorm,
		sealed.evidenceID,
		tenantID,
		eventID,
		"CUSTOM",
		sealed.filePath,
		sealed.canonicalHex,
		sealed.wormHex,
		sealed.sigB64,
		sealed.retentionTier,
		sealed.blobSize,
		ev.DroppedCount,
	); err != nil {
		return err
	}

	auditTime := time.Now().UTC()
	auditDetails := map[string]any{
		"agent_id":            ev.AgentIDStr,
		"canonical_json_hash": sealed.canonicalHex,
		"evidence_id":         sealed.evidenceID,
		"event_id":            eventID,
		"event_type":          ev.EventType,
		"logical_clock":       ev.LogicalClock,
		"retention_tier":      sealed.retentionTier,
		"source":              src,
		"worm_file_hash":      sealed.wormHex,
	}
	if err := governance.LogEventTx(ctx, tx, governance.Event{
		EventType: governance.EventTypeTelemetryIngest,
		Actor:     ev.AgentIDStr,
		TenantID:  tenantID,
		CreatedAt: auditTime,
		Details:   auditDetails,
	}); err != nil {
		log.Printf("[AUDIT] governance log failed event_id=%s err=%v", eventID, err)
	} else {
		log.Printf("[AUDIT] governance log success event_id=%s", eventID)
	}

	return tx.Commit(ctx)
}

const prd13ExecutionContextHashEnv = "RANSOMEYE_EXECUTION_CONTEXT_HASH"
const prd13AuthorityBindingsEnv = "RANSOMEYE_PRD13_AUTHORITY_BINDINGS_JSON"
const prd13AuthoritySnapshotsEnv = "RANSOMEYE_PRD13_AUTHORITY_SNAPSHOTS_JSON"

func (p *WorkerPool) appendPRD13CommittedSignal(ctx context.Context, tx pgx.Tx, meta ack.Metadata, ev *ingest.VerifiedTelemetry) error {
	if meta.MessageID == "" || meta.ReplayKey == "" {
		return nil
	}
	if p == nil {
		return errors.New("nil worker")
	}
	if len(p.PRD13CommitKey) != ed25519.PrivateKeySize || p.PRD13CommitKeyID == "" {
		return errors.New("prd13 commit signing key missing")
	}

	_, identityPart, bootPart, messagePart, err := parseReplayKey(meta.ReplayKey)
	if err != nil {
		return err
	}
	if messagePart != meta.MessageID {
		return errors.New("replay_key message_id mismatch")
	}

	agentUUID, err := uuid.Parse(identityPart)
	if err != nil {
		return fmt.Errorf("replay_key identity uuid: %w", err)
	}
	bootUUID, err := uuid.Parse(bootPart)
	if err != nil {
		return fmt.Errorf("replay_key boot_session uuid: %w", err)
	}
	msgUUID, err := uuid.Parse(messagePart)
	if err != nil {
		return fmt.Errorf("replay_key message uuid: %w", err)
	}

	computed := sha256.Sum256(ev.Payload)
	if computed != meta.ContentSHA256 {
		return errors.New("content sha mismatch between computed payload and ack metadata")
	}
	canonicalPayloadHash := computed
	payloadHash := computed
	partitionID := prd13PartitionID()
	if partitionID <= 0 {
		return errors.New("prd13 partition_id must be > 0 for authoritative pipeline commit")
	}

	authorityRefs, authoritySnapshots, execHash, err := resolvePRD13AuthorityAndContext(ctx, tx)
	if err != nil {
		return err
	}
	logicalShardID, err := parsePRD13LogicalShardID()
	if err != nil {
		return err
	}

	schemaVersion := "telemetry_v1"
	schemaTransformHash := authority.SchemaTransformHash(schemaVersion, execHash)
	logicalClock := uint64(ev.LogicalClock)

	// partition_context for edge telemetry batch: 16-byte binding (align with gateway SIGNAL shape; not a second authority root).
	partitionContext := make([]byte, 16)

	opts := authority.CommitOptions{
		PartitionID:           partitionID,
		PartitionEpoch:        0,
		ExecutionContextHash:  execHash,
		PrivateKey:            p.PRD13CommitKey,
		KeyID:                 p.PRD13CommitKeyID,
		KeyEpoch:              p.PRD13CommitKeyEpoch,
		AuthorityRefs:         authorityRefs,
		AuthoritySnapshots:    authoritySnapshots,
		Records: []authority.RecordDraft{{
			RecordType:            "SIGNAL",
			RecordVersion:         "v1",
			StageOrder:            1,
			RecordID:              msgUUID[:],
			MessageID:             msgUUID[:],
			AgentID:               agentUUID[:],
			BootSessionID:         bootUUID[:],
			LogicalClock:          &logicalClock,
			LogicalShardID:        logicalShardID,
			CausalParentRefsText:  "{}",
			CanonicalPayloadText:  nil,
			CanonicalPayloadBytes: ev.Payload,
			CanonicalPayloadHash:  canonicalPayloadHash,
			PayloadHash:           &payloadHash,
			Signature:             ev.AgentSignature,
			PartitionContext:      partitionContext,
			SchemaVersion:         &schemaVersion,
			SchemaTransformHash:   &schemaTransformHash,
		}},
		ReplayGuard: []authority.ReplayGuardAdmittedRow{{
			LogicalShardID: logicalShardID,
			EmitterID:      agentUUID[:],
			BootSessionID:  bootUUID[:],
			LogicalClock:   logicalClock,
			MessageID:      msgUUID[:],
		}},
	}

	return authority.CommitPartitionBatchTx(ctx, tx, opts)
}

func parseExecutionContextHash() ([32]byte, bool, error) {
	raw := strings.TrimSpace(os.Getenv(prd13ExecutionContextHashEnv))
	if raw == "" {
		return authority.ZeroHash32, false, nil
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 32 {
		return [32]byte{}, false, fmt.Errorf("%s must be 64 hex chars (32 bytes)", prd13ExecutionContextHashEnv)
	}
	var out [32]byte
	copy(out[:], b)
	return out, true, nil
}

func prd13PartitionID() int64 {
	s := strings.TrimSpace(os.Getenv("RANSOMEYE_PRD13_PARTITION_ID"))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
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

func parseReplayKey(k string) (tenant, identity, bootSession, messageID string, err error) {
	parts := strings.Split(k, "|")
	if len(parts) != 4 {
		return "", "", "", "", errors.New("replay key invalid")
	}
	return parts[0], parts[1], parts[2], parts[3], nil
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

func resolvePRD13AuthorityAndContext(ctx context.Context, tx pgx.Tx) ([]authority.AuthorityRef, []authority.SnapshotUpsert, [32]byte, error) {
	refs, err := parseAuthorityBindingsEnv()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	if err := authority.RequireSingleTrustSnapshotBindingForSignal(refs); err != nil {
		return nil, nil, [32]byte{}, err
	}
	snaps, snapHashMap, err := parseAuthoritySnapshotsEnv()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

	// Ensure every requested binding has a payload_hash available, either from env snapshots
	// or from existing authority_snapshots rows (explicit, deterministic, no inference).
	type key struct{ t, id, v string }
	keys := make([]key, 0, len(refs))
	for _, r := range refs {
		keys = append(keys, key{t: r.Type, id: r.ID, v: r.Version})
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].t != keys[j].t {
			return keys[i].t < keys[j].t
		}
		if keys[i].id != keys[j].id {
			return keys[i].id < keys[j].id
		}
		return keys[i].v < keys[j].v
	})

	hashes := make([][32]byte, 0, len(keys))
	for _, k := range keys {
		if h, ok := snapHashMap[k.t+"\x00"+k.id+"\x00"+k.v]; ok {
			hashes = append(hashes, h)
			continue
		}
		var payloadHash []byte
		if err := tx.QueryRow(ctx, `
SELECT payload_hash
FROM authority_snapshots
WHERE authority_type = $1 AND authority_id = $2 AND authority_version = $3`, k.t, k.id, k.v).Scan(&payloadHash); err != nil {
			return nil, nil, [32]byte{}, fmt.Errorf("authority_snapshots missing for execution context input %s/%s/%s: %w", k.t, k.id, k.v, err)
		}
		if len(payloadHash) != 32 {
			return nil, nil, [32]byte{}, fmt.Errorf("authority_snapshots payload_hash length %d", len(payloadHash))
		}
		var h [32]byte
		copy(h[:], payloadHash)
		hashes = append(hashes, h)
	}

	computed := sha256.New()
	for _, h := range hashes {
		_, _ = computed.Write(h[:])
	}
	var execComputed [32]byte
	copy(execComputed[:], computed.Sum(nil))

	envExec, provided, err := parseExecutionContextHash()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	if provided && envExec != execComputed {
		return nil, nil, [32]byte{}, errors.New("execution_context_hash mismatch with bound authority snapshot payload_hash inputs")
	}
	if provided {
		return refs, snaps, envExec, nil
	}
	return refs, snaps, execComputed, nil
}

func parseAuthorityBindingsEnv() ([]authority.AuthorityRef, error) {
	raw := strings.TrimSpace(os.Getenv(prd13AuthorityBindingsEnv))
	if raw == "" {
		return nil, nil
	}
	var in []authorityRefJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("%s invalid json: %w", prd13AuthorityBindingsEnv, err)
	}
	out := make([]authority.AuthorityRef, 0, len(in))
	for _, r := range in {
		if strings.TrimSpace(r.Type) == "" || strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Version) == "" {
			return nil, fmt.Errorf("%s: missing type/id/version", prd13AuthorityBindingsEnv)
		}
		out = append(out, authority.AuthorityRef{Type: r.Type, ID: r.ID, Version: r.Version})
	}
	return out, nil
}

func parseAuthoritySnapshotsEnv() ([]authority.SnapshotUpsert, map[string][32]byte, error) {
	raw := strings.TrimSpace(os.Getenv(prd13AuthoritySnapshotsEnv))
	if raw == "" {
		return nil, map[string][32]byte{}, nil
	}
	var in []authoritySnapshotJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, nil, fmt.Errorf("%s invalid json: %w", prd13AuthoritySnapshotsEnv, err)
	}
	out := make([]authority.SnapshotUpsert, 0, len(in))
	hashes := make(map[string][32]byte, len(in))
	for _, s := range in {
		if strings.TrimSpace(s.Type) == "" || strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.Version) == "" {
			return nil, nil, fmt.Errorf("%s: missing type/id/version", prd13AuthoritySnapshotsEnv)
		}
		ph, err := hex.DecodeString(strings.TrimSpace(s.PayloadHashHex))
		if err != nil || len(ph) != 32 {
			return nil, nil, fmt.Errorf("%s: payload_hash_hex must be 64 hex chars", prd13AuthoritySnapshotsEnv)
		}
		sig, err := hex.DecodeString(strings.TrimSpace(s.SignatureHex))
		if err != nil || len(sig) == 0 {
			return nil, nil, fmt.Errorf("%s: signature_hex required (non-empty hex)", prd13AuthoritySnapshotsEnv)
		}
		// Deterministic integrity check: payload_hash must equal SHA256(UTF8(canonical_payload_text)).
		sum := sha256.Sum256([]byte(s.CanonicalPayloadText))
		if !bytes.Equal(ph, sum[:]) {
			return nil, nil, fmt.Errorf("%s: payload_hash_hex mismatch for %s/%s/%s", prd13AuthoritySnapshotsEnv, s.Type, s.ID, s.Version)
		}
		var ph32 [32]byte
		copy(ph32[:], ph)
		k := s.Type + "\x00" + s.ID + "\x00" + s.Version
		hashes[k] = ph32
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

func (p *WorkerPool) lookupExistingEvent(ctx context.Context, tenantID, agentID string, meta ack.Metadata) (string, bool, error) {
	if meta.MessageID == "" {
		return "", false, nil
	}
	// Authoritative duplicate detection: committed SIGNAL in partition_records + batch_commit (not telemetry_events).
	partitionID := prd13PartitionID()
	if partitionID > 0 {
		msgBytes, err := authority.DecodeMessageIDHexStrict(meta.MessageID)
		if err == nil {
			committed, err := authority.SignalMessageIDCommitted(ctx, p.DB.Pool, partitionID, msgBytes)
			if err != nil {
				return "", false, err
			}
			if committed {
				var eventID string
				if err := p.DB.Pool.QueryRow(ctx, `
SELECT event_id::text FROM telemetry_events
WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND message_id = $3::text LIMIT 1`,
					tenantID, agentID, meta.MessageID).Scan(&eventID); err == nil && strings.TrimSpace(eventID) != "" {
					return eventID, true, nil
				}
				// Committed Mishka batch without legacy telemetry row: stable synthetic id for idempotent ack path.
				synth := uuid.NewSHA1(uuid.NameSpaceOID, append([]byte("mishka:signal:committed-only:"), msgBytes...)).String()
				return synth, true, nil
			}
		}
	}
	// Legacy telemetry_events schema does not carry message_id, so authoritative
	// replay must rely on committed SIGNAL tables only.
	return "", false, nil
}

func (p *WorkerPool) acker() *ack.Controller {
	if p == nil {
		return nil
	}
	if p.Acker != nil {
		return p.Acker
	}
	if p.Scheduler != nil {
		return p.Scheduler.Acker()
	}
	return nil
}

func (p *WorkerPool) commitAck(meta ack.Metadata) {
	if meta.ReplayKey == "" {
		return
	}
	if acker := p.acker(); acker != nil {
		acker.Commit(meta)
	}
}

func (p *WorkerPool) failAck(meta ack.Metadata, err error) {
	if meta.ReplayKey == "" {
		return
	}
	if acker := p.acker(); acker != nil {
		acker.Fail(meta, err)
	}
}

func (p *WorkerPool) resolveQueue(sequence uint64) error {
	if p == nil || p.Scheduler == nil || sequence == 0 {
		return nil
	}
	return p.Scheduler.Resolve(sequence)
}

func (p *WorkerPool) sealForensicOnly(_ context.Context, ev *ingest.VerifiedTelemetry) error {
	if err := p.validateTelemetryForSealing(ev); err != nil {
		return err
	}
	agentID, err := uuid.Parse(ev.AgentIDStr)
	if err != nil {
		return err
	}

	root, err := wormStorageRoot()
	if err != nil {
		return err
	}

	eventID := uuid.NewString()
	evidenceID := uuid.NewString()
	filePath := filepath.Join(root, "blocked", agentID.String(), "forensic-only", evidenceID+".sealed")
	_, err = p.sealEvidence(ev, eventID, evidenceID, "forensic-only", filePath)
	return err
}

func (p *WorkerPool) validateTelemetryForSealing(ev *ingest.VerifiedTelemetry) error {
	if p.WORM == nil {
		return errors.New("nil WORM crypto")
	}
	if ev == nil {
		return errors.New("nil event")
	}
	if len(ev.Payload) != ingest.CanonicalTelemetryV1Size {
		return errors.New("telemetry payload length")
	}
	if len(ev.AgentSignature) != 64 {
		return errors.New("telemetry agent signature length")
	}
	return nil
}

func (p *WorkerPool) lookupTenantID(ctx context.Context, agentID string) (string, error) {
	var tenantID string
	const qTenant = `
SELECT tenant_id::text
FROM agent_sessions
WHERE agent_id = $1::uuid
LIMIT 1
`
	if err := p.DB.Pool.QueryRow(ctx, qTenant, agentID).Scan(&tenantID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
		return p.lookupSystemTenantID(ctx)
	}
	return tenantID, nil
}

func (p *WorkerPool) lookupSystemTenantID(ctx context.Context) (string, error) {
	if p.DB == nil || p.DB.Pool == nil {
		return "", errors.New("db not initialized")
	}

	var tenantCount int
	if err := p.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&tenantCount); err != nil {
		return "", err
	}
	if tenantCount != 1 {
		return "", pgx.ErrNoRows
	}

	var tenantID string
	if err := p.DB.Pool.QueryRow(ctx, `SELECT tenant_id::text FROM tenants WHERE tenant_id = $1::uuid`, systemTenantID).Scan(&tenantID); err != nil {
		return "", err
	}
	return tenantID, nil
}

type tenantContextSetter interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func setTenantContext(ctx context.Context, execer tenantContextSetter, tenantID string) error {
	if execer == nil {
		return errors.New("nil tenant context setter")
	}
	if tenantID == "" {
		return errors.New("tenant_id is empty")
	}
	_, err := execer.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID)
	return err
}

func wormStorageRoot() (string, error) {
	root := os.Getenv("WORM_STORAGE_PATH")
	if root == "" {
		return "", errors.New("WORM_STORAGE_PATH not set")
	}
	return root, nil
}

func (p *WorkerPool) sealEvidence(ev *ingest.VerifiedTelemetry, eventID, evidenceID, retentionTier, filePath string) (*sealedEvidence, error) {
	recordPayload, err := buildWORMRecordPayload(ev)
	if err != nil {
		return nil, err
	}

	ciphertext, nonce, err := p.WORM.EncryptEvidence(recordPayload)
	if err != nil {
		return nil, err
	}

	sig, err := p.WORM.SignEvidence(ciphertext, ev.LogicalClock, ev.AgentIDStr, eventID, ev.EventType)
	if err != nil {
		return nil, err
	}
	if !p.WORM.VerifyEvidence(ciphertext, ev.LogicalClock, ev.AgentIDStr, eventID, ev.EventType, sig) {
		return nil, errors.New("WORM signature verification failed before persist (fail closed)")
	}

	// Write sealed blob (ciphertext only for now; nonce is required to decrypt, so we prefix it).
	// Format: [12-byte nonce][ciphertext]
	blob := make([]byte, 0, 12+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	canonicalHash := sha256.Sum256(recordPayload)
	canonicalHex := hex.EncodeToString(canonicalHash[:])
	wormHash := sha256.Sum256(blob)
	wormHex := hex.EncodeToString(wormHash[:])
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return nil, err
	}
	if err := writeSealedBlobAtomically(filePath, blob, p.persistenceHooks.WriteSealedTempFile); err != nil {
		return nil, err
	}
	if st, err := os.Stat(filePath); err != nil {
		return nil, err
	} else if st.Mode().Perm() != 0o444 {
		return nil, fmt.Errorf("worm file permissions not 0444: %s (%#o)", filePath, st.Mode().Perm())
	}

	if err := forensics.MustBeSealed(&forensics.Event{
		WormSignature: sig,
		Hash:          wormHex,
	}); err != nil {
		return nil, err
	}
	return &sealedEvidence{
		evidenceID:    evidenceID,
		filePath:      filePath,
		retentionTier: retentionTier,
		canonicalHex:  canonicalHex,
		wormHex:       wormHex,
		sigB64:        sigB64,
		blobSize:      int64(len(blob)),
	}, nil
}

func buildWORMRecordPayload(ev *ingest.VerifiedTelemetry) ([]byte, error) {
	if ev == nil {
		return nil, errors.New("nil event")
	}

	payloadHash := sha256.Sum256(ev.Payload)
	record := struct {
		DroppedPacketsBefore uint64 `json:"dropped_packets_before"`
		PayloadBytesBase64   string `json:"payload_bytes_base64"`
		PayloadSHA256        string `json:"payload_sha256"`
	}{
		DroppedPacketsBefore: ev.DroppedCount,
		PayloadBytesBase64:   base64.StdEncoding.EncodeToString(ev.Payload),
		PayloadSHA256:        hex.EncodeToString(payloadHash[:]),
	}
	return json.Marshal(record)
}

func buildAIEvaluationPayload(ev *ingest.VerifiedTelemetry, finding DetectionEvent) ([]byte, error) {
	if ev == nil {
		return nil, errors.New("nil event")
	}
	view, err := ingest.ParseTelemetryV1(ev.Payload)
	if err != nil {
		return nil, err
	}

	processSignal := clampUnitInterval(finding.ProcessAnomaly)
	fileSignal := clampUnitInterval(finding.EntropyScore)
	networkSignal := clampUnitInterval(finding.BurstScore)
	userSignal := clampUnitInterval(finding.ProcessAnomaly)
	deceptionSignal := 0.0

	switch ev.EventType {
	case "PROCESS_EVENT":
		processSignal = clampUnitInterval(maxFloat(finding.ModelPrediction, finding.Confidence))
	case "FILE_EVENT":
		fileSignal = clampUnitInterval(maxFloat(finding.EntropyScore, finding.Confidence))
	case "NETWORK_EVENT":
		networkSignal = clampUnitInterval(maxFloat(finding.BurstScore, finding.Confidence))
	case "USER_EVENT":
		userSignal = clampUnitInterval(maxFloat(finding.ProcessAnomaly, finding.Confidence))
	case "DECEPTION_EVENT":
		deceptionSignal = 1.0
	}

	payload := map[string]any{
		"agent_id":             ev.AgentIDStr,
		"event_id":             view.EventID.String(),
		"event_type":           ev.EventType,
		"logical_clock":        ev.LogicalClock,
		"signal_process":       processSignal,
		"signal_file":          fileSignal,
		"signal_network":       networkSignal,
		"signal_user":          userSignal,
		"signal_deception":     deceptionSignal,
		"process":              processSignal,
		"file":                 fileSignal,
		"network":              networkSignal,
		"user":                 userSignal,
		"deception":            deceptionSignal,
		"autoencoder":          clampUnitInterval(finding.ModelPrediction),
		"beacon_confidence":    networkSignal,
		"exfil_confidence":     networkSignal,
		"high_entropy_ratio":   fileSignal,
		"volume_spike":         fileSignal,
		"privilege_escalation": userSignal >= 0.8,
		"uid":                  0,
	}
	return json.Marshal(payload)
}

var hex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func currentModelHash() string {
	value := strings.TrimSpace(os.Getenv("RANSOMEYE_MODEL_HASH"))
	if hex64Pattern.MatchString(value) {
		return value
	}
	return strings.Repeat("0", 64)
}

func aecClassFromFinding(finding DetectionEvent) int {
	score := clampUnitInterval(finding.Confidence)
	switch {
	case score >= 0.95:
		return 3
	case score >= 0.85:
		return 2
	case finding.Decision == "malicious" || score >= 0.75:
		return 1
	default:
		return 0
	}
}

func clampOpenUnitInterval(value float64) float64 {
	switch {
	case value <= 0:
		return 0.00000001
	case value >= 1:
		return 0.99999999
	default:
		return value
	}
}

func clampUnitInterval(value float64) float64 {
	switch {
	case value <= 0:
		return 0
	case value >= 1:
		return 1
	default:
		return value
	}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func writeSealedBlobAtomically(filePath string, blob []byte, writeHook func(string, []byte, os.FileMode) error) error {
	tmpPath := filePath + ".tmp"
	_ = os.Remove(tmpPath)

	if writeHook != nil {
		if err := writeHook(tmpPath, blob, 0o600); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
	} else {
		if err := writeTempFile(tmpPath, blob, 0o600); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
	}
	if err := fsyncFile(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0o444); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := syncParentDirOf(filePath); err != nil {
		_ = removeSealedEvidenceFile(filePath)
		return err
	}
	return nil
}

func writeTempFile(path string, blob []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncParentDirOf(path string) error {
	dir := filepath.Dir(path)
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer df.Close()
	return df.Sync()
}

func removeSealedEvidenceFile(path string) error {
	if path == "" {
		return nil
	}
	_ = os.Chmod(path, 0o644)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
