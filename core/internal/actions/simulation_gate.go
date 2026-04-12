package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	DefaultSimulationRiskThreshold = 0.7
	replayReadonlyRole             = "ransomeye_readonly"
	statusPendingConfirmation      = "PENDING_CONFIRMATION"
	statusDispatched               = "DISPATCHED"
	actionTypeIsolateHost          = "ISOLATE_HOST"
	recommendationProceed          = "PROCEED"
	recommendationHold             = "HOLD"
	recommendationEscalate         = "ESCALATE"
	totpApprovalWindow             = 5 * time.Minute
)

var (
	ErrSimulationHold         = errors.New("simulation recommendation is HOLD")
	ErrRiskThresholdExceeded  = errors.New("simulation risk exceeds threshold")
	ErrTOTPExpired            = errors.New("totp verification is missing or older than 5 minutes")
	ErrReadonlyRoleRequired   = errors.New("attack replay pre-check must use ransomeye_readonly role")
	ErrInvalidApproverRole    = errors.New("approver must have ANALYST or ADMIN role")
)

type SimulationGate struct {
	writePool               *pgxpool.Pool
	replayReadPool          *pgxpool.Pool
	simulationRiskThreshold float64
	now                     func() time.Time
}

type IsolationSimulationInput struct {
	ActionID                  string
	RiskScore                 float64
	EstimatedDowntimeMinutes  int
	AffectedSystems           []string
	SimulationDetail          map[string]any
	Recommendation            string
}

type IsolationSimulationResult struct {
	ActionID                  string
	DetectionID               string
	Recommendation            string
	NormalizedRisk            float64
	ThresholdExceeded         bool
	Status                    string
	AffectedSystems           []string
	EstimatedDowntimeMinutes  int
}

type IsolationApprovalInput struct {
	ActionID string
	Username string
}

type actionContext struct {
	ActionID     string
	TenantID     string
	DetectionID  string
	AgentID      string
	ActionType   string
	Status       string
}

type replayPrecheck struct {
	PathScore       float64
	AffectedSystems []string
}

func NewSimulationGate(writePool, replayReadPool *pgxpool.Pool) (*SimulationGate, error) {
	if writePool == nil {
		return nil, errors.New("nil write pool")
	}
	if replayReadPool == nil {
		return nil, errors.New("nil replay read pool")
	}

	return &SimulationGate{
		writePool:               writePool,
		replayReadPool:          replayReadPool,
		simulationRiskThreshold: DefaultSimulationRiskThreshold,
		now:                     time.Now,
	}, nil
}

func (g *SimulationGate) PrepareIsolation(ctx context.Context, in IsolationSimulationInput) (*IsolationSimulationResult, error) {
	if g == nil || g.writePool == nil || g.replayReadPool == nil {
		return nil, errors.New("simulation gate not initialized")
	}
	if strings.TrimSpace(in.ActionID) == "" {
		return nil, errors.New("missing action_id")
	}

	actionCtx, err := g.loadActionContext(ctx, in.ActionID)
	if err != nil {
		return nil, err
	}
	if actionCtx.ActionType != actionTypeIsolateHost {
		return nil, fmt.Errorf("simulation gate only supports %s actions", actionTypeIsolateHost)
	}
	if actionCtx.DetectionID == "" {
		return nil, fmt.Errorf("isolation action %s is missing detection_id", actionCtx.ActionID)
	}

	precheck, err := g.runAttackReplayPrecheck(ctx, actionCtx.DetectionID)
	if err != nil {
		return nil, err
	}

	storedRisk, normalizedRisk, err := normalizeRiskScore(in.RiskScore, precheck.PathScore)
	if err != nil {
		return nil, err
	}

	affectedSystems := sanitizeAffectedSystems(in.AffectedSystems)
	if len(affectedSystems) == 0 {
		affectedSystems = sanitizeAffectedSystems(precheck.AffectedSystems)
	}
	if len(affectedSystems) == 0 {
		affectedSystems = []string{actionCtx.AgentID}
	}

	downtime := in.EstimatedDowntimeMinutes
	if downtime <= 0 {
		downtime = estimateDowntimeMinutes(precheck.PathScore, len(affectedSystems))
	}

	recommendation := effectiveRecommendation(strings.ToUpper(strings.TrimSpace(in.Recommendation)), normalizedRisk, g.simulationRiskThreshold)
	thresholdExceeded := normalizedRisk > g.simulationRiskThreshold
	status := statusPendingConfirmation
	resultDetail := buildResultDetail(recommendation, normalizedRisk, g.simulationRiskThreshold, thresholdExceeded, downtime, affectedSystems)

	simulationDetail, err := marshalSimulationDetail(in.SimulationDetail, precheck, normalizedRisk, downtime, affectedSystems)
	if err != nil {
		return nil, err
	}

	affectedSystemsJSON, err := json.Marshal(affectedSystems)
	if err != nil {
		return nil, err
	}

	tx, err := g.writePool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	const qSim = `
INSERT INTO simulation_runs (
    tenant_id,
    detection_id,
    action_id,
    risk_score,
    affected_systems,
    estimated_downtime_minutes,
    recommendation,
    simulation_detail
)
VALUES (
    $1::uuid,
    $2::uuid,
    $3::uuid,
    $4::numeric,
    $5::jsonb,
    $6::integer,
    $7::text,
    $8::jsonb
)
`
	if _, err := tx.Exec(ctx, qSim,
		actionCtx.TenantID,
		actionCtx.DetectionID,
		actionCtx.ActionID,
		storedRisk,
		affectedSystemsJSON,
		downtime,
		recommendation,
		simulationDetail,
	); err != nil {
		return nil, err
	}

	const qAction = `
UPDATE actions
SET
    status = $2::text,
    approval_required = TRUE,
    result_detail = $3::text
WHERE action_id = $1::uuid
`
	if _, err := tx.Exec(ctx, qAction, actionCtx.ActionID, status, resultDetail); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true

	result := &IsolationSimulationResult{
		ActionID:                 actionCtx.ActionID,
		DetectionID:              actionCtx.DetectionID,
		Recommendation:           recommendation,
		NormalizedRisk:           normalizedRisk,
		ThresholdExceeded:        thresholdExceeded,
		Status:                   status,
		AffectedSystems:          affectedSystems,
		EstimatedDowntimeMinutes: downtime,
	}

	if recommendation == recommendationHold {
		return result, ErrSimulationHold
	}
	if thresholdExceeded {
		return result, ErrRiskThresholdExceeded
	}
	return result, nil
}

func (g *SimulationGate) ApproveIsolation(ctx context.Context, in IsolationApprovalInput) error {
	if g == nil || g.writePool == nil {
		return errors.New("simulation gate not initialized")
	}
	if strings.TrimSpace(in.ActionID) == "" {
		return errors.New("missing action_id")
	}
	if strings.TrimSpace(in.Username) == "" {
		return errors.New("missing username")
	}

	tx, err := g.writePool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	const q = `
SELECT
    a.tenant_id::text,
    a.action_type,
    a.totp_verified_at,
    COALESCE(a.status, ''),
    u.role,
    u.is_active,
    COALESCE(s.recommendation, ''),
    COALESCE(s.risk_score, 0)
FROM actions a
JOIN soc_users u
  ON u.tenant_id = a.tenant_id
 AND u.username = $2::text
LEFT JOIN LATERAL (
    SELECT recommendation, risk_score
    FROM simulation_runs
    WHERE action_id = a.action_id
       OR (action_id IS NULL AND detection_id = a.detection_id)
    ORDER BY simulated_at DESC
    LIMIT 1
) s ON TRUE
WHERE a.action_id = $1::uuid
`
	var tenantID string
	var actionType string
	var totpVerifiedAt *time.Time
	var status string
	var role string
	var isActive bool
	var recommendation string
	var storedRisk float64
	if err := tx.QueryRow(ctx, q, in.ActionID, in.Username).Scan(
		&tenantID,
		&actionType,
		&totpVerifiedAt,
		&status,
		&role,
		&isActive,
		&recommendation,
		&storedRisk,
	); err != nil {
		return err
	}

	if actionType != actionTypeIsolateHost {
		return fmt.Errorf("action %s is not %s", in.ActionID, actionTypeIsolateHost)
	}
	if !isActive || (role != "ANALYST" && role != "ADMIN") {
		return ErrInvalidApproverRole
	}
	if recommendation == "" {
		return errors.New("missing simulation run for isolation approval")
	}
	if totpVerifiedAt == nil || g.now().UTC().Sub(totpVerifiedAt.UTC()) > totpApprovalWindow {
		return ErrTOTPExpired
	}

	normalizedRisk := storedRisk / 100.0
	if recommendation == recommendationHold {
		if err := g.updatePendingReason(ctx, tx, in.ActionID, "simulation HOLD recommendation blocks dispatch"); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		committed = true
		return ErrSimulationHold
	}
	if normalizedRisk > g.simulationRiskThreshold {
		if err := g.updatePendingReason(ctx, tx, in.ActionID, fmt.Sprintf("simulation risk %.2f exceeded threshold %.2f", normalizedRisk, g.simulationRiskThreshold)); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		committed = true
		return ErrRiskThresholdExceeded
	}
	if recommendation != recommendationProceed && recommendation != recommendationEscalate {
		return fmt.Errorf("simulation recommendation %q does not permit dispatch", recommendation)
	}
	if status != statusPendingConfirmation {
		return fmt.Errorf("action %s is not awaiting confirmation (status=%s)", in.ActionID, status)
	}

	const qUpdate = `
UPDATE actions
SET
    status = $2::text,
    approved_by = $3::text,
    approved_at = $4::timestamptz,
    dispatched_at = $4::timestamptz,
    result_detail = $5::text
WHERE action_id = $1::uuid
`
	now := g.now().UTC()
	if _, err := tx.Exec(ctx, qUpdate, in.ActionID, statusDispatched, in.Username, now, "simulation gate approved; ready for dispatch"); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	_ = tenantID
	return nil
}

func (g *SimulationGate) loadActionContext(ctx context.Context, actionID string) (*actionContext, error) {
	const q = `
SELECT
    action_id::text,
    tenant_id::text,
    COALESCE(detection_id::text, ''),
    COALESCE(agent_id::text, ''),
    action_type,
    status
FROM actions
WHERE action_id = $1::uuid
`
	var out actionContext
	if err := g.writePool.QueryRow(ctx, q, actionID).Scan(
		&out.ActionID,
		&out.TenantID,
		&out.DetectionID,
		&out.AgentID,
		&out.ActionType,
		&out.Status,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (g *SimulationGate) runAttackReplayPrecheck(ctx context.Context, detectionID string) (*replayPrecheck, error) {
	tx, err := g.replayReadPool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var currentUser string
	if err := tx.QueryRow(ctx, "SELECT current_user::text").Scan(&currentUser); err != nil {
		return nil, err
	}
	if currentUser != replayReadonlyRole {
		return nil, fmt.Errorf("%w: got %s", ErrReadonlyRoleRequired, currentUser)
	}

	const q = `
SELECT node_sequence, score
FROM attack_paths
WHERE detection_id = $1::uuid
`
	var nodeSequence []byte
	var score float64
	if err := tx.QueryRow(ctx, q, detectionID).Scan(&nodeSequence, &score); err != nil {
		return nil, err
	}

	var decoded any
	if err := json.Unmarshal(nodeSequence, &decoded); err != nil {
		return nil, err
	}

	return &replayPrecheck{
		PathScore:       score,
		AffectedSystems: extractAffectedSystems(decoded),
	}, nil
}

func (g *SimulationGate) updatePendingReason(ctx context.Context, tx pgx.Tx, actionID, detail string) error {
	const q = `
UPDATE actions
SET
    status = $2::text,
    result_detail = $3::text
WHERE action_id = $1::uuid
`
	_, err := tx.Exec(ctx, q, actionID, statusPendingConfirmation, detail)
	return err
}

func normalizeRiskScore(input, fallback float64) (stored float64, normalized float64, err error) {
	if input < 0 {
		return 0, 0, fmt.Errorf("invalid risk score %.4f", input)
	}
	if fallback < 0 {
		return 0, 0, fmt.Errorf("invalid fallback risk score %.4f", fallback)
	}

	score := input
	if score == 0 {
		score = fallback
	}
	switch {
	case score <= 1:
		return round(score * 100), score, nil
	case score <= 100:
		return round(score), score / 100.0, nil
	default:
		return 0, 0, fmt.Errorf("invalid risk score %.4f", score)
	}
}

func effectiveRecommendation(in string, normalizedRisk, threshold float64) string {
	switch in {
	case recommendationProceed, recommendationHold, recommendationEscalate:
		if normalizedRisk > threshold {
			return recommendationHold
		}
		return in
	default:
		if normalizedRisk > threshold {
			return recommendationHold
		}
		if normalizedRisk >= threshold*0.85 {
			return recommendationEscalate
		}
		return recommendationProceed
	}
}

func estimateDowntimeMinutes(pathScore float64, affectedSystems int) int {
	base := int(math.Ceil(pathScore * 60))
	if base < 5 {
		base = 5
	}
	base += affectedSystems * 5
	return base
}

func sanitizeAffectedSystems(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	slices.Sort(out)
	return out
}

func buildResultDetail(recommendation string, normalizedRisk, threshold float64, thresholdExceeded bool, downtime int, systems []string) string {
	detail := fmt.Sprintf(
		"AEC-3 simulation completed recommendation=%s risk=%.2f threshold=%.2f downtime_minutes=%d affected_systems=%d",
		recommendation,
		normalizedRisk,
		threshold,
		downtime,
		len(systems),
	)
	if thresholdExceeded {
		return detail + " forced_review=true"
	}
	return detail + " forced_review=false"
}

func marshalSimulationDetail(input map[string]any, precheck *replayPrecheck, normalizedRisk float64, downtime int, systems []string) ([]byte, error) {
	detail := map[string]any{
		"simulation_source":            "simulation_gate",
		"attack_path_score":            precheck.PathScore,
		"normalized_risk_score":        normalizedRisk,
		"estimated_downtime_minutes":   downtime,
		"affected_systems":             systems,
	}
	for k, v := range input {
		detail[k] = v
	}
	return json.Marshal(detail)
}

func extractAffectedSystems(node any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch typed := v.(type) {
		case string:
			trimmed := strings.TrimSpace(typed)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(node)
	return sanitizeAffectedSystems(out)
}

func round(v float64) float64 {
	return math.Round(v*100) / 100
}
