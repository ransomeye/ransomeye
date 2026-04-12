package failure

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"

	"ransomeye/core/internal/ai"
	internalapi "ransomeye/core/internal/api"
	wormcrypto "ransomeye/core/internal/crypto"
	coreconfig "ransomeye/core/internal/config"
	dbbase "ransomeye/core/internal/db"
	"ransomeye/core/internal/db/migrator"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/netcfg"
	"ransomeye/core/internal/pipeline"
	"ransomeye/core/internal/replay"
	"ransomeye/core/internal/storage"
	coreperf "ransomeye/core/performance"
	internalaipb "ransomeye/proto/internalai"
)

const (
	scenarioDBDown         = "db_down"
	scenarioDiskFull       = "disk_full"
	scenarioAIServiceCrash = "ai_service_crash"
	scenarioTLSFailure     = "tls_failure"
	scenarioOverflow       = "pipeline_overflow"
)

type Config struct {
	DBMaxConns int32 `json:"db_max_conns"`
}

type ScenarioResult struct {
	Scenario            string `json:"scenario"`
	Passed              bool   `json:"passed"`
	FailClosed          bool   `json:"fail_closed"`
	DataIntegrity       bool   `json:"data_integrity"`
	ReplayValid         bool   `json:"replay_valid"`
	DBConsistent        bool   `json:"db_consistent"`
	NoOrphanRecords     bool   `json:"no_orphan_records"`
	DeterministicDrop   bool   `json:"deterministic_drop,omitempty"`
	NoDeadlock          bool   `json:"no_deadlock,omitempty"`
	NoDetectionOutput   bool   `json:"no_detection_output,omitempty"`
	NoFallbackHeuristic bool   `json:"no_fallback_heuristic,omitempty"`
	ObservedError       string `json:"observed_error,omitempty"`
}

type Report struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Config      Config           `json:"config"`
	Results     []ScenarioResult `json:"results"`
	Passed      bool             `json:"passed"`
	Failures    []string         `json:"failures,omitempty"`
}

type harnessEnv struct {
	repoRoot string
	dbCfg    dbbase.Config
	db       *storage.DB
}

type noopReleaser struct{}

func (noopReleaser) ReleaseTelemetryPayload(_ *ingest.VerifiedTelemetry) {}

type aiEvalServer struct {
	internalaipb.UnimplementedAIDetectionServiceServer
}

func (s *aiEvalServer) EvaluateTelemetry(context.Context, *internalaipb.EvaluationRequest) (*internalaipb.EvaluationResponse, error) {
	return &internalaipb.EvaluationResponse{
		PosteriorProbability: 0.99,
		AecClass:             "AEC-3",
	}, nil
}

type persistenceState struct {
	TelemetryRows        int64
	EvidenceRows         int64
	TelemetryWithoutWORM int64
	WORMWithoutTelemetry int64
	FinalFiles           int
	TempFiles            int
}

func DefaultConfig() Config {
	return Config{DBMaxConns: 4}
}

func RunFailureValidation(ctx context.Context, cfg Config) (Report, error) {
	cfg = normalizeConfig(cfg)
	report := Report{
		GeneratedAt: time.Now().UTC(),
		Config:      cfg,
	}

	env, err := openHarnessEnv(ctx, cfg)
	if err != nil {
		report.Failures = append(report.Failures, fmt.Sprintf("environment: %v", err))
		return report, err
	}
	defer env.db.Close()

	replayID, cleanupReplay, err := env.prepareReplayBaseline(ctx)
	if err != nil {
		report.Failures = append(report.Failures, fmt.Sprintf("replay baseline: %v", err))
		return report, err
	}
	defer cleanupReplay()

	report.Results = append(report.Results,
		runDBDownScenario(ctx, env, replayID),
		runDiskFullScenario(ctx, env, replayID),
		runAIServiceCrashScenario(ctx, env, replayID),
		runTLSFailureScenario(ctx, env, replayID),
		runPipelineOverflowScenario(ctx, env, replayID),
	)

	for _, result := range report.Results {
		if !result.Passed {
			report.Failures = append(report.Failures, formatFailure(result))
		}
	}

	report.Passed = len(report.Failures) == 0
	if !report.Passed {
		return report, errors.New(strings.Join(report.Failures, "; "))
	}
	return report, nil
}

func WriteJSON(path string, report Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func WriteMarkdown(path string, report Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Failure Validation Report\n\n")
	b.WriteString(fmt.Sprintf("- Generated: `%s`\n", report.GeneratedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Passed: `%t`\n\n", report.Passed))
	b.WriteString("| Scenario | Pass | Fail-Closed | Integrity | Replay | DB | Orphans |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, result := range report.Results {
		b.WriteString(fmt.Sprintf(
			"| %s | %t | %t | %t | %t | %t | %t |\n",
			result.Scenario,
			result.Passed,
			result.FailClosed,
			result.DataIntegrity,
			result.ReplayValid,
			result.DBConsistent,
			result.NoOrphanRecords,
		))
	}
	if len(report.Failures) > 0 {
		b.WriteString("\n## Failures\n\n")
		for _, failure := range report.Failures {
			b.WriteString(fmt.Sprintf("- %s\n", failure))
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func runDBDownScenario(ctx context.Context, env harnessEnv, replayID uuid.UUID) ScenarioResult {
	result := ScenarioResult{Scenario: scenarioDBDown}
	fixture, cleanup, err := env.newPersistenceFixture(ctx)
	if err != nil {
		result.ObservedError = err.Error()
		return finalizeResult(result)
	}
	defer cleanup()

	fixture.worker.SetPersistenceHooks(pipeline.PersistenceHooks{
		AfterTelemetryInsert: func(ctx context.Context, tx pgx.Tx, _ string) error {
			var pid int32
			if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
				return err
			}
			var terminated bool
			if err := env.db.Pool.QueryRow(ctx, "SELECT pg_terminate_backend($1)", pid).Scan(&terminated); err != nil {
				return err
			}
			if !terminated {
				return errors.New("pg_terminate_backend returned false")
			}
			return nil
		},
	})

	err = fixture.worker.ProcessOne(ctx, fixture.telemetry)
	if err != nil {
		result.ObservedError = err.Error()
	}
	state, stateErr := collectPersistenceState(ctx, env.db.Pool, fixture.tenantID, fixture.agentID, fixture.storageRoot)
	if stateErr != nil && result.ObservedError == "" {
		result.ObservedError = stateErr.Error()
	}
	replayValid, replayErr := verifyStoredReplay(ctx, env.dbCfg, replayID)
	if replayErr != nil && result.ObservedError == "" {
		result.ObservedError = replayErr.Error()
	}

	result.FailClosed = err != nil
	result.DataIntegrity = state.clean()
	result.DBConsistent = state.dbConsistent()
	result.NoOrphanRecords = state.orphanCount() == 0
	result.ReplayValid = replayValid
	return finalizeResult(result)
}

func runDiskFullScenario(ctx context.Context, env harnessEnv, replayID uuid.UUID) ScenarioResult {
	result := ScenarioResult{Scenario: scenarioDiskFull}
	fixture, cleanup, err := env.newPersistenceFixture(ctx)
	if err != nil {
		result.ObservedError = err.Error()
		return finalizeResult(result)
	}
	defer cleanup()

	fixture.worker.SetPersistenceHooks(pipeline.PersistenceHooks{
		WriteSealedTempFile: func(path string, blob []byte, mode os.FileMode) error {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			partial := len(blob) / 2
			if partial == 0 {
				partial = 1
			}
			if _, err := f.Write(blob[:partial]); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			return syscall.ENOSPC
		},
	})

	err = fixture.worker.ProcessOne(ctx, fixture.telemetry)
	if err != nil {
		result.ObservedError = err.Error()
	}
	state, stateErr := collectPersistenceState(ctx, env.db.Pool, fixture.tenantID, fixture.agentID, fixture.storageRoot)
	if stateErr != nil && result.ObservedError == "" {
		result.ObservedError = stateErr.Error()
	}
	replayValid, replayErr := verifyStoredReplay(ctx, env.dbCfg, replayID)
	if replayErr != nil && result.ObservedError == "" {
		result.ObservedError = replayErr.Error()
	}

	result.FailClosed = err != nil
	result.DataIntegrity = state.clean()
	result.DBConsistent = state.dbConsistent()
	result.NoOrphanRecords = state.orphanCount() == 0
	result.ReplayValid = replayValid
	return finalizeResult(result)
}

func runAIServiceCrashScenario(ctx context.Context, env harnessEnv, replayID uuid.UUID) ScenarioResult {
	result := ScenarioResult{Scenario: scenarioAIServiceCrash}

	lis, err := net.Listen("tcp", net.JoinHostPort(netcfg.LoopbackHost, "0"))
	if err != nil {
		result.ObservedError = err.Error()
		return finalizeResult(result)
	}
	defer lis.Close()

	server := grpc.NewServer()
	internalaipb.RegisterAIDetectionServiceServer(server, &aiEvalServer{})
	go func() {
		_ = server.Serve(lis)
	}()

	client, err := ai.Dial(ctx, ai.ClientOptions{
		Addr:        lis.Addr().String(),
		DialTimeout: time.Second,
	})
	if err != nil {
		server.Stop()
		result.ObservedError = err.Error()
		return finalizeResult(result)
	}
	defer client.Close()

	server.Stop()

	router := ai.NewRouter(client, nil, 4, nil)
	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var logBuf bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(previousWriter)

	done := make(chan error, 1)
	go func() {
		done <- router.Run(runCtx)
	}()

	router.TryEnqueue("failure-ai-event", "failure-ai-agent", []byte(`{"kind":"telemetry"}`), 11)
	router.Close()

	select {
	case runErr := <-done:
		if runErr != nil && !errors.Is(runErr, context.Canceled) && result.ObservedError == "" {
			result.ObservedError = runErr.Error()
		}
	case <-time.After(3 * time.Second):
		result.ObservedError = "AI router did not drain after service crash"
	}

	logs := logBuf.String()
	replayValid, replayErr := verifyStoredReplay(ctx, env.dbCfg, replayID)
	if replayErr != nil && result.ObservedError == "" {
		result.ObservedError = replayErr.Error()
	}

	result.NoDetectionOutput = !strings.Contains(logs, "AI_EVALUATED")
	result.NoFallbackHeuristic = !strings.Contains(logs, "decision=")
	result.FailClosed = strings.Contains(logs, "AI_EVALUATE_FAILED") && result.NoDetectionOutput && result.NoFallbackHeuristic
	result.DataIntegrity = true
	result.DBConsistent = true
	result.NoOrphanRecords = true
	result.ReplayValid = replayValid
	return finalizeResult(result)
}

func runTLSFailureScenario(ctx context.Context, env harnessEnv, replayID uuid.UUID) ScenarioResult {
	result := ScenarioResult{Scenario: scenarioTLSFailure}

	badCfg := env.dbCfg
	badCfg.TLSServerName = "invalid.ransomeye.local"
	conn, err := dbbase.Connect(ctx, badCfg)
	if err == nil {
		conn.Close(ctx)
		result.ObservedError = "expected TLS validation failure, got successful connection"
	} else {
		result.ObservedError = err.Error()
	}
	replayValid, replayErr := verifyStoredReplay(ctx, env.dbCfg, replayID)
	if replayErr != nil && err != nil {
		result.ObservedError = err.Error() + "; " + replayErr.Error()
	} else if replayErr != nil && result.ObservedError == "" {
		result.ObservedError = replayErr.Error()
	}

	result.FailClosed = err != nil
	result.DataIntegrity = true
	result.DBConsistent = true
	result.NoOrphanRecords = true
	result.ReplayValid = replayValid
	return finalizeResult(result)
}

func runPipelineOverflowScenario(ctx context.Context, env harnessEnv, replayID uuid.UUID) ScenarioResult {
	result := ScenarioResult{Scenario: scenarioOverflow}

	backpressure := coreperf.ValidateDeterministicBackpressure()
	replayValid, replayErr := verifyStoredReplay(ctx, env.dbCfg, replayID)
	if replayErr != nil {
		result.ObservedError = replayErr.Error()
	}

	result.DeterministicDrop = backpressure.SchedulerDeterministic && backpressure.DispatcherDeterministic && backpressure.HubDeterministic
	result.NoDeadlock = backpressure.NoDeadlocks && backpressure.SchedulerNoBlocking && backpressure.DispatcherNoBlocking && backpressure.HubNoBlocking
	result.FailClosed = result.DeterministicDrop && result.NoDeadlock
	result.DataIntegrity = true
	result.DBConsistent = true
	result.NoOrphanRecords = true
	result.ReplayValid = replayValid
	if !result.FailClosed && result.ObservedError == "" {
		result.ObservedError = fmt.Sprintf("%+v", backpressure)
	}
	return finalizeResult(result)
}

func openHarnessEnv(ctx context.Context, cfg Config) (harnessEnv, error) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return harnessEnv{}, err
	}

	dbCfg := dbbase.LoadConfigFromEnv()
	configPath, cfgPathErr := internalapi.ResolveConfigPath()
	if cfgPathErr == nil {
		cc, err := coreconfig.LoadVerifiedCommonConfig(
			configPath,
			coreconfig.IntermediateCACertPath,
		)
		if err != nil {
			return harnessEnv{}, fmt.Errorf("load signed common config for postgres fingerprint: %w", err)
		}
		dbCfg.ExpectedPostgresServerFingerprint = strings.TrimSpace(cc.Database.ExpectedServerFingerprint)
	}
	if dbCfg.ExpectedPostgresServerFingerprint == "" {
		return harnessEnv{}, fmt.Errorf("database fingerprint unavailable")
	}
	if _, err := migrator.Run(ctx, migrator.Config{DB: dbCfg}); err != nil {
		return harnessEnv{}, fmt.Errorf("database migrate unavailable: %w", err)
	}

	dbCfg.PoolMaxConns = cfg.DBMaxConns
	pool, err := dbbase.NewPool(ctx, dbCfg)
	if err != nil {
		return harnessEnv{}, fmt.Errorf("database open unavailable: %w", err)
	}
	db := &storage.DB{Pool: pool}

	return harnessEnv{
		repoRoot: repoRoot,
		dbCfg:    dbCfg,
		db:       db,
	}, nil
}

func (e harnessEnv) prepareReplayBaseline(ctx context.Context) (uuid.UUID, func(), error) {
	keyPath := filepath.Join(os.TempDir(), fmt.Sprintf("ransomeye-failure-replay-%d.key", time.Now().UnixNano()))
	seed := make([]byte, ed25519.SeedSize)
	for idx := range seed {
		seed[idx] = byte(idx)
	}
	if err := os.WriteFile(keyPath, seed, 0o600); err != nil {
		return uuid.Nil, nil, err
	}

	metadata, err := resolveReplayMetadata(e.repoRoot, keyPath)
	if err != nil {
		_ = os.Remove(keyPath)
		return uuid.Nil, nil, err
	}

	restore := captureEnv([]string{
		replay.DefaultReplaySigningKeyEnv,
		replay.DefaultConfigHashEnv,
		replay.DefaultModelHashEnv,
		replay.DefaultFeatureVersionEnv,
		replay.DefaultPRDHashEnv,
		"RANSOMEYE_AI_ROOT",
	})

	os.Setenv(replay.DefaultReplaySigningKeyEnv, keyPath)
	os.Setenv(replay.DefaultConfigHashEnv, metadata.ConfigHash)
	os.Setenv(replay.DefaultModelHashEnv, metadata.ModelHash)
	os.Setenv(replay.DefaultFeatureVersionEnv, metadata.FeatureVersion)
	os.Setenv(replay.DefaultPRDHashEnv, metadata.PRDHash)
	os.Setenv("RANSOMEYE_AI_ROOT", filepath.Join(e.repoRoot, "ml"))

	envelopePath := filepath.Join(os.TempDir(), fmt.Sprintf("ransomeye-failure-replay-%d.rre", time.Now().UnixNano()))
	envelope, err := deterministicReplayEnvelope(envelopePath, metadata)
	if err != nil {
		restore()
		_ = os.Remove(keyPath)
		_ = os.Remove(envelopePath)
		return uuid.Nil, nil, err
	}

	store, err := replay.NewBaselineStore(e.db.Pool, metadata)
	if err != nil {
		restore()
		_ = os.Remove(keyPath)
		_ = os.Remove(envelopePath)
		return uuid.Nil, nil, err
	}
	replayID, err := store.CaptureEnvelope(ctx, envelope)
	if err != nil {
		restore()
		_ = os.Remove(keyPath)
		_ = os.Remove(envelopePath)
		return uuid.Nil, nil, err
	}

	cleanup := func() {
		restore()
		_ = os.Remove(keyPath)
		_ = os.Remove(envelopePath)
	}
	return replayID, cleanup, nil
}

func (e harnessEnv) newPersistenceFixture(ctx context.Context) (*scenarioFixture, func(), error) {
	tenantID := uuid.New().String()
	agentID := uuid.New().String()
	if err := seedTenantSession(ctx, e.db.Pool, tenantID, agentID); err != nil {
		return nil, nil, err
	}

	storageRoot, err := os.MkdirTemp("", "ransomeye-failure-worm-*")
	if err != nil {
		return nil, nil, err
	}
	restoreWORM := captureEnv([]string{"WORM_STORAGE_PATH"})
	os.Setenv("WORM_STORAGE_PATH", storageRoot)

	worm, err := newWORM()
	if err != nil {
		restoreWORM()
		_ = os.RemoveAll(storageRoot)
		return nil, nil, err
	}
	telemetry, err := deterministicTelemetry(agentID)
	if err != nil {
		restoreWORM()
		_ = os.RemoveAll(storageRoot)
		return nil, nil, err
	}

	fixture := &scenarioFixture{
		tenantID:    tenantID,
		agentID:     agentID,
		storageRoot: storageRoot,
		telemetry:   telemetry,
		worker: &pipeline.WorkerPool{
			DB:       e.db,
			Releaser: noopReleaser{},
			WORM:     worm,
			Source:   "linux_agent",
		},
	}
	cleanup := func() {
		restoreWORM()
		cleanupTenantSession(context.Background(), e.db.Pool, tenantID)
		_ = os.RemoveAll(storageRoot)
	}
	return fixture, cleanup, nil
}

type scenarioFixture struct {
	tenantID    string
	agentID     string
	storageRoot string
	telemetry   *ingest.VerifiedTelemetry
	worker      *pipeline.WorkerPool
}

func seedTenantSession(ctx context.Context, pool *pgxpool.Pool, tenantID, agentID string) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ts := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	if _, err := tx.Exec(ctx, `
INSERT INTO tenants (
    tenant_id,
    tenant_name,
    tenant_slug,
    dek_wrapped,
    status,
    created_at,
    updated_at
)
VALUES (
    $1,
    $2,
    $3,
    decode(repeat('11', 60), 'hex'),
    'ACTIVE',
    $4,
    $4
)`,
		tenantID,
		"failure-"+tenantID[:8],
		"failure-"+tenantID[:8],
		ts,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO agent_sessions (
    session_id,
    agent_id,
    tenant_id,
    boot_session_id,
    hostname,
    primary_ip,
    agent_type,
    agent_version,
    binary_hash,
    tpm_quote,
    tpm_pcr_values,
    last_heartbeat,
    status,
    lamport_clock,
    os_info,
    last_seen_ip,
    is_critical_asset,
    enrolled_at,
    created_at,
    updated_at
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $8::inet,
    'linux',
    'V0.0',
    $6,
    '\x'::bytea,
    '{}'::jsonb,
    $7,
    'ACTIVE',
    1,
    '{}'::jsonb,
    $8::inet,
    FALSE,
    $7,
    $7,
    $7
)`,
		uuid.NewString(),
		agentID,
		tenantID,
		uuid.NewString(),
		"failure-host-"+agentID[:8],
		strings.Repeat("b", 64),
		ts,
		netcfg.LoopbackHost,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func cleanupTenantSession(ctx context.Context, pool *pgxpool.Pool, tenantID string) {
	_, _ = pool.Exec(ctx, `DELETE FROM worm_evidence WHERE tenant_id = $1::uuid`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM telemetry_events WHERE tenant_id = $1::uuid`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM agent_sessions WHERE tenant_id = $1::uuid`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE tenant_id = $1::uuid`, tenantID)
}

func collectPersistenceState(ctx context.Context, pool *pgxpool.Pool, tenantID, agentID, storageRoot string) (persistenceState, error) {
	var state persistenceState
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM telemetry_events WHERE agent_id = $1::uuid`, agentID).Scan(&state.TelemetryRows); err != nil {
		return state, err
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM worm_evidence WHERE tenant_id = $1::uuid AND file_path LIKE $2`, tenantID, storageRoot+"%").Scan(&state.EvidenceRows); err != nil {
		return state, err
	}
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)
FROM telemetry_events te
LEFT JOIN worm_evidence we ON te.event_id = we.event_id
WHERE te.agent_id = $1::uuid AND we.event_id IS NULL`, agentID).Scan(&state.TelemetryWithoutWORM); err != nil {
		return state, err
	}
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)
FROM worm_evidence we
LEFT JOIN telemetry_events te ON we.event_id = te.event_id
WHERE we.tenant_id = $1::uuid AND we.file_path LIKE $2 AND te.event_id IS NULL`, tenantID, storageRoot+"%").Scan(&state.WORMWithoutTelemetry); err != nil {
		return state, err
	}
	finalFiles, tempFiles, err := countEvidenceFiles(storageRoot)
	if err != nil {
		return state, err
	}
	state.FinalFiles = finalFiles
	state.TempFiles = tempFiles
	return state, nil
}

func countEvidenceFiles(root string) (int, int, error) {
	if root == "" {
		return 0, 0, nil
	}
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	finalFiles := 0
	tempFiles := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".sealed"):
			finalFiles++
		case strings.HasSuffix(path, ".tmp"):
			tempFiles++
		}
		return nil
	})
	return finalFiles, tempFiles, err
}

func (s persistenceState) orphanCount() int64 {
	return s.TelemetryWithoutWORM + s.WORMWithoutTelemetry
}

func (s persistenceState) clean() bool {
	return s.TelemetryRows == 0 && s.EvidenceRows == 0 && s.orphanCount() == 0 && s.FinalFiles == 0 && s.TempFiles == 0
}

func (s persistenceState) dbConsistent() bool {
	return s.orphanCount() == 0
}

func verifyStoredReplay(ctx context.Context, cfg dbbase.Config, replayID uuid.UUID) (bool, error) {
	conn, err := dbbase.Connect(ctx, cfg)
	if err != nil {
		return false, err
	}
	defer conn.Close(ctx)

	result, err := replay.VerifyStoredReplay(ctx, conn, replayID)
	if err != nil {
		return false, err
	}
	return result.Status == "PASS", nil
}

func resolveReplayMetadata(repoRoot, signingKeyPath string) (replay.Metadata, error) {
	model, err := ai.LoadRuntimeModelFromRootWithSigningKeyPath(filepath.Join(repoRoot, "ml"), signingKeyPath)
	if err != nil {
		return replay.Metadata{}, err
	}
	return replay.Metadata{
		ConfigHash:     strings.Repeat("1", 64),
		ModelHash:      model.Identity.ModelHash,
		FeatureVersion: model.Identity.FeatureVersion,
		PRDHash:        strings.Repeat("3", 64),
	}, nil
}

func deterministicReplayEnvelope(path string, metadata replay.Metadata) (replay.Envelope, error) {
	capture, err := replay.NewInputCapture(path, metadata)
	if err != nil {
		return replay.Envelope{}, err
	}
	ev1, err := deterministicReplayTelemetry(7, uuid.MustParse("00000000-0000-0000-0000-000000000007"), 1_700_000_000_000_000_000, 4242, 250)
	if err != nil {
		return replay.Envelope{}, err
	}
	ev2, err := deterministicReplayTelemetry(8, uuid.MustParse("00000000-0000-0000-0000-000000000008"), 1_700_000_000_000_000_100, 999999, 255)
	if err != nil {
		return replay.Envelope{}, err
	}
	if err := capture.CaptureVerifiedDPIEvent(ev1); err != nil {
		return replay.Envelope{}, err
	}
	if err := capture.CaptureVerifiedDPIEvent(ev2); err != nil {
		return replay.Envelope{}, err
	}
	if err := capture.Close(); err != nil {
		return replay.Envelope{}, err
	}
	return replay.LoadEnvelope(path)
}

func deterministicReplayTelemetry(logicalClock uint64, eventID uuid.UUID, timestampUnixNano uint64, auxPID uint32, seedByte byte) (*ingest.VerifiedTelemetry, error) {
	agentID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	var processHash [32]byte
	var fileHash [32]byte
	var networkTuple [16]byte
	var bootSessionID [16]byte
	processHash[0] = seedByte
	fileHash[0] = seedByte + 1
	networkTuple[0] = seedByte + 2
	bootSessionID[0] = byte(logicalClock + 3)

	payload, err := ingest.BuildCanonicalV1(
		logicalClock,
		agentID,
		eventID,
		ingest.EventTypeCodeDecept,
		auxPID,
		processHash,
		fileHash,
		networkTuple,
		timestampUnixNano,
		bootSessionID,
	)
	if err != nil {
		return nil, err
	}
	return &ingest.VerifiedTelemetry{
		Payload:        payload[:],
		AgentSignature: bytes.Repeat([]byte{seedByte}, 64),
		AgentIDStr:     agentID.String(),
		EventType:      "DECEPTION_EVENT",
		TimestampUnix:  float64(timestampUnixNano) / float64(time.Second),
		LogicalClock:   int64(logicalClock),
		DroppedCount:   uint64(seedByte % 4),
	}, nil
}

func deterministicTelemetry(agentID string) (*ingest.VerifiedTelemetry, error) {
	parsedAgentID, err := uuid.Parse(agentID)
	if err != nil {
		return nil, err
	}
	eventID := uuid.New()
	var processHash [32]byte
	var fileHash [32]byte
	var networkTuple [16]byte
	var bootSessionID [16]byte
	processHash[0] = 0x11
	fileHash[0] = 0x22
	networkTuple[0] = 0x33
	bootSessionID[0] = 0x44
	payload, err := ingest.BuildCanonicalV1(
		42,
		parsedAgentID,
		eventID,
		ingest.EventTypeCodeProcess,
		4242,
		processHash,
		fileHash,
		networkTuple,
		1_700_000_000_000_000_000,
		bootSessionID,
	)
	if err != nil {
		return nil, err
	}
	return &ingest.VerifiedTelemetry{
		Payload:        payload[:],
		AgentSignature: bytes.Repeat([]byte{0xAB}, 64),
		AgentIDStr:     agentID,
		EventType:      "PROCESS_EVENT",
		TimestampUnix:  1_700_000_000,
		LogicalClock:   42,
	}, nil
}

func newWORM() (*wormcrypto.WORM, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	return wormcrypto.NewWORM(priv, aesKey)
}

func captureEnv(keys []string) func() {
	type item struct {
		key     string
		value   string
		present bool
	}
	snapshot := make([]item, 0, len(keys))
	for _, key := range keys {
		value, present := os.LookupEnv(key)
		snapshot = append(snapshot, item{key: key, value: value, present: present})
	}
	return func() {
		for _, item := range snapshot {
			if item.present {
				os.Setenv(item.key, item.value)
			} else {
				os.Unsetenv(item.key)
			}
		}
	}
}

func normalizeConfig(cfg Config) Config {
	def := DefaultConfig()
	if cfg.DBMaxConns <= 0 {
		cfg.DBMaxConns = def.DBMaxConns
	}
	return cfg
}

func finalizeResult(result ScenarioResult) ScenarioResult {
	result.Passed = result.FailClosed && result.DataIntegrity && result.ReplayValid && result.DBConsistent && result.NoOrphanRecords
	if result.Scenario == scenarioAIServiceCrash {
		result.Passed = result.Passed && result.NoDetectionOutput && result.NoFallbackHeuristic
	}
	if result.Scenario == scenarioOverflow {
		result.Passed = result.Passed && result.DeterministicDrop && result.NoDeadlock
	}
	return result
}

func formatFailure(result ScenarioResult) string {
	if result.ObservedError != "" {
		return fmt.Sprintf("%s: %s", result.Scenario, result.ObservedError)
	}
	return fmt.Sprintf(
		"%s: pass=%t fail_closed=%t data_integrity=%t replay_valid=%t db_consistent=%t no_orphans=%t",
		result.Scenario,
		result.Passed,
		result.FailClosed,
		result.DataIntegrity,
		result.ReplayValid,
		result.DBConsistent,
		result.NoOrphanRecords,
	)
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("repository root not found")
		}
		dir = parent
	}
}
