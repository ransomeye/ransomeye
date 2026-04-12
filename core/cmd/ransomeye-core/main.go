package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"ransomeye/core/internal/ai"
	"ransomeye/core/internal/compliance"
	coreconfig "ransomeye/core/internal/config"
	worm "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/events"
	"ransomeye/core/internal/forensics"
	"ransomeye/core/internal/gateway"
	"ransomeye/core/internal/health"
	"ransomeye/core/internal/identity"
	"ransomeye/core/internal/integrity"
	"ransomeye/core/internal/intel"
	"ransomeye/core/internal/metrics"
	"ransomeye/core/internal/netcfg"
	"ransomeye/core/internal/pipeline"
	"ransomeye/core/internal/policy"
	"ransomeye/core/internal/replay"
	"ransomeye/core/internal/security"
	"ransomeye/core/internal/sine"
	"ransomeye/core/internal/soc"
	"ransomeye/core/internal/storage"

	"ransomeye/core/internal/contracts"
	redb "ransomeye/core/internal/db"
	"ransomeye/core/internal/dbbootstrap"

	"net"

	"google.golang.org/grpc"
	internalaipb "ransomeye/proto/internalai"
	_ "ransomeye/proto/ransomeyepb" // ensure proto registration
)

const (
	requiredMigrationsDir = "/opt/ransomeye/core/migrations/"
)

func main() {
	coreconfig.MustLoadVerifiedCommonConfig()
	bootstrapCfg := coreconfig.LoadBootstrapConfig()
	devMode := os.Getenv("RANSOMEYE_DEV_MODE") == "true"

	// ======================================================
	// PHASE 0 — COMPLIANCE HARD GATE (FAIL-CLOSED)
	// ======================================================
	if !devMode {
		if err := compliance.ValidatePRDIntegrity(); err != nil {
			log.Fatalf("PRD integrity failure: %v", err)
		}
	} else {
		log.Printf("[DEV MODE] skipping PRD integrity gate")
	}
	if err := compliance.AssertAll(); err != nil {
		log.Fatalf("%v", err)
	}

	// 1. OS Signals — Root Context Creation
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 2. Load config (fail-closed)
	cfg := mustLoadConfig(bootstrapCfg)

	// 3. Init crypto identity (fail-closed inside)
	signingKey := worm.MustLoadSigningKey()
	aesKey := cfg.masterKey
	wormCrypto, err := worm.NewWORM(signingKey, aesKey)
	if err != nil {
		log.Fatalf("[FATAL] WORM crypto init failed: %v", err)
	}

	// 4. Init validator (fail-closed if missing)
	validator := gateway.NewValidator()
	if validator == nil {
		log.Fatal("[FATAL] validator init failed")
	}

	// 5. Init pipeline (scheduler + buffers) + state managers
	sessions := identity.NewSessionManager()
	// PipelineHealthy defaults true until worker/sweeper observe failure — zero value shadowed /health vs /shadow mismatch.
	health.SetSystemState(&health.SystemState{PipelineHealthy: true})

	// 6. Event bus created early; audit/worm/soc subscribers registered after pool (see below).
	bus := events.NewInMemoryBus(1024) // PRD-00 §11.13: 1024-depth event queue
	bus.SubscribeEnforcementEvent(health.HandleEnforcementEvent)

	// 7. Migrations + validation (application role only). Roles/database are installer-provisioned (PRD-01 DB-BOOTSTRAP-01).
	if err := redb.ValidateInboundPostgresDSN(cfg.postgresDSN); err != nil {
		log.Fatalf("[FATAL] postgres DSN validation: %v", err)
	}
	os.Setenv("POSTGRES_DSN", cfg.postgresDSN)
	migrationsDir := mustEnforceCoreMigrationPath()
	if !devMode {
		bctx, bcancel := context.WithTimeout(ctx, 30*time.Minute)
		if err := dbbootstrap.RunMigrationsAndValidate(bctx, dbbootstrap.Options{
			MigrationsDir:                     migrationsDir,
			ExpectedPostgresServerFingerprint: strings.TrimSpace(cfg.commonCfg.Database.ExpectedServerFingerprint),
		}); err != nil {
			bcancel()
			log.Fatalf("[FATAL] database migrations: %v", err)
		}
		bcancel()
	} else {
		log.Printf("[DEV MODE] skipping migration runner against existing local database")
	}

	// 8. Init DB pool + stdlib (single trust entrypoints in ransomeye/core/internal/db)
	appCfg, err := dbbootstrap.EffectiveAppConfig()
	if err != nil {
		log.Fatalf("[FATAL] postgres app config: %v", err)
	}
	appCfg.ExpectedPostgresServerFingerprint = strings.TrimSpace(cfg.commonCfg.Database.ExpectedServerFingerprint)
	pool, err := redb.NewPool(ctx, appCfg)
	if err != nil {
		log.Fatalf("[FATAL] pg pool: %v", err)
	}
	defer pool.Close()
	log.Printf("[SECURITY] PostgreSQL TLS 1.3 mTLS channel established (pgx enforced)")
	sqlDB := stdlib.OpenDBFromPool(pool)
	pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
	if err := sqlDB.PingContext(pctx); err != nil {
		pcancel()
		_ = sqlDB.Close()
		log.Fatalf("[FATAL] stdlib db ping: %v", err)
	}
	pcancel()
	defer sqlDB.Close()
	log.Printf("[DB] All connections routed via trust gate: VERIFIED")

	primeCtx, primeCancel := context.WithTimeout(ctx, 5*time.Second)
	health.PrimePlaneReadinessGates(primeCtx, pool)
	primeCancel()

	// ======================================================
	// PHASE 0B — RUNTIME COMPLIANCE (FAIL-CLOSED)
	// ======================================================

	// ======================================================
	// PHASE 5 — WORM MIGRATION PATH + IMMUTABILITY VALIDATION (FAIL-CLOSED)
	// ======================================================
	if !migrationExists(migrationsDir, 5) {
		log.Fatalf("[FATAL] Missing migration (005)")
	}
	if !migrationExists(migrationsDir, 6) {
		log.Fatalf("[FATAL] Missing WORM immutability migration (006)")
	}

	if err := compliance.AssertNoForbiddenTables(sqlDB); err != nil {
		log.Fatalf("%v", err)
	}
	if err := compliance.AssertPostgresTLS(sqlDB); err != nil {
		if !devMode {
			log.Fatalf("%v", err)
		}
		log.Printf("[DEV MODE] skipping SQL-level PostgreSQL TLS gate: %v", err)
	}
	if err := compliance.AssertLoopbackBindings(); err != nil {
		log.Fatalf("%v", err)
	}
	if err := compliance.AssertNoIPv6Bindings(); err != nil {
		log.Fatalf("%v", err)
	}
	applyAirGapStartupGates(devMode)

	validateWORMTriggers(sqlDB)

	// Audit and health receive enforcement events; SOC subscribes inside NewServer for all events.
	bus.SubscribeEnforcementEvent(func(e contracts.EnforcementEvent) { auditEnforcementEvent(ctx, pool, e) })
	bus.Run()

	enforcementWriter := forensics.NewEnforcementEventWriter(wormCrypto)
	dispatcher := enforcement.NewActionDispatcher(bus, enforcementWriter)

	// Phase 6.5: synchronous signed manifest gate before optional AI dial; periodic loop matches installer manifest verification.
	labSkipIntegrity := strings.TrimSpace(os.Getenv("RANSOMEYE_LAB_SKIP_RUNTIME_INTEGRITY")) == "true"
	if labSkipIntegrity {
		log.Printf("[LAB] RANSOMEYE_LAB_SKIP_RUNTIME_INTEGRITY=true: skipping signed manifest/vendor integrity gate and periodic loop; compliance_bootstrap_ok will stay false until a full install provisions manifest + anchor state")
	} else if err := integrity.RunRuntimeIntegrityCheck(); err != nil {
		if !devMode {
			log.Fatalf("[FATAL] Runtime integrity violation: %v", err)
		}
		log.Printf("[DEV MODE] skipping runtime integrity gate: %v", err)
	} else if devMode {
		log.Printf("[DEV MODE] runtime integrity gate passed")
	}
	if !devMode && !labSkipIntegrity {
		integrity.StartRuntimeIntegrityLoop()
		health.MarkComplianceBootstrapOK()
	} else if devMode {
		log.Printf("[DEV MODE] runtime integrity loop disabled")
	} else if labSkipIntegrity {
		log.Printf("[LAB] runtime integrity loop disabled (lab skip)")
	}

	var aiClient *ai.Client
	if cfg.aiAddr != "" {
		var dialErr error
		for attempt := 0; attempt < 50; attempt++ {
			aiClient, dialErr = ai.Dial(ctx, ai.ClientOptions{Addr: cfg.aiAddr})
			if dialErr == nil {
				break
			}
			if attempt < 49 {
				select {
				case <-ctx.Done():
					log.Fatalf("[FATAL] shutdown while waiting for AI")
				case <-time.After(200 * time.Millisecond):
				}
			}
		}
		if dialErr != nil {
			if !devMode {
				log.Fatalf("[FATAL] AI client dial failed: %v", dialErr)
			}
			log.Printf("[DEV MODE] AI client unavailable; continuing without AI sidecar: %v", dialErr)
			aiClient = nil
		} else {
			defer func() { _ = aiClient.Close() }()
			health.MarkAIHealthy()
		}
	} else {
		log.Printf("[INFO] RANSOMEYE_AI_ADDR unset; AI evaluation sidecar disabled")
	}

	var sineClient *sine.Client
	if cfg.sineAddr != "" {
		var sineDialErr error
		for attempt := 0; attempt < 50; attempt++ {
			sineClient, sineDialErr = sine.Dial(cfg.sineAddr)
			if sineDialErr == nil {
				break
			}
			if attempt < 49 {
				select {
				case <-ctx.Done():
					log.Fatalf("[FATAL] shutdown while waiting for SINE")
				case <-time.After(200 * time.Millisecond):
				}
			}
		}
		if sineDialErr != nil {
			if !devMode {
				log.Fatalf("[FATAL] SINE gRPC client dial failed: %v", sineDialErr)
			}
			log.Printf("[DEV MODE] SINE client unavailable; continuing without SINE sidecar: %v", sineDialErr)
			sineClient = nil
		} else {
			defer func() { _ = sineClient.Close() }()
			health.MarkSINEHealthy()
		}
	} else {
		log.Printf("[INFO] RANSOMEYE_SINE_ADDR unset; SINE sidecar disabled")
	}

	// Avoid Go's typed-nil interface pitfall: (*sine.Client)(nil) assigned to pipeline.SINEFilter is non-nil
	// and would make the worker call Filter and get SINE_UNAVAILABLE even when SINE is disabled.
	var sineFilter pipeline.SINEFilter
	if sineClient != nil {
		sineFilter = sineClient
	}

	blockEvalPolicy := policy.NewPolicyEvaluator(health.BlockEvalStateProvider())
	aiRouter := ai.NewRouter(aiClient, dispatcher, 1024, blockEvalPolicy)
	aiRouter.SetTenantConfigAEC(false)

	// RANSOMEYE_ENFORCEMENT_E2E_PROBE=true: lab-only path to prove policy→dispatcher→ReceiveActions
	// with the built-in deterministic model (fused score ~0.5; default ScoreThreshold 1.0 never yields "malicious").
	// Does not relax TLS/ingest gates; requires explicit operator env on the host.
	const enforcementProbeScoreThreshold = 0.35
	enforcementE2EProbe := strings.TrimSpace(os.Getenv("RANSOMEYE_ENFORCEMENT_E2E_PROBE")) == "true"
	runtimeModel, err := ai.LoadRuntimeModel()
	if err != nil {
		if devMode {
			log.Printf("[DEV MODE] using built-in fallback detector model: %v", err)
			runtimeModel = devRuntimeModel()
		} else if strings.TrimSpace(os.Getenv("RANSOMEYE_AI_ADDR")) == "" {
			log.Printf("[INFO] RANSOMEYE_AI_ADDR unset; using built-in deterministic detector model (Mishka Phase-1 slice without external AI sidecar): %v", err)
			runtimeModel = devRuntimeModel()
		} else {
			log.Fatalf("[FATAL] deterministic detector model load failed: %v", err)
		}
	}
	if enforcementE2EProbe {
		runtimeModel.ScoreThreshold = enforcementProbeScoreThreshold
		runtimeModel.SineMinThreshold = 0
		log.Printf("[LAB] RANSOMEYE_ENFORCEMENT_E2E_PROBE: detector ScoreThreshold=%v SineMinThreshold=0 (policy-driven dispatch proof / operator harness)", runtimeModel.ScoreThreshold)
	}
	policyConfig := policy.DefaultEnforcementPolicy()
	autoEnforceReady := cfg.AECAutoEnforce
	if enforcementE2EProbe {
		policyConfig.Mode = policy.ModeAuto
		policyConfig.Threshold = enforcementProbeScoreThreshold
		autoEnforceReady = true
		log.Printf("[LAB] RANSOMEYE_ENFORCEMENT_E2E_PROBE: policy Mode=%s Threshold=%v autoEnforceReady=%v", policyConfig.Mode, policyConfig.Threshold, autoEnforceReady)
	}
	policyEngine := policy.NewEngine(policyConfig, autoEnforceReady)

	workerDetector, err := pipeline.NewDeterministicDetector(runtimeModel)
	if err != nil {
		log.Fatalf("[FATAL] linux worker detector init failed: %v", err)
	}
	workerDetector.SetPolicyEngine(policyEngine)
	dpiDetector, err := pipeline.NewDeterministicDetector(runtimeModel)
	if err != nil {
		log.Fatalf("[FATAL] dpi worker detector init failed: %v", err)
	}
	dpiDetector.SetPolicyEngine(policyEngine)

	// 9. Pipeline (worker pool consuming gateway telemetry)
	scheduler := &pipeline.Scheduler{}

	handlers := gateway.NewHandlers(nil, dispatcher, sessions)
	handlers.SetValidator(validator)
	handlers.SetScheduler(scheduler)
	handlers.SetDBPool(pool)
	handlers.SetPRD13CommitSigner(signingKey, hex.EncodeToString(wormCrypto.PublicKey()), 1)

	// Non-blocking direct fan-out hub: no central queue. SOC must never backpressure ingestion/AI/persistence.
	hub := pipeline.NewHub()

	worker := &pipeline.WorkerPool{
		Scheduler:  scheduler,
		DB:         &storage.DB{Pool: pool},
		Releaser:   handlers,
		WORM:       wormCrypto,
		PRD13CommitKey:      signingKey,
		PRD13CommitKeyID:    hex.EncodeToString(wormCrypto.PublicKey()),
		PRD13CommitKeyEpoch: 1,
		Detector:          workerDetector,
		AIRouter:          aiRouter,
		Enforcer:          dispatcher,
		EnforcementPolicy: blockEvalPolicy,
		SINE:              sineFilter,
		Hub:               hub,
		Workers:           8,
		Source:            "linux_agent",
		SourceType:        "agent",
	}

	dpiScheduler := &pipeline.Scheduler{}
	dpiWorker := &pipeline.WorkerPool{
		Scheduler:  dpiScheduler,
		DB:         &storage.DB{Pool: pool},
		Releaser:   handlers,
		WORM:       wormCrypto,
		PRD13CommitKey:      signingKey,
		PRD13CommitKeyID:    hex.EncodeToString(wormCrypto.PublicKey()),
		PRD13CommitKeyEpoch: 1,
		Detector:          dpiDetector,
		AIRouter:          aiRouter,
		Enforcer:          dispatcher,
		EnforcementPolicy: blockEvalPolicy,
		SINE:              sineFilter,
		Hub:               hub,
		Workers:           2,
		Source:            "dpi_probe",
		SourceType:        "dpi",
	}

	replayCapture, err := replay.NewInputCaptureFromEnv()
	if err != nil {
		log.Fatalf("[FATAL] replay input capture init failed: %v", err)
	}
	replayBaselineStore, err := replay.NewBaselineStoreFromEnv(pool)
	if err != nil {
		log.Fatalf("[FATAL] replay baseline store init failed: %v", err)
	}
	if replayCapture != nil {
		defer func() {
			if closeErr := replayCapture.Close(); closeErr != nil {
				log.Printf("[WARN] replay input capture close failed: %v", closeErr)
			}
		}()
	}
	schedulerEnqueuer := replay.NewCapturingEnqueuerWithBaseline(scheduler, replayCapture, replayBaselineStore)
	dpiSchedulerEnqueuer := replay.NewCapturingEnqueuerWithBaseline(dpiScheduler, replayCapture, replayBaselineStore)
	handlers.SetSchedulerEnqueuer(schedulerEnqueuer)

	var dpiIngest *gateway.DPIIngest
	var dpiControl *gateway.DPIControlLoop
	if cfg.dpiPlaneEnabled {
		var errDPI error
		dpiIngest, errDPI = gateway.NewDPIIngest(gateway.DPIIngestOptions{
			SocketPath:    cfg.dpiSocketPath,
			PublicKeyPath: cfg.dpiPublicKeyPath,
			AgentID:       cfg.dpiAgentID,
			TenantID:      cfg.dpiTenantID,
			Hostname:      cfg.dpiHostname,
			PrimaryIP:     cfg.dpiPrimaryIP,
			DBPool:        pool,
			Scheduler:     dpiSchedulerEnqueuer,
		})
		if errDPI != nil {
			log.Fatalf("[FATAL] DPI ingress init failed: %v", errDPI)
		}
		dpiControl, errDPI = gateway.NewDPIControlLoop(gateway.DPIControlOptions{
			Scheduler: dpiScheduler,
		})
		if errDPI != nil {
			log.Fatalf("[FATAL] DPI control loop init failed: %v", errDPI)
		}
	} else {
		log.Printf("[INFO] DPI plane disabled (set RANSOMEYE_DPI_PUBLIC_KEY_PATH, RANSOMEYE_DPI_AGENT_ID, RANSOMEYE_DPI_TENANT_ID to enable)")
	}

	// 8. gRPC Gateway (mTLS server)
	gw, err := gateway.NewServer(gateway.ServerOptions{
		Addr:        cfg.coreAddr,
		TelemetryCh: nil,
		Handlers:    handlers,
	})
	if err != nil {
		log.Fatalf("[FATAL] gRPC gateway init failed: %v", err)
	}

	if gateway.ReplayGuardCommittedSource() {
		rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := handlers.ReloadCommittedReplayGuard(rctx); err != nil {
			cancel()
			log.Fatalf("[FATAL] committed replay_guard recovery failed: %v", err)
		}
		cancel()
	}

	// 9. Intel gRPC server (loopback only; optional when RANSOMEYE_INTEL_ADDR is unset)
	var intelServer *grpc.Server
	var intelLis net.Listener
	if cfg.intelAddr != "" {
		intelColumn := validateIntelSchema(sqlDB)
		intelServer = grpc.NewServer()
		internalaipb.RegisterIntelServiceServer(intelServer, intel.NewIntelServer(sqlDB, intelColumn))
		var errIntel error
		intelLis, errIntel = net.Listen("tcp", cfg.intelAddr)
		if errIntel != nil {
			log.Fatalf("[FATAL] intel server bind failed: %v", errIntel)
		}
	} else {
		log.Printf("[INFO] RANSOMEYE_INTEL_ADDR unset; internal Intel gRPC disabled")
	}

	// 10. SOC backend (loopback only); reads from a hub subscription (decoupled from core).
	socSrv, err := soc.NewServer(soc.ServerOptions{
		Addr:                    cfg.socAddr,
		Events:                  hub.Subscribe(1024),
		EventHub:                hub,
		DBPool:                  pool,
		WORM:                    wormCrypto,
		WORMStoragePath:         strings.TrimSpace(os.Getenv("WORM_STORAGE_PATH")),
		EnforcementDispatcher: dispatcher,
	})
	if err != nil {
		log.Fatalf("[FATAL] soc server init failed: %v", err)
	}

	// WaitGroup: tracks ONLY infinite-loop goroutines (P0 shutdown invariant).
	// Finite-lifetime servers (gw, intelServer, socSrv) are stopped explicitly
	// in the shutdown sequence — they MUST NOT be in the WaitGroup.
	var wg sync.WaitGroup

	// ======================================================
	// REQUIRED STRUCTURE (Strict WaitGroup Accounting)
	// Tracked: aiRouter, worker, health; plus dpiWorker + dpiControl when DPI plane is enabled.
	// ======================================================
	tracked := 3
	if cfg.dpiPlaneEnabled {
		tracked += 2
	}
	wg.Add(tracked)

	// 1. AI Router (infinite loop — tracked)
	go func() {
		defer wg.Done()
		_ = aiRouter.Run(ctx)
	}()

	// 2. Worker Pool (infinite loop — tracked)
	go func() {
		defer wg.Done()
		_ = worker.Run(ctx)
	}()

	// 3. DPI Worker (infinite loop — tracked only when DPI plane enabled)
	if cfg.dpiPlaneEnabled {
		go func() {
			defer wg.Done()
			_ = dpiWorker.Run(ctx)
		}()
	}

	// 4. Health Sweeper (infinite loop — tracked)
	go func() {
		defer wg.Done()
		health.RunSweeper(ctx, sessions, dispatcher, pool) // dispatcher implements contracts.StreamUnregister
	}()

	// 5. DPI Control Loop (infinite loop — tracked only when DPI plane enabled)
	if cfg.dpiPlaneEnabled && dpiControl != nil {
		go func() {
			defer wg.Done()
			_ = dpiControl.Run(ctx)
		}()
	}

	// Drop-rate rotation for PRD-18 alerting (1s / 10s rolling window).
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				metrics.RotateDropRateWindow()
				metrics.RotateBackpressureWindow()
			}
		}
	}()

	// 6. gRPC Gateway (finite — NOT tracked, stopped explicitly)
	go func() {
		_ = gw.Serve(ctx)
	}()

	// 7. Intel Server (finite — NOT tracked, stopped explicitly)
	if intelServer != nil && intelLis != nil {
		go func() {
			_ = intelServer.Serve(intelLis)
		}()
	}

	// 8. SOC Server (finite — NOT tracked, stopped explicitly)
	go func() {
		_ = socSrv.Serve(ctx)
	}()

	// 9. DPI UNIX ingest bridge (finite — NOT tracked, stopped explicitly)
	if dpiIngest != nil {
		go func() {
			_ = dpiIngest.Serve(ctx)
		}()
	}

	// ======================================================
	// SHUTDOWN (Zero Leak Sequence — Strict Order)
	// ======================================================
	<-ctx.Done()
	log.Println("[INFO] Signal received, initiating graceful shutdown")

	// Phase 1 — Cancel context (already done via signal).
	// Phase 2 — Gracefully stop finite-lifetime servers (deterministic order).
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	gw.GracefulStop(shutdownCtx)
	if dpiIngest != nil {
		_ = dpiIngest.Close()
	}
	socSrv.Shutdown(shutdownCtx)
	if intelServer != nil {
		intelServer.GracefulStop()
	}

	// Phase 3 — Wait for infinite-loop goroutines to drain.
	wg.Wait()

	log.Println("[INFO] Shutdown complete")
}

func mustEnforceCoreMigrationPath() string {
	paths := []string{
		strings.TrimSpace(os.Getenv("RANSOMEYE_MIGRATIONS_PATH")),
		strings.TrimSpace(os.Getenv("MIGRATIONS_PATH")),
		strings.TrimSpace(os.Getenv("DB_MIGRATIONS_PATH")),
	}

	seen := make(map[string]struct{}, 3)
	for _, p := range paths {
		if p == "" {
			continue
		}
		seen[p] = struct{}{}
	}
	if len(seen) > 1 {
		log.Fatalf("[FATAL] Multiple migration paths detected; refusing startup")
	}
	for p := range seen {
		if filepath.Clean(p) != filepath.Clean(requiredMigrationsDir) {
			log.Fatalf("[FATAL] Invalid migration path %q (must be %q)", p, requiredMigrationsDir)
		}
	}

	st, err := os.Stat(requiredMigrationsDir)
	if err != nil {
		log.Fatalf("[FATAL] Core migrations path unavailable: %v", err)
	}
	if !st.IsDir() {
		log.Fatalf("[FATAL] Core migrations path is not a directory: %q", requiredMigrationsDir)
	}
	return requiredMigrationsDir
}

func migrationExists(dir string, n int) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	prefix := fmt.Sprintf("%03d_", n)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".sql") {
			return true
		}
	}
	return false
}

func validateWORMTriggers(db *sql.DB) {
	if db == nil {
		log.Fatalf("[FATAL] sql db not initialized")
	}

	rows, err := db.Query(`
		SELECT tgname
		FROM pg_trigger
		WHERE tgrelid = 'telemetry_events'::regclass
		AND tgname IN (
			'worm_no_update_telemetry',
			'worm_no_delete_telemetry'
		)
	`)
	if err != nil {
		log.Fatalf("[FATAL] Failed to validate WORM triggers: %v", err)
	}
	defer rows.Close()

	found := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Fatalf("[FATAL] Trigger scan failed: %v", err)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("[FATAL] Trigger query failed: %v", err)
	}
	for _, r := range []string{"worm_no_update_telemetry", "worm_no_delete_telemetry"} {
		if !found[r] {
			log.Fatalf("[FATAL] Missing WORM trigger: %s", r)
		}
	}

	rows2, err := db.Query(`
		SELECT tgname
		FROM pg_trigger
		WHERE tgrelid = 'worm_evidence'::regclass
		AND tgname IN (
			'worm_no_update_evidence',
			'worm_no_delete_evidence'
		)
	`)
	if err != nil {
		log.Fatalf("[FATAL] Failed to validate WORM triggers: %v", err)
	}
	defer rows2.Close()

	found2 := map[string]bool{}
	for rows2.Next() {
		var name string
		if err := rows2.Scan(&name); err != nil {
			log.Fatalf("[FATAL] Trigger scan failed: %v", err)
		}
		found2[name] = true
	}
	if err := rows2.Err(); err != nil {
		log.Fatalf("[FATAL] Trigger query failed: %v", err)
	}
	for _, r := range []string{"worm_no_update_evidence", "worm_no_delete_evidence"} {
		if !found2[r] {
			log.Fatalf("[FATAL] Missing WORM trigger: %s", r)
		}
	}
}

func validateIntelSchema(db *sql.DB) string {
	if db == nil {
		log.Fatalf("[FATAL] nil db in validateIntelSchema")
	}
	cols := map[string]bool{}
	rows, err := db.Query(`
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public'
		AND table_name = 'intel_indicators'
	`)
	if err != nil {
		log.Fatalf("[FATAL] intel schema read failed: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			log.Fatalf("[FATAL] schema scan failed: %v", err)
		}
		cols[c] = true
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("[FATAL] intel schema query failed: %v", err)
	}
	if !(cols["indicator"] || cols["value"]) {
		log.Fatalf("[FATAL] intel_indicators missing indicator/value column")
	}
	if !cols["confidence"] {
		log.Fatalf("[FATAL] intel_indicators missing confidence column")
	}
	column := "indicator"
	if cols["value"] {
		column = "value"
	}
	return column
}

type runtimeConfig struct {
	postgresDSN      string
	commonCfg        coreconfig.CommonConfig
	masterKey        []byte
	AECAutoEnforce   bool
	coreAddr         string
	aiAddr           string
	sineAddr         string
	socAddr          string
	intelAddr        string
	dpiPlaneEnabled  bool
	dpiSocketPath    string
	dpiPublicKeyPath string
	dpiAgentID       string
	dpiTenantID      string
	dpiHostname      string
	dpiPrimaryIP     string
}

func dpiPlaneEnvComplete() bool {
	return strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_PUBLIC_KEY_PATH")) != "" &&
		strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_AGENT_ID")) != "" &&
		strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_TENANT_ID")) != ""
}

func mustOptionalLoopbackAddr(key string) string {
	addr, err := netcfg.LoadOptionalLoopbackAddr(key)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	return addr
}

func mustLoadConfig(bootstrapCfg coreconfig.BootstrapConfig) runtimeConfig {
	dsn, err := coreconfig.BuildPostgresDSN()
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	dpiPrimary := strings.TrimSpace(bootstrapCfg.DPIPrimaryIP)
	if dpiPrimary == "" {
		dpiPrimary = netcfg.LoopbackHost
	}
	ip := net.ParseIP(dpiPrimary)
	if ip == nil {
		log.Fatalf("[FATAL] network.dpi_primary_ip must be a valid IP")
	}
	primaryIP := ip.String()
	key := mustDecodeMasterKey32(bootstrapCfg.MasterKey)
	commonCfg, err := coreconfig.LoadVerifiedCommonConfig(
		coreconfig.InstalledCommonConfigPath,
		coreconfig.IntermediateCACertPath,
	)
	if err != nil {
		log.Fatalf("[FATAL] signed common config: %v", err)
	}
	if err := coreconfig.RequireRole(commonCfg, "core"); err != nil {
		log.Fatalf("[FATAL] signed common config role: %v", err)
	}
	devMode := os.Getenv("RANSOMEYE_DEV_MODE") == "true"
	certPath, _, err := security.ResolveCoreServerCertPath(devMode)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	if err := security.VerifyCoreServerCertificateAttestation(devMode, certPath, commonCfg.Core.ServerCertFingerprint); err != nil {
		log.Fatalf("[FATAL] core server certificate attestation: %v", err)
	}
	dpiOn := dpiPlaneEnvComplete()
	rc := runtimeConfig{
		postgresDSN:     dsn,
		commonCfg:       commonCfg,
		masterKey:       key,
		AECAutoEnforce:  false,
		coreAddr:        commonCfg.Core.GRPCEndpoint,
		aiAddr:          mustOptionalLoopbackAddr("RANSOMEYE_AI_ADDR"),
		sineAddr:        mustOptionalLoopbackAddr("RANSOMEYE_SINE_ADDR"),
		socAddr:         mustLoopbackAddr("RANSOMEYE_SOC_ADDR", "SOC_ADDR_NOT_SET"),
		intelAddr:       mustOptionalLoopbackAddr("RANSOMEYE_INTEL_ADDR"),
		dpiPlaneEnabled: dpiOn,
		dpiSocketPath:   valueOrDefault("RANSOMEYE_DPI_SOCKET_PATH", "/tmp/ransomeye-dpi.sock"),
		dpiHostname:     defaultHostname(),
		dpiPrimaryIP:    primaryIP,
	}
	if dpiOn {
		rc.dpiPublicKeyPath = strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_PUBLIC_KEY_PATH"))
		rc.dpiAgentID = strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_AGENT_ID"))
		rc.dpiTenantID = strings.TrimSpace(os.Getenv("RANSOMEYE_DPI_TENANT_ID"))
	}
	return rc
}

// applyAirGapStartupGates evaluates PRD-19 / deployment air-gap posture without live network probes.
// RANSOMEYE_AIR_GAP_MODE:
//   - unset or "enforced": fail-closed outbound/resolv checks (unless RANSOMEYE_DISABLE_AIR_GAP_CHECKS=true or DEV skips).
//   - "off": checks skipped; posture "disabled".
//   - "preflight" / "preflight_only": checks run for observability only; never fatal.
func applyAirGapStartupGates(devMode bool) {
	disable := strings.TrimSpace(os.Getenv("RANSOMEYE_DISABLE_AIR_GAP_CHECKS")) == "true"
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RANSOMEYE_AIR_GAP_MODE")))

	if disable {
		health.SetAirGapRuntimeState(health.AirGapBypassedForLab, "RANSOMEYE_DISABLE_AIR_GAP_CHECKS=true")
		log.Printf("[LAB] air-gap resolv/route checks skipped (RANSOMEYE_DISABLE_AIR_GAP_CHECKS=true); posture=%s", health.AirGapPosture())
		return
	}

	switch mode {
	case "off":
		health.SetAirGapRuntimeState(health.AirGapDisabled, "RANSOMEYE_AIR_GAP_MODE=off")
		log.Printf("[INFO] air-gap enforcement disabled (RANSOMEYE_AIR_GAP_MODE=off); not evaluating /etc/resolv.conf or default route")
		return
	case "preflight", "preflight_only":
		if err := compliance.AssertNoOutboundConnectivity(); err != nil {
			health.SetAirGapRuntimeState(health.AirGapConfiguredNotValidated, err.Error())
			log.Printf("[INFO] air-gap preflight: checks failed (non-fatal): %v", err)
		} else {
			health.SetAirGapRuntimeState(health.AirGapValidated, "")
			log.Printf("[INFO] air-gap preflight: resolv.conf + route table checks passed")
		}
		return
	default:
		// enforced (explicit or legacy default)
		if err := compliance.AssertNoOutboundConnectivity(); err != nil {
			if !devMode {
				log.Fatalf("%v", err)
			}
			health.SetAirGapRuntimeState(health.AirGapConfiguredNotValidated, err.Error())
			log.Printf("[DEV MODE] skipping outbound connectivity gate: %v", err)
			return
		}
		health.SetAirGapRuntimeState(health.AirGapValidated, "")
	}
}

func valueOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func defaultHostname() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "ransomeye-dpi-bridge"
	}
	return host
}

func mustLoopbackAddr(key, emptyCode string) string {
	addr, err := netcfg.LoadLoopbackAddr(key, emptyCode)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	return addr
}

func mustDecodeMasterKey32(hexKey string) []byte {
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != 32 {
		log.Fatalf("[FATAL] RANSOMEYE_MASTER_KEY must be 32-byte hex (64 chars)")
	}
	return b
}

func devRuntimeModel() ai.RuntimeModel {
	return ai.RuntimeModel{
		Algorithm:                "logistic_regression",
		VectorLength:             15,
		Weights:                  make([]float64, 15),
		FeatureNames:             []string{"event_type_norm", "time_delta_norm", "process_id_norm", "entropy_score", "burst_score", "chain_depth_norm", "execution_frequency_norm", "privilege_level_norm", "dropped_packets_norm", "window_entropy_mean", "window_burst_mean", "window_process_anomaly_mean", "window_execution_frequency_mean", "window_time_delta_mean", "window_privilege_level_mean"},
		Explainability:           "deterministic_fallback",
		FusionVersion:            "dev",
		FusionWeights:            ai.FusionWeights{ModelPrediction: 1.0},
		MaxTimeDeltaNS:           int64(5 * time.Second),
		SequenceWindowSize:       8,
		ScoreThreshold:           1.0,
		SineMinThreshold:         1.0,
		TemporalBurstThresholdNS: int64(250 * time.Millisecond),
	}
}

// auditEnforcementEvent persists every enforcement event to governance_audit_log (zero loss).
func auditEnforcementEvent(ctx context.Context, pool *pgxpool.Pool, e contracts.EnforcementEvent) {
	if err := storage.LogEnforcementEvent(ctx, pool, e); err != nil {
		log.Printf("[WARN] audit enforcement event failed seq=%d: %v", e.Seq, err)
	}
}
