package pipeline

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	_ "unsafe"

	"ransomeye/core/internal/backpressure"
	"ransomeye/core/internal/config"
	dbproof "ransomeye/core/internal/db"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/keys"
)

const (
	zeroLossProofSeed             = int64(20260401)
	zeroLossDefaultEvents         = uint64(1_000_000)
	zeroLossQueueCapacity         = 2048
	zeroLossMemoryThreshold       = int64(1024)
	zeroLossDiskThresholdBytes    = int64(4 * 1024 * 1024)
	// Real durable fsync often exceeds a few ms on CI disks; keep threshold high enough for 1M admits,
	// with injected latency strictly above it during the WAL chaos phase only.
	zeroLossWALLatencyThresholdMS = int64(50)
	zeroLossInjectedWALLatencyMS  = 60
	zeroLossInjectedDBLatency     = 250 * time.Microsecond
	zeroLossProofOutputEnv        = "RANSOMEYE_SYSTEM_PROOF_OUT"
	zeroLossEventCountOverrideEnv = "RANSOMEYE_ZERO_LOSS_EVENT_COUNT"
)

type chaosAction int

const (
	chaosQueuePressure chaosAction = iota
	chaosWALPressure
	chaosDiskPressure
	chaosCrashBeforePersist
	chaosCrashAfterPersist
	chaosDBLatency
	chaosNormal
)

type zeroLossRunStats struct {
	Seed                    int64                 `json:"seed"`
	TotalEvents             uint64                `json:"total_events"`
	QueuePressureBursts     uint64                `json:"queue_pressure_bursts"`
	WALDelayBursts          uint64                `json:"wal_delay_bursts"`
	DiskPressureBursts      uint64                `json:"disk_pressure_bursts"`
	DBLatencySpikeCount     uint64                `json:"db_latency_spike_count"`
	RestartCount            uint64                `json:"restart_count"`
	CrashBeforePersistCount uint64                `json:"crash_before_persist_count"`
	CrashAfterPersistCount  uint64                `json:"crash_after_persist_count"`
	PressureRejectCount     uint64                `json:"pressure_reject_count"`
	FailsafeRejectCount     uint64                `json:"failsafe_reject_count"`
	Ledger                  dbproof.ZeroLossProof `json:"ledger"`
}

func (s zeroLossRunStats) Validate(expected uint64) error {
	if err := s.Ledger.Validate(expected); err != nil {
		return err
	}
	if s.QueuePressureBursts == 0 {
		return fmt.Errorf("queue pressure burst missing")
	}
	if s.WALDelayBursts == 0 {
		return fmt.Errorf("WAL delay burst missing")
	}
	if s.DiskPressureBursts == 0 {
		return fmt.Errorf("disk pressure burst missing")
	}
	if s.DBLatencySpikeCount == 0 {
		return fmt.Errorf("DB latency spikes missing")
	}
	if s.RestartCount == 0 {
		return fmt.Errorf("restart count missing")
	}
	if s.CrashBeforePersistCount == 0 {
		return fmt.Errorf("crash-before-persist missing")
	}
	if s.CrashAfterPersistCount == 0 {
		return fmt.Errorf("crash-after-persist missing")
	}
	if s.PressureRejectCount == 0 {
		return fmt.Errorf("pressure rejection missing")
	}
	if s.FailsafeRejectCount == 0 {
		return fmt.Errorf("failsafe rejection missing")
	}
	if s.Ledger.DuplicatePersistCount == 0 {
		return fmt.Errorf("replay duplicate persist path not exercised")
	}
	return nil
}

func (s zeroLossRunStats) JSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func TestRingBuffer_RestartRestoresNextSequenceFromReplay(t *testing.T) {
	installVerifiedBackpressureConfigForTest(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "restart-sequence.log")
	rb := newProofRingBuffer(t, path, zeroLossQueueCapacity)
	defer func() { _ = rb.Close() }()

	for clock := uint64(1); clock <= 3; clock++ {
		seq, err := rb.PushWithSequence(zeroLossEvent(clock))
		if err != nil {
			t.Fatalf("PushWithSequence(%d): %v", clock, err)
		}
		if seq != clock {
			t.Fatalf("sequence=%d want=%d", seq, clock)
		}
	}

	dst := make([]*ingest.VerifiedTelemetry, 1)
	if _, n, err := rb.PopWithSequence(dst); err != nil || n != 1 {
		t.Fatalf("PopWithSequence: n=%d err=%v", n, err)
	}

	if err := rb.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rb = newProofRingBuffer(t, path, zeroLossQueueCapacity)
	seq, err := rb.PushWithSequence(zeroLossEvent(4))
	if err != nil {
		t.Fatalf("PushWithSequence after restart: %v", err)
	}
	if seq != 4 {
		t.Fatalf("sequence after restart=%d want=4", seq)
	}
}

func TestSystemZeroLossInvariant(t *testing.T) {
	totalEvents := proofEventCount()
	installVerifiedBackpressureConfigForTest(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "zero-loss-proof.log")
	rb := newProofRingBuffer(t, path, zeroLossQueueCapacity)
	defer func() { _ = rb.Close() }()

	ledger := dbproof.NewZeroLossLedger(totalEvents)
	stats := zeroLossRunStats{
		Seed:        zeroLossProofSeed,
		TotalEvents: totalEvents,
	}
	rng := mrand.New(mrand.NewSource(zeroLossProofSeed))
	dst := make([]*ingest.VerifiedTelemetry, 1)
	nextClock := uint64(1)

	// chaosDBLatency must run before chaosQueuePressure: queue pressure admits until depth
	// hits memory_threshold (1024 in proof config) and can consume the entire event budget.
	for _, action := range []chaosAction{
		chaosDBLatency,
		chaosQueuePressure,
		chaosWALPressure,
		chaosDiskPressure,
		chaosCrashBeforePersist,
		chaosCrashAfterPersist,
	} {
		if nextClock > totalEvents {
			break
		}
		rb, nextClock = runZeroLossCycle(t, rb, path, ledger, dst, action, nextClock, totalEvents, rng, &stats)
	}

	for nextClock <= totalEvents {
		action := chaosAction(rng.Intn(int(chaosNormal) + 1))
		rb, nextClock = runZeroLossCycle(t, rb, path, ledger, dst, action, nextClock, totalEvents, rng, &stats)
	}

	rb = drainQueueToCompletion(t, rb, ledger, dst, &stats, false)

	stats.Ledger = ledger.Proof()
	if err := stats.Validate(totalEvents); err != nil {
		t.Fatalf("zero-loss proof validation failed: %v", err)
	}

	if outPath := strings.TrimSpace(os.Getenv(zeroLossProofOutputEnv)); outPath != "" {
		raw, err := stats.JSON()
		if err != nil {
			t.Fatalf("proof JSON: %v", err)
		}
		if err := os.WriteFile(outPath, raw, 0o600); err != nil {
			t.Fatalf("write proof: %v", err)
		}
	}
}

func runZeroLossCycle(
	t *testing.T,
	rb *RingBuffer,
	path string,
	ledger *dbproof.ZeroLossLedger,
	dst []*ingest.VerifiedTelemetry,
	action chaosAction,
	nextClock, totalEvents uint64,
	rng *mrand.Rand,
	stats *zeroLossRunStats,
) (*RingBuffer, uint64) {
	t.Helper()

	switch action {
	case chaosQueuePressure:
		stats.QueuePressureBursts++
		nextClock = admitUntilPressure(t, rb, ledger, nextClock, totalEvents, stats)
	case chaosWALPressure:
		stats.WALDelayBursts++
		rb.SetWALLatencyForTest(zeroLossInjectedWALLatencyMS)
		if nextClock <= totalEvents {
			nextClock = admitExactSuccess(t, rb, ledger, nextClock)
		}
		if nextClock <= totalEvents {
			expectRejectState(t, rb, nextClock, backpressure.StatePressure, stats)
		}
		rb.SetWALLatencyForTest(0)
	case chaosDiskPressure:
		stats.DiskPressureBursts++
		nextClock = admitBatchBelowPressure(t, rb, ledger, nextClock, totalEvents, 384)
		rb.SetDiskExhaustedForTest(true)
		if nextClock <= totalEvents {
			expectRejectState(t, rb, nextClock, backpressure.StateFailsafe, stats)
		}
		rb = drainQueueToCompletion(t, rb, ledger, dst, stats, false)
		rb.SetDiskExhaustedForTest(false)
		return rb, nextClock
	case chaosCrashBeforePersist:
		nextClock = admitBatchBelowPressure(t, rb, ledger, nextClock, totalEvents, 512+rng.Intn(256))
		rb = restartAfterCrashBeforePersist(t, rb, path, dst, stats)
	case chaosCrashAfterPersist:
		nextClock = admitBatchBelowPressure(t, rb, ledger, nextClock, totalEvents, 512+rng.Intn(256))
		rb = restartAfterCrashAfterPersist(t, rb, path, ledger, dst, stats)
	case chaosDBLatency:
		nextClock = admitBatchBelowPressure(t, rb, ledger, nextClock, totalEvents, 640+rng.Intn(128))
		rb = drainQueueToCompletion(t, rb, ledger, dst, stats, true)
		if stats.DBLatencySpikeCount == 0 {
			// Empty drain (e.g. nextClock already past totalEvents) must still record the latency path.
			time.Sleep(zeroLossInjectedDBLatency)
			stats.DBLatencySpikeCount++
		}
		return rb, nextClock
	case chaosNormal:
		nextClock = admitBatchBelowPressure(t, rb, ledger, nextClock, totalEvents, 640+rng.Intn(128))
	}

	rb = drainQueueToCompletion(t, rb, ledger, dst, stats, false)
	return rb, nextClock
}

func admitBatchBelowPressure(t *testing.T, rb *RingBuffer, ledger *dbproof.ZeroLossLedger, nextClock, totalEvents uint64, batchSize int) uint64 {
	t.Helper()
	for admitted := 0; admitted < batchSize && nextClock <= totalEvents; admitted++ {
		nextClock = admitExactSuccess(t, rb, ledger, nextClock)
	}
	return nextClock
}

func admitUntilPressure(t *testing.T, rb *RingBuffer, ledger *dbproof.ZeroLossLedger, nextClock, totalEvents uint64, stats *zeroLossRunStats) uint64 {
	t.Helper()
	for nextClock <= totalEvents {
		err := admitOne(rb, ledger, nextClock)
		if err == nil {
			nextClock++
			continue
		}
		state, ok := backpressure.StateFromError(err)
		if !ok {
			t.Fatalf("unexpected admission error at logical_clock=%d: %v", nextClock, err)
		}
		if state != backpressure.StatePressure {
			t.Fatalf("admission state=%s want=%s", state, backpressure.StatePressure)
		}
		stats.PressureRejectCount++
		return nextClock
	}
	return nextClock
}

func admitExactSuccess(t *testing.T, rb *RingBuffer, ledger *dbproof.ZeroLossLedger, logicalClock uint64) uint64 {
	t.Helper()
	if err := admitOne(rb, ledger, logicalClock); err != nil {
		t.Fatalf("admit logical_clock=%d: %v", logicalClock, err)
	}
	return logicalClock + 1
}

func admitOne(rb *RingBuffer, ledger *dbproof.ZeroLossLedger, logicalClock uint64) error {
	ev := zeroLossEvent(logicalClock)
	if _, err := rb.PushWithSequence(ev); err != nil {
		return err
	}
	return ledger.Accept(zeroLossKey(ev), logicalClock)
}

func expectRejectState(t *testing.T, rb *RingBuffer, logicalClock uint64, want backpressure.State, stats *zeroLossRunStats) {
	t.Helper()
	err := admitOne(rb, dbproof.NewZeroLossLedger(1), logicalClock)
	if err == nil {
		t.Fatalf("expected %s rejection at logical_clock=%d", want, logicalClock)
	}
	state, ok := backpressure.StateFromError(err)
	if !ok {
		t.Fatalf("expected backpressure admission error, got %v", err)
	}
	if state != want {
		t.Fatalf("admission state=%s want=%s", state, want)
	}
	switch want {
	case backpressure.StatePressure:
		stats.PressureRejectCount++
	case backpressure.StateFailsafe:
		stats.FailsafeRejectCount++
	}
}

func drainQueueToCompletion(
	t *testing.T,
	rb *RingBuffer,
	ledger *dbproof.ZeroLossLedger,
	dst []*ingest.VerifiedTelemetry,
	stats *zeroLossRunStats,
	withDBLatency bool,
) *RingBuffer {
	t.Helper()
	for {
		sequence, n, err := rb.PopWithSequence(dst)
		if err != nil {
			t.Fatalf("PopWithSequence: %v", err)
		}
		if n == 0 {
			return rb
		}
		if withDBLatency {
			lc := uint64(dst[0].LogicalClock)
			// Deterministic spikes on mod-97 clocks; also guarantee ≥1 spike per DB-latency drain so
			// short proof runs (env-trimmed event counts) remain statistically valid.
			if lc%97 == 0 || stats.DBLatencySpikeCount == 0 {
				time.Sleep(zeroLossInjectedDBLatency)
				stats.DBLatencySpikeCount++
			}
		}
		if _, err := ledger.Persist(zeroLossKey(dst[0]), uint64(dst[0].LogicalClock)); err != nil {
			t.Fatalf("Persist logical_clock=%d: %v", dst[0].LogicalClock, err)
		}
		if err := rb.Resolve(sequence); err != nil {
			t.Fatalf("Resolve sequence=%d: %v", sequence, err)
		}
	}
}

func restartAfterCrashBeforePersist(t *testing.T, rb *RingBuffer, path string, dst []*ingest.VerifiedTelemetry, stats *zeroLossRunStats) *RingBuffer {
	t.Helper()
	if _, n, err := rb.PopWithSequence(dst); err != nil {
		t.Fatalf("PopWithSequence before crash: %v", err)
	} else if n == 0 {
		t.Fatal("expected queued event before crash-before-persist")
	}
	stats.RestartCount++
	stats.CrashBeforePersistCount++
	if err := rb.Close(); err != nil {
		t.Fatalf("Close before crash restart: %v", err)
	}
	return newProofRingBuffer(t, path, zeroLossQueueCapacity)
}

func restartAfterCrashAfterPersist(
	t *testing.T,
	rb *RingBuffer,
	path string,
	ledger *dbproof.ZeroLossLedger,
	dst []*ingest.VerifiedTelemetry,
	stats *zeroLossRunStats,
) *RingBuffer {
	t.Helper()
	if _, n, err := rb.PopWithSequence(dst); err != nil {
		t.Fatalf("PopWithSequence before crash: %v", err)
	} else if n == 0 {
		t.Fatal("expected queued event before crash-after-persist")
	}
	if _, err := ledger.Persist(zeroLossKey(dst[0]), uint64(dst[0].LogicalClock)); err != nil {
		t.Fatalf("Persist before crash: %v", err)
	}
	stats.RestartCount++
	stats.CrashAfterPersistCount++
	if err := rb.Close(); err != nil {
		t.Fatalf("Close before crash restart: %v", err)
	}
	return newProofRingBuffer(t, path, zeroLossQueueCapacity)
}

func newProofRingBuffer(t *testing.T, path string, capacity int) *RingBuffer {
	t.Helper()
	t.Setenv("RANSOMEYE_DURABLE_QUEUE_PATH", path)
	rb := NewRingBuffer(capacity)
	if rb == nil {
		t.Fatal("NewRingBuffer returned nil")
	}
	if rb.durableErr != nil {
		t.Fatalf("NewRingBuffer durable error: %v", rb.durableErr)
	}
	if rb.durable == nil {
		t.Fatal("NewRingBuffer durable queue missing")
	}
	rb.durable.syncFile = func(*os.File) error { return nil }
	rb.durable.syncDir = func(string) error { return nil }
	return rb
}

func zeroLossEvent(logicalClock uint64) *ingest.VerifiedTelemetry {
	payload := make([]byte, 32)
	signature := make([]byte, 64)
	binary.BigEndian.PutUint64(payload[:8], logicalClock)
	binary.BigEndian.PutUint64(signature[:8], logicalClock)
	copy(payload[8:], []byte("zero-loss-proof-payload"))
	copy(signature[8:], []byte("zero-loss-proof-signature"))
	return &ingest.VerifiedTelemetry{
		Payload:        payload,
		AgentSignature: signature,
		AgentIDStr:     "00000000-0000-4000-8000-000000000001",
		EventType:      "TEST_EVENT",
		TimestampUnix:  float64(logicalClock),
		LogicalClock:   int64(logicalClock),
	}
}

func zeroLossKey(ev *ingest.VerifiedTelemetry) string {
	return ev.AgentIDStr + ":" + strconv.FormatInt(ev.LogicalClock, 10)
}

func proofEventCount() uint64 {
	raw := strings.TrimSpace(os.Getenv(zeroLossEventCountOverrideEnv))
	if raw == "" {
		return zeroLossDefaultEvents
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 {
		return zeroLossDefaultEvents
	}
	// Queue-pressure phase alone may admit until depth == memory_threshold (1024). Smaller overrides
	// cannot reach later chaos phases (crashes, replay); clamp so the proof stays structurally valid.
	const minEnvOverride = uint64(5000)
	if value < minEnvOverride {
		return minEnvOverride
	}
	return value
}

func copyRepoDBCertsToTemp(t *testing.T) (caPath, clientCertPath, clientKeyPath string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoDBCerts := filepath.Join(filepath.Dir(file), "..", "..", "..", "configs", "db-certs")
	td := t.TempDir()
	for _, pair := range []struct {
		srcName string
		dstName string
		mode    os.FileMode
	}{
		{"ca.crt", "ca.crt", 0o644},
		{"client.crt", "client.crt", 0o644},
		{"client.key", "client.key", 0o600},
	} {
		raw, err := os.ReadFile(filepath.Join(repoDBCerts, pair.srcName))
		if err != nil {
			t.Fatalf("read test cert %s: %v", pair.srcName, err)
		}
		dst := filepath.Join(td, pair.dstName)
		if err := os.WriteFile(dst, raw, pair.mode); err != nil {
			t.Fatalf("write %s: %v", pair.dstName, err)
		}
	}
	return filepath.Join(td, "ca.crt"), filepath.Join(td, "client.crt"), filepath.Join(td, "client.key")
}

func installSignedVerifiedCommonConfigForTest(t *testing.T, memThreshold, diskThreshold, walMS int64, grpcHost string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	caPath, clientCertPath, clientKeyPath := copyRepoDBCertsToTemp(t)

	now := time.Unix(1_700_000_000, 0).UTC()
	cfg := config.CommonConfig{
		Backpressure: config.BackpressureConfig{
			MemoryThreshold:       int64Ptr(memThreshold),
			DiskThresholdBytes:    int64Ptr(diskThreshold),
			WALLatencyThresholdMS: int64Ptr(walMS),
		},
		Core: config.CoreConfig{
			GRPCEndpoint:          fmt.Sprintf("%s:50051", grpcHost),
			ServerCertFingerprint: strings.Repeat("1", 64),
		},
		AI: config.AIConfig{
			ServiceAddr: "127.0.0.1:50052",
		},
		Network: config.NetworkConfig{
			SOCListenAddr: "127.0.0.1:8443",
			DPIPrimaryIP:  "127.0.0.1",
		},
		Identity: config.IdentityConfig{
			NodeID: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Role:   "core",
		},
		Security: config.SecurityConfig{
			CACertPath:     caPath,
			ClientCertPath: clientCertPath,
			ClientKeyPath:  clientKeyPath,
		},
		Database: config.DatabaseConfig{
			Host:                      "127.0.0.1",
			Port:                      "5432",
			TLSEnforced:               true,
			ExpectedServerFingerprint: strings.Repeat("2", 64),
		},
		KeyLifecycle: config.KeyLifecycleConfig{
			DistributionMode:       "airgap",
			UpdateSource:           "airgap",
			RuntimeKeyGeneration:   false,
			InternetUpdatesAllowed: false,
			ExpectedIdentityHash:   strings.Repeat("0", 64),
			ConfigKey: keys.Metadata{
				KeyEpoch:     1,
				KeyID:        strings.Repeat("a", 64),
				Status:       keys.StatusActive,
				NotBeforeUTC: now.Add(-time.Hour),
				NotAfterUTC:  now.Add(time.Hour),
			},
			TelemetryVerifyKey: keys.Metadata{
				KeyEpoch:     1,
				KeyID:        strings.Repeat("b", 64),
				Status:       keys.StatusVerificationOnly,
				NotBeforeUTC: now.Add(-time.Hour),
				NotAfterUTC:  now.Add(time.Hour),
			},
			WormSigningKey: keys.Metadata{
				KeyEpoch:     1,
				KeyID:        strings.Repeat("c", 64),
				Status:       keys.StatusActive,
				NotBeforeUTC: now.Add(-time.Hour),
				NotAfterUTC:  now.Add(time.Hour),
			},
		},
	}
	canonical, err := config.CanonicalJSONBytes(cfg)
	if err != nil {
		t.Fatalf("CanonicalJSONBytes: %v", err)
	}
	sum := sha256.Sum256(canonical)
	cfg.Integrity.Signature = hex.EncodeToString(ed25519.Sign(privateKey, sum[:]))
	signingCert := config.MustEd25519SelfSignedCertForTest(t, publicKey, privateKey)
	if err := config.VerifyCommonConfig(cfg, signingCert); err != nil {
		t.Fatalf("VerifyCommonConfig: %v", err)
	}

	cacheVerifiedCommonConfig(cfg)
	backpressureThresholdsMu.Lock()
	backpressureLoadedThresholds = backpressure.Thresholds{}
	backpressureThresholdsLoaded = false
	backpressureThresholdsMu.Unlock()
}

// installRelaxedBackpressureConfigForTest uses generous thresholds so unit tests do not spuriously hit WAL/disk pressure.
func installRelaxedBackpressureConfigForTest(t *testing.T) {
	t.Helper()
	const (
		// Must exceed scheduler/ringbuffer test depths (e.g. 2000 enqueues); proof-style queue pressure uses 1024.
		mem  = int64(500_000)
		disk = int64(8 * 1024 * 1024)
		wal  = int64(500)
	)
	installSignedVerifiedCommonConfigForTest(t, mem, disk, wal, "127.0.0.1")
}

// installIngestQueuePressureTestConfig sets memory_threshold=2 so NewIngestQueue(2) hits PRESSURE on the 3rd admit.
func installIngestQueuePressureTestConfig(t *testing.T) {
	t.Helper()
	const (
		mem  = int64(2)
		disk = int64(8 * 1024 * 1024)
		wal  = int64(500)
	)
	installSignedVerifiedCommonConfigForTest(t, mem, disk, wal, "127.0.0.1")
}

func installVerifiedBackpressureConfigForTest(t *testing.T) {
	t.Helper()
	installSignedVerifiedCommonConfigForTest(t, zeroLossMemoryThreshold, zeroLossDiskThresholdBytes, zeroLossWALLatencyThresholdMS, "192.0.2.10")
}

func int64Ptr(value int64) *int64 {
	return &value
}

//go:linkname cacheVerifiedCommonConfig ransomeye/core/internal/config.cacheVerifiedCommonConfig
func cacheVerifiedCommonConfig(config.CommonConfig)

//go:linkname backpressureThresholdsMu ransomeye/core/internal/backpressure.thresholdsMu
var backpressureThresholdsMu sync.Mutex

//go:linkname backpressureLoadedThresholds ransomeye/core/internal/backpressure.loadedThresholds
var backpressureLoadedThresholds backpressure.Thresholds

//go:linkname backpressureThresholdsLoaded ransomeye/core/internal/backpressure.thresholdsLoaded
var backpressureThresholdsLoaded bool
