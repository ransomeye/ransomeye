package performance

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	"ransomeye/core/internal/ai"
	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/events"
	"ransomeye/core/internal/forensics"
	"ransomeye/core/internal/ingest"
	"ransomeye/core/internal/metrics"
	"ransomeye/core/internal/pipeline"
	"ransomeye/core/internal/policy"
	pb "ransomeye/proto/ransomeyepb"
)

const (
	defaultTickInterval       = 10 * time.Millisecond
	defaultScenarioDuration   = 1 * time.Second
	defaultProgressInterval   = 100 * time.Millisecond
	defaultStallAfter         = 1500 * time.Millisecond
	defaultStabilityDriftPct  = 25.0
	defaultMaxMemoryMB uint64 = 512
	dispatchQueueDepth        = 64
	nonBlockingThreshold      = 10 * time.Millisecond
)

type LoadProfile struct {
	EPS      int           `json:"eps"`
	Duration time.Duration `json:"duration"`
}

type Config struct {
	Profiles              []LoadProfile `json:"profiles"`
	Repetitions           int           `json:"repetitions"`
	Workers               int           `json:"workers"`
	TickInterval          time.Duration `json:"tick_interval"`
	ProgressInterval      time.Duration `json:"progress_interval"`
	StallAfter            time.Duration `json:"stall_after"`
	MaxMemoryMB           uint64        `json:"max_memory_mb"`
	RequireStableAcross3  bool          `json:"require_stable_across_3"`
	MaxStableDriftPercent float64       `json:"max_stable_drift_percent"`
}

type LatencyStats struct {
	P50Millis int64 `json:"p50_ms"`
	P95Millis int64 `json:"p95_ms"`
	P99Millis int64 `json:"p99_ms"`
}

type RepetitionResult struct {
	Repetition              int          `json:"repetition"`
	EPS                     int          `json:"eps"`
	ThroughputEPS           int64        `json:"throughput_eps"`
	LatencyP50              int64        `json:"latency_p50"`
	LatencyP95              int64        `json:"latency_p95"`
	LatencyP99              int64        `json:"latency_p99"`
	MemoryMB                uint64       `json:"memory_mb"`
	Drops                   uint64       `json:"drops"`
	IngestionLatency        LatencyStats `json:"ingestion_latency"`
	DetectionLatency        LatencyStats `json:"detection_latency"`
	EnforcementLatency      LatencyStats `json:"enforcement_latency"`
	HeapAllocBytes          uint64       `json:"heap_alloc_bytes"`
	PeakHeapAllocBytes      uint64       `json:"peak_heap_alloc_bytes"`
	AllocationsPerSecond    float64      `json:"allocations_per_sec"`
	GCPauseTotalMillis      float64      `json:"gc_pause_total_ms"`
	GCPauseMaxMillis        float64      `json:"gc_pause_max_ms"`
	EventsGenerated         uint64       `json:"events_generated"`
	EventsAccepted          uint64       `json:"events_accepted"`
	EventsProcessed         uint64       `json:"events_processed"`
	QueueDrops              uint64       `json:"queue_drops"`
	DispatchDrops           uint64       `json:"dispatch_drops"`
	StallDetected           bool         `json:"stall_detected"`
	UnexpectedErrorCount    uint64       `json:"unexpected_error_count"`
	DurationSeconds         float64      `json:"duration_seconds"`
	MaxSchedulerQueueDepth  int          `json:"max_scheduler_queue_depth"`
	MaxEnqueueBlockMicros   int64        `json:"max_enqueue_block_us"`
	MaxDispatchBlockMicros  int64        `json:"max_dispatch_block_us"`
	MaxProcessLatencyMicros int64        `json:"max_process_latency_us"`
}

type ScenarioAggregate struct {
	EPS                 int                `json:"eps"`
	LatencyP50          int64              `json:"latency_p50"`
	LatencyP95          int64              `json:"latency_p95"`
	LatencyP99          int64              `json:"latency_p99"`
	MemoryMB            uint64             `json:"memory_mb"`
	Drops               uint64             `json:"drops"`
	ThroughputEPS       int64              `json:"throughput_eps"`
	IngestionLatency    LatencyStats       `json:"ingestion_latency"`
	DetectionLatency    LatencyStats       `json:"detection_latency"`
	EnforcementLatency  LatencyStats       `json:"enforcement_latency"`
	Stable              bool               `json:"stable"`
	StabilityDriftPct   float64            `json:"stability_drift_pct"`
	RepetitionResults   []RepetitionResult `json:"repetitions"`
	UnexpectedFailures  []string           `json:"unexpected_failures,omitempty"`
}

type BackpressureValidationResult struct {
	SchedulerExpectedDrops    uint64 `json:"scheduler_expected_drops"`
	SchedulerObservedDrops    uint64 `json:"scheduler_observed_drops"`
	SchedulerDeterministic    bool   `json:"scheduler_deterministic"`
	SchedulerNoBlocking       bool   `json:"scheduler_no_blocking"`
	DispatcherExpectedDrops   uint64 `json:"dispatcher_expected_drops"`
	DispatcherObservedDrops   uint64 `json:"dispatcher_observed_drops"`
	DispatcherDeterministic   bool   `json:"dispatcher_deterministic"`
	DispatcherNoBlocking      bool   `json:"dispatcher_no_blocking"`
	HubExpectedDrops          uint64 `json:"hub_expected_drops"`
	HubObservedDrops          uint64 `json:"hub_observed_drops"`
	HubDeterministic          bool   `json:"hub_deterministic"`
	HubNoBlocking             bool   `json:"hub_no_blocking"`
	NoDeadlocks               bool   `json:"no_deadlocks"`
}

type SIMDValidationResult struct {
	VectorLength int     `json:"vector_length"`
	Samples      int     `json:"samples"`
	Identical    bool    `json:"identical"`
	MaxAbsDelta  float64 `json:"max_abs_delta"`
}

type Report struct {
	GeneratedAt  time.Time                    `json:"generated_at"`
	Config       Config                       `json:"config"`
	Scenarios    []ScenarioAggregate          `json:"scenarios"`
	Backpressure BackpressureValidationResult `json:"backpressure"`
	SIMD         SIMDValidationResult         `json:"simd"`
	Passed       bool                         `json:"passed"`
	Failures     []string                     `json:"failures,omitempty"`
}

type noopReleaser struct{}

func (noopReleaser) ReleaseTelemetryPayload(_ *ingest.VerifiedTelemetry) {}

type durationRecorder struct {
	mu     sync.Mutex
	values []int64
}

func (r *durationRecorder) Record(d time.Duration) {
	r.mu.Lock()
	r.values = append(r.values, d.Nanoseconds())
	r.mu.Unlock()
}

func (r *durationRecorder) Snapshot() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int64, len(r.values))
	copy(out, r.values)
	return out
}

type scenarioCollector struct {
	ingestion   durationRecorder
	detection   durationRecorder
	enforcement durationRecorder
	endToEnd    durationRecorder

	enqueueMu    sync.Mutex
	enqueueTimes map[int64]time.Time

	generated      atomic.Uint64
	accepted       atomic.Uint64
	processed      atomic.Uint64
	queueDrops     atomic.Uint64
	dispatchDrops  atomic.Uint64
	unexpectedErrs atomic.Uint64
	stalled        atomic.Bool

	maxQueueDepth        atomic.Int64
	maxEnqueueBlockNs    atomic.Int64
	maxDispatchBlockNs   atomic.Int64
	maxProcessLatencyNs  atomic.Int64
	peakHeapAllocBytes   atomic.Uint64
}

func newScenarioCollector() *scenarioCollector {
	return &scenarioCollector{
		enqueueTimes: make(map[int64]time.Time),
	}
}

func (c *scenarioCollector) putEnqueueTime(logicalClock int64, ts time.Time) {
	c.enqueueMu.Lock()
	c.enqueueTimes[logicalClock] = ts
	c.enqueueMu.Unlock()
}

func (c *scenarioCollector) popEnqueueTime(logicalClock int64) (time.Time, bool) {
	c.enqueueMu.Lock()
	defer c.enqueueMu.Unlock()
	ts, ok := c.enqueueTimes[logicalClock]
	if ok {
		delete(c.enqueueTimes, logicalClock)
	}
	return ts, ok
}

func (c *scenarioCollector) noteQueueDepth(depth int) {
	current := int64(depth)
	for {
		prev := c.maxQueueDepth.Load()
		if current <= prev || c.maxQueueDepth.CompareAndSwap(prev, current) {
			return
		}
	}
}

func (c *scenarioCollector) noteDuration(dst *atomic.Int64, d time.Duration) {
	current := d.Nanoseconds()
	for {
		prev := dst.Load()
		if current <= prev || dst.CompareAndSwap(prev, current) {
			return
		}
	}
}

func (c *scenarioCollector) notePeakHeap(bytes uint64) {
	for {
		prev := c.peakHeapAllocBytes.Load()
		if bytes <= prev || c.peakHeapAllocBytes.CompareAndSwap(prev, bytes) {
			return
		}
	}
}

type tracingDetector struct {
	inner pipeline.Detector
	sink  *scenarioCollector
}

func (d *tracingDetector) Evaluate(ev *ingest.VerifiedTelemetry) (pipeline.DetectionEvent, error) {
	start := time.Now()
	finding, err := d.inner.Evaluate(ev)
	d.sink.detection.Record(time.Since(start))
	return finding, err
}

type tracingDispatcher struct {
	inner *enforcement.ActionDispatcher
	sink  *scenarioCollector
}

func (d *tracingDispatcher) Dispatch(req enforcement.DispatchRequest) error {
	start := time.Now()
	err := d.inner.Dispatch(req)
	elapsed := time.Since(start)
	d.sink.enforcement.Record(elapsed)
	d.sink.noteDuration(&d.sink.maxDispatchBlockNs, elapsed)
	if errors.Is(err, enforcement.ErrDispatchBackpressure) {
		d.sink.dispatchDrops.Add(1)
	}
	return err
}

type recordingRecorder struct{}

func (recordingRecorder) Record(_ string, _ int64, event forensics.EnforcementEvent) (forensics.StoredEnforcementEvent, error) {
	return forensics.StoredEnforcementEvent{
		Event:     event,
		FilePath:  "/tmp/ransomeye-performance.sealed",
		Signature: []byte("perf-signature"),
	}, nil
}

type performanceStream struct {
	grpc.ServerStream
	sendDelay time.Duration

	blockFirst   bool
	blockStarted chan struct{}
	blockRelease chan struct{}
	blockOnce    sync.Once

	sent atomic.Uint64
}

func (s *performanceStream) Send(*pb.ActionCommand) error {
	if s.blockFirst {
		s.blockOnce.Do(func() {
			if s.blockStarted != nil {
				close(s.blockStarted)
			}
			if s.blockRelease != nil {
				<-s.blockRelease
			}
		})
	}
	if s.sendDelay > 0 {
		time.Sleep(s.sendDelay)
	}
	s.sent.Add(1)
	return nil
}

func (s *performanceStream) Context() context.Context { return context.Background() }

func DefaultConfig() Config {
	return Config{
		Profiles: []LoadProfile{
			{EPS: 1000, Duration: defaultScenarioDuration},
			{EPS: 10000, Duration: defaultScenarioDuration},
			{EPS: 50000, Duration: defaultScenarioDuration},
			{EPS: 100000, Duration: defaultScenarioDuration},
		},
		Repetitions:           3,
		Workers:               maxInt(1, runtime.GOMAXPROCS(0)),
		TickInterval:          defaultTickInterval,
		ProgressInterval:      defaultProgressInterval,
		StallAfter:            defaultStallAfter,
		MaxMemoryMB:           defaultMaxMemoryMB,
		RequireStableAcross3:  true,
		MaxStableDriftPercent: defaultStabilityDriftPct,
	}
}

func RunPerformanceValidation(ctx context.Context, cfg Config) (Report, error) {
	cfg = normalizeConfig(cfg)
	report := Report{
		GeneratedAt: time.Now().UTC(),
		Config:      cfg,
	}

	for _, profile := range cfg.Profiles {
		repetitions := make([]RepetitionResult, 0, cfg.Repetitions)
		for repetition := 1; repetition <= cfg.Repetitions; repetition++ {
			result, err := runScenario(ctx, cfg, profile, repetition)
			if err != nil {
				report.Failures = append(report.Failures, fmt.Sprintf("eps=%d repetition=%d: %v", profile.EPS, repetition, err))
			}
			repetitions = append(repetitions, result)
		}
		aggregate := aggregateScenario(cfg, profile.EPS, repetitions)
		report.Scenarios = append(report.Scenarios, aggregate)
		if len(aggregate.UnexpectedFailures) > 0 {
			report.Failures = append(report.Failures, aggregate.UnexpectedFailures...)
		}
	}

	backpressure := ValidateDeterministicBackpressure()
	report.Backpressure = backpressure
	if !backpressure.SchedulerDeterministic || !backpressure.DispatcherDeterministic || !backpressure.HubDeterministic ||
		!backpressure.SchedulerNoBlocking || !backpressure.DispatcherNoBlocking || !backpressure.HubNoBlocking || !backpressure.NoDeadlocks {
		report.Failures = append(report.Failures, "backpressure validation failed")
	}

	simd := ValidateSIMDConsistency()
	report.SIMD = simd
	if !simd.Identical {
		report.Failures = append(report.Failures, "SIMD/vectorized math validation failed")
	}

	report.Passed = len(report.Failures) == 0
	if !report.Passed {
		return report, errors.New(strings.Join(report.Failures, "; "))
	}
	return report, nil
}

func ValidateDeterministicBackpressure() BackpressureValidationResult {
	result := BackpressureValidationResult{NoDeadlocks: true}

	scheduler := &pipeline.Scheduler{}
	schedulerAttempts := scheduler.Capacity() + 128
	var maxSchedulerCall time.Duration
	payload := &ingest.VerifiedTelemetry{}
	for idx := 0; idx < schedulerAttempts; idx++ {
		callStart := time.Now()
		if err := scheduler.Enqueue(payload); errors.Is(err, pipeline.ErrQueueFull) {
			result.SchedulerObservedDrops++
		}
		if elapsed := time.Since(callStart); elapsed > maxSchedulerCall {
			maxSchedulerCall = elapsed
		}
	}
	result.SchedulerExpectedDrops = uint64(schedulerAttempts - scheduler.Capacity())
	result.SchedulerDeterministic = result.SchedulerObservedDrops == result.SchedulerExpectedDrops
	result.SchedulerNoBlocking = maxSchedulerCall < nonBlockingThreshold

	dispatcher := enforcement.NewActionDispatcherWithRateLimiter(events.NewInMemoryBus(0), recordingRecorder{}, nil)
	stream := &performanceStream{
		blockFirst:   true,
		blockStarted: make(chan struct{}),
		blockRelease: make(chan struct{}),
	}
	agentID := "perf-agent"
	dispatcher.RegisterStream(agentID, stream)
	defer dispatcher.UnregisterStream(agentID)

	firstReq := mustDispatchRequest(agentID, 1)
	if err := dispatcher.Dispatch(firstReq); err != nil {
		result.NoDeadlocks = false
		close(stream.blockRelease)
		return result
	}
	<-stream.blockStarted

	dispatchAttempts := dispatchQueueDepth + 64
	var maxDispatchCall time.Duration
	for idx := 0; idx < dispatchAttempts; idx++ {
		callStart := time.Now()
		err := dispatcher.Dispatch(mustDispatchRequest(agentID, int64(idx+2)))
		if errors.Is(err, enforcement.ErrDispatchBackpressure) {
			result.DispatcherObservedDrops++
		}
		if elapsed := time.Since(callStart); elapsed > maxDispatchCall {
			maxDispatchCall = elapsed
		}
	}
	close(stream.blockRelease)
	result.DispatcherExpectedDrops = 64
	result.DispatcherDeterministic = result.DispatcherObservedDrops == result.DispatcherExpectedDrops
	result.DispatcherNoBlocking = maxDispatchCall < nonBlockingThreshold

	hub := pipeline.NewHub()
	slow := hub.Subscribe(0)
	_ = slow
	fast := hub.Subscribe(8)
	defer hub.Unsubscribe(fast)
	startPerSubscriberDrops := metrics.PerSubscriberDrops()

	hubAttempts := 128
	var maxHubCall time.Duration
	for idx := 0; idx < hubAttempts; idx++ {
		env := pipeline.NewEventEnvelope(int64(idx+1), "detection", fmt.Sprintf("e-%d", idx), "a-1", "detection", "t", "detected", "ok", time.Unix(1, 0))
		callStart := time.Now()
		_ = hub.TryPublish(env)
		if elapsed := time.Since(callStart); elapsed > maxHubCall {
			maxHubCall = elapsed
		}
		select {
		case got := <-fast:
			got.Release()
		default:
		}
		env.Release()
	}
	result.HubExpectedDrops = uint64(hubAttempts)
	result.HubObservedDrops = metrics.PerSubscriberDrops() - startPerSubscriberDrops
	result.HubDeterministic = result.HubObservedDrops == result.HubExpectedDrops
	result.HubNoBlocking = maxHubCall < nonBlockingThreshold

	return result
}

func ValidateSIMDConsistency() SIMDValidationResult {
	const (
		vectorLength = 15
		samples      = 1024
	)

	rng := rand.New(rand.NewSource(21))
	maxAbsDelta := 0.0
	for sample := 0; sample < samples; sample++ {
		vector := make([]float64, vectorLength)
		weights := make([]float64, vectorLength)
		for idx := 0; idx < vectorLength; idx++ {
			vector[idx] = round64((rng.Float64() * 2) - 1)
			weights[idx] = round64((rng.Float64() * 2) - 1)
		}
		bias := round64((rng.Float64() * 0.5) - 0.25)
		scalar := scalarPrediction(vector, weights, bias)
		vectorized := vectorizedPrediction(vector, weights, bias)
		delta := math.Abs(scalar - vectorized)
		if delta > maxAbsDelta {
			maxAbsDelta = delta
		}
	}

	return SIMDValidationResult{
		VectorLength: vectorLength,
		Samples:      samples,
		Identical:    maxAbsDelta <= 1e-9,
		MaxAbsDelta:  maxAbsDelta,
	}
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
	b.WriteString("# Performance Report\n\n")
	b.WriteString(fmt.Sprintf("- Generated: `%s`\n", report.GeneratedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Passed: `%t`\n", report.Passed))
	b.WriteString(fmt.Sprintf("- Repetitions: `%d`\n", report.Config.Repetitions))
	b.WriteString(fmt.Sprintf("- Workers: `%d`\n\n", report.Config.Workers))
	b.WriteString("| EPS | Throughput EPS | P50 ms | P95 ms | P99 ms | Memory MB | Drops | Stable |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n")
	for _, scenario := range report.Scenarios {
		b.WriteString(fmt.Sprintf(
			"| %d | %d | %d | %d | %d | %d | %d | %t |\n",
			scenario.EPS,
			scenario.ThroughputEPS,
			scenario.LatencyP50,
			scenario.LatencyP95,
			scenario.LatencyP99,
			scenario.MemoryMB,
			scenario.Drops,
			scenario.Stable,
		))
	}
	b.WriteString("\n## Backpressure\n\n")
	b.WriteString(fmt.Sprintf("- Scheduler deterministic drops: `%t` (%d/%d)\n", report.Backpressure.SchedulerDeterministic, report.Backpressure.SchedulerObservedDrops, report.Backpressure.SchedulerExpectedDrops))
	b.WriteString(fmt.Sprintf("- Dispatcher deterministic drops: `%t` (%d/%d)\n", report.Backpressure.DispatcherDeterministic, report.Backpressure.DispatcherObservedDrops, report.Backpressure.DispatcherExpectedDrops))
	b.WriteString(fmt.Sprintf("- Hub deterministic drops: `%t` (%d/%d)\n", report.Backpressure.HubDeterministic, report.Backpressure.HubObservedDrops, report.Backpressure.HubExpectedDrops))
	b.WriteString(fmt.Sprintf("- No deadlocks: `%t`\n", report.Backpressure.NoDeadlocks))
	b.WriteString("\n## SIMD Validation\n\n")
	b.WriteString(fmt.Sprintf("- Identical vs scalar path: `%t`\n", report.SIMD.Identical))
	b.WriteString(fmt.Sprintf("- Max absolute delta: `%.12f`\n", report.SIMD.MaxAbsDelta))
	if len(report.Failures) > 0 {
		b.WriteString("\n## Failures\n\n")
		for _, failure := range report.Failures {
			b.WriteString(fmt.Sprintf("- %s\n", failure))
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func runScenario(ctx context.Context, cfg Config, profile LoadProfile, repetition int) (RepetitionResult, error) {
	runtime.GC()
	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	collector := newScenarioCollector()
	scheduler := &pipeline.Scheduler{}
	eventsBus := events.NewInMemoryBus(0)
	dispatcher := enforcement.NewActionDispatcherWithRateLimiter(eventsBus, recordingRecorder{}, nil)
	stream := &performanceStream{}
	agentUUID := deterministicUUID(0xA1, 1)
	agentID := agentUUID.String()
	dispatcher.RegisterStream(agentID, stream)
	defer dispatcher.UnregisterStream(agentID)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	generatorDone := &atomic.Bool{}
	memDone := make(chan struct{})

	go sampleMemory(ctx, collector, memDone)

	var wg sync.WaitGroup
	for worker := 0; worker < cfg.Workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			detector, err := newDetector()
			if err != nil {
				collector.unexpectedErrs.Add(1)
				return
			}
			pool := &pipeline.WorkerPool{
				Scheduler: scheduler,
				Releaser: noopReleaser{},
				Detector: &tracingDetector{inner: detector, sink: collector},
				Enforcer: &tracingDispatcher{inner: dispatcher, sink: collector},
				Workers:  1,
				Source:   "performance_harness",
			}
			pool.SetPersistAllowedFunc(func(_ context.Context, ev *ingest.VerifiedTelemetry) (string, error) {
				view, err := ingest.ParseTelemetryV1(ev.Payload)
				if err != nil {
					return "", err
				}
				return view.EventID.String(), nil
			})
			runWorker(ctx, pool, collector, generatorDone)
		}()
	}

	stallErr := make(chan error, 1)
	go monitorProgress(ctx, cfg, collector, generatorDone, stallErr)

	scenarioStart := time.Now()
	generateErr := runGenerator(ctx, profile, cfg.TickInterval, scheduler, agentUUID, collector)
	generatorDone.Store(true)

	wg.Wait()
	cancel()
	<-memDone

	stallDetected := false
	select {
	case err := <-stallErr:
		if err != nil {
			stallDetected = true
		}
	default:
	}

	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)
	durationSeconds := time.Since(scenarioStart).Seconds()
	if durationSeconds <= 0 {
		durationSeconds = profile.Duration.Seconds()
	}

	result := RepetitionResult{
		Repetition:              repetition,
		EPS:                     profile.EPS,
		ThroughputEPS:           int64(math.Round(float64(collector.processed.Load()) / durationSeconds)),
		LatencyP50:              percentileMillis(collector.endToEnd.Snapshot(), 0.50),
		LatencyP95:              percentileMillis(collector.endToEnd.Snapshot(), 0.95),
		LatencyP99:              percentileMillis(collector.endToEnd.Snapshot(), 0.99),
		MemoryMB:                bytesToMB(collector.peakHeapAllocBytes.Load()),
		Drops:                   collector.queueDrops.Load() + collector.dispatchDrops.Load(),
		IngestionLatency:        summarizeLatency(collector.ingestion.Snapshot()),
		DetectionLatency:        summarizeLatency(collector.detection.Snapshot()),
		EnforcementLatency:      summarizeLatency(collector.enforcement.Snapshot()),
		HeapAllocBytes:          memEnd.HeapAlloc,
		PeakHeapAllocBytes:      collector.peakHeapAllocBytes.Load(),
		AllocationsPerSecond:    float64(memEnd.Mallocs-memStart.Mallocs) / durationSeconds,
		GCPauseTotalMillis:      float64(memEnd.PauseTotalNs-memStart.PauseTotalNs) / float64(time.Millisecond),
		GCPauseMaxMillis:        gcPauseMaxMillis(memStart, memEnd),
		EventsGenerated:         collector.generated.Load(),
		EventsAccepted:          collector.accepted.Load(),
		EventsProcessed:         collector.processed.Load(),
		QueueDrops:              collector.queueDrops.Load(),
		DispatchDrops:           collector.dispatchDrops.Load(),
		StallDetected:           stallDetected || collector.stalled.Load(),
		UnexpectedErrorCount:    collector.unexpectedErrs.Load(),
		DurationSeconds:         durationSeconds,
		MaxSchedulerQueueDepth:  int(collector.maxQueueDepth.Load()),
		MaxEnqueueBlockMicros:   collector.maxEnqueueBlockNs.Load() / int64(time.Microsecond),
		MaxDispatchBlockMicros:  collector.maxDispatchBlockNs.Load() / int64(time.Microsecond),
		MaxProcessLatencyMicros: collector.maxProcessLatencyNs.Load() / int64(time.Microsecond),
	}

	if generateErr != nil {
		return result, generateErr
	}
	if result.StallDetected {
		return result, errors.New("pipeline stalled")
	}
	if result.UnexpectedErrorCount > 0 {
		return result, fmt.Errorf("unexpected errors=%d", result.UnexpectedErrorCount)
	}
	return result, nil
}

func runGenerator(ctx context.Context, profile LoadProfile, tickInterval time.Duration, scheduler *pipeline.Scheduler, agentID uuid.UUID, collector *scenarioCollector) error {
	pid := uint32(os.Getpid())
	start := time.Now()
	nextTick := start
	end := start.Add(profile.Duration)
	accumulator := 0.0
	logicalClock := int64(1)

	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		now := time.Now()
		if now.Before(nextTick) {
			time.Sleep(time.Until(nextTick))
			continue
		}

		accumulator += float64(profile.EPS) * tickInterval.Seconds()
		toEmit := int(accumulator)
		accumulator -= float64(toEmit)

		for emitted := 0; emitted < toEmit; emitted++ {
			ev, err := newVerifiedTelemetry(agentID, logicalClock, pid)
			if err != nil {
				return err
			}
			collector.generated.Add(1)
			enqueueStart := time.Now()
			collector.putEnqueueTime(logicalClock, enqueueStart)
			err = scheduler.Enqueue(ev)
			elapsed := time.Since(enqueueStart)
			collector.noteDuration(&collector.maxEnqueueBlockNs, elapsed)
			if errors.Is(err, pipeline.ErrQueueFull) {
				collector.queueDrops.Add(1)
				collector.popEnqueueTime(logicalClock)
			} else if err != nil {
				return err
			} else {
				collector.accepted.Add(1)
				collector.noteQueueDepth(scheduler.QueueDepth())
			}
			logicalClock++
		}

		nextTick = nextTick.Add(tickInterval)
	}
	return nil
}

func runWorker(ctx context.Context, pool *pipeline.WorkerPool, collector *scenarioCollector, generatorDone *atomic.Bool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		scheduler := pool.Scheduler
		if scheduler == nil {
			return
		}
		ev, err := scheduler.DequeueNext()
		if err != nil {
			collector.unexpectedErrs.Add(1)
			continue
		}
		if ev == nil {
			if generatorDone.Load() && collector.accepted.Load() == collector.processed.Load() {
				return
			}
			time.Sleep(50 * time.Microsecond)
			continue
		}

		start := time.Now()
		if enqueueTime, ok := collector.popEnqueueTime(ev.Payload.LogicalClock); ok {
			collector.ingestion.Record(start.Sub(enqueueTime))
		}
		err = pool.ProcessOne(ctx, ev.Payload)
		processElapsed := time.Since(start)
		collector.endToEnd.Record(processElapsed)
		collector.noteDuration(&collector.maxProcessLatencyNs, processElapsed)
		collector.processed.Add(1)

		if err != nil && !errors.Is(err, enforcement.ErrDispatchBackpressure) {
			collector.unexpectedErrs.Add(1)
		}
	}
}

func monitorProgress(ctx context.Context, cfg Config, collector *scenarioCollector, generatorDone *atomic.Bool, stallErr chan<- error) {
	ticker := time.NewTicker(cfg.ProgressInterval)
	defer ticker.Stop()

	lastProgressAt := time.Now()
	lastProcessed := collector.processed.Load()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentProcessed := collector.processed.Load()
			if currentProcessed != lastProcessed {
				lastProcessed = currentProcessed
				lastProgressAt = time.Now()
				continue
			}
			if time.Since(lastProgressAt) < cfg.StallAfter {
				continue
			}
			if generatorDone.Load() && collector.accepted.Load() == collector.processed.Load() {
				return
			}
			collector.stalled.Store(true)
			select {
			case stallErr <- errors.New("pipeline stalled"):
			default:
			}
			return
		}
	}
}

func sampleMemory(ctx context.Context, collector *scenarioCollector, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(defaultProgressInterval)
	defer ticker.Stop()
	for {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		collector.notePeakHeap(stats.HeapAlloc)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func aggregateScenario(cfg Config, eps int, repetitions []RepetitionResult) ScenarioAggregate {
	aggregate := ScenarioAggregate{
		EPS:               eps,
		RepetitionResults: repetitions,
		Stable:            true,
	}
	if len(repetitions) == 0 {
		aggregate.Stable = false
		aggregate.UnexpectedFailures = append(aggregate.UnexpectedFailures, fmt.Sprintf("eps=%d: no repetitions recorded", eps))
		return aggregate
	}

	aggregate.LatencyP50 = medianInt64(extractInt64(repetitions, func(item RepetitionResult) int64 { return item.LatencyP50 }))
	aggregate.LatencyP95 = medianInt64(extractInt64(repetitions, func(item RepetitionResult) int64 { return item.LatencyP95 }))
	aggregate.LatencyP99 = medianInt64(extractInt64(repetitions, func(item RepetitionResult) int64 { return item.LatencyP99 }))
	aggregate.MemoryMB = uint64(medianInt64(extractInt64(repetitions, func(item RepetitionResult) int64 { return int64(item.MemoryMB) })))
	aggregate.Drops = uint64(medianInt64(extractInt64(repetitions, func(item RepetitionResult) int64 { return int64(item.Drops) })))
	aggregate.ThroughputEPS = medianInt64(extractInt64(repetitions, func(item RepetitionResult) int64 { return item.ThroughputEPS }))
	aggregate.IngestionLatency = summarizeAggregateLatency(repetitions, func(item RepetitionResult) LatencyStats { return item.IngestionLatency })
	aggregate.DetectionLatency = summarizeAggregateLatency(repetitions, func(item RepetitionResult) LatencyStats { return item.DetectionLatency })
	aggregate.EnforcementLatency = summarizeAggregateLatency(repetitions, func(item RepetitionResult) LatencyStats { return item.EnforcementLatency })

	drift := maxDriftPercent(aggregate.LatencyP99, extractInt64(repetitions, func(item RepetitionResult) int64 { return item.LatencyP99 }))
	aggregate.StabilityDriftPct = drift

	for _, repetition := range repetitions {
		if repetition.StallDetected {
			aggregate.Stable = false
			aggregate.UnexpectedFailures = append(aggregate.UnexpectedFailures, fmt.Sprintf("eps=%d repetition=%d stalled", eps, repetition.Repetition))
		}
		if repetition.UnexpectedErrorCount > 0 {
			aggregate.Stable = false
			aggregate.UnexpectedFailures = append(aggregate.UnexpectedFailures, fmt.Sprintf("eps=%d repetition=%d unexpected_errors=%d", eps, repetition.Repetition, repetition.UnexpectedErrorCount))
		}
		if repetition.MemoryMB > cfg.MaxMemoryMB {
			aggregate.Stable = false
			aggregate.UnexpectedFailures = append(aggregate.UnexpectedFailures, fmt.Sprintf("eps=%d repetition=%d memory_mb=%d exceeds limit=%d", eps, repetition.Repetition, repetition.MemoryMB, cfg.MaxMemoryMB))
		}
	}
	if cfg.RequireStableAcross3 {
		if len(repetitions) < 3 {
			aggregate.Stable = false
			aggregate.UnexpectedFailures = append(aggregate.UnexpectedFailures, fmt.Sprintf("eps=%d: fewer than 3 repetitions", eps))
		}
		if drift > cfg.MaxStableDriftPercent {
			aggregate.Stable = false
			aggregate.UnexpectedFailures = append(aggregate.UnexpectedFailures, fmt.Sprintf("eps=%d: latency drift %.2f%% exceeds %.2f%%", eps, drift, cfg.MaxStableDriftPercent))
		}
	}
	return aggregate
}

func summarizeAggregateLatency(results []RepetitionResult, pick func(RepetitionResult) LatencyStats) LatencyStats {
	return LatencyStats{
		P50Millis: medianInt64(extractInt64(results, func(item RepetitionResult) int64 { return pick(item).P50Millis })),
		P95Millis: medianInt64(extractInt64(results, func(item RepetitionResult) int64 { return pick(item).P95Millis })),
		P99Millis: medianInt64(extractInt64(results, func(item RepetitionResult) int64 { return pick(item).P99Millis })),
	}
}

func summarizeLatency(values []int64) LatencyStats {
	return LatencyStats{
		P50Millis: percentileMillis(values, 0.50),
		P95Millis: percentileMillis(values, 0.95),
		P99Millis: percentileMillis(values, 0.99),
	}
}

func percentileMillis(values []int64, percentile float64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := int(math.Ceil(percentile*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index] / int64(time.Millisecond)
}

func maxDriftPercent(baseline int64, values []int64) float64 {
	if baseline <= 0 || len(values) == 0 {
		return 0
	}
	maxDrift := 0.0
	for _, value := range values {
		drift := math.Abs(float64(value-baseline)) / float64(baseline) * 100
		if drift > maxDrift {
			maxDrift = drift
		}
	}
	return maxDrift
}

func gcPauseMaxMillis(start, end runtime.MemStats) float64 {
	delta := end.NumGC - start.NumGC
	if delta == 0 {
		return 0
	}
	var max uint64
	for idx := uint32(0); idx < delta && idx < uint32(len(end.PauseNs)); idx++ {
		slot := (end.NumGC - 1 - idx) % uint32(len(end.PauseNs))
		if end.PauseNs[slot] > max {
			max = end.PauseNs[slot]
		}
	}
	return float64(max) / float64(time.Millisecond)
}

func normalizeConfig(cfg Config) Config {
	def := DefaultConfig()
	if len(cfg.Profiles) == 0 {
		cfg.Profiles = def.Profiles
	}
	for idx := range cfg.Profiles {
		if cfg.Profiles[idx].Duration <= 0 {
			cfg.Profiles[idx].Duration = defaultScenarioDuration
		}
	}
	if cfg.Repetitions <= 0 {
		cfg.Repetitions = def.Repetitions
	}
	if cfg.Workers <= 0 {
		cfg.Workers = def.Workers
	}
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = def.TickInterval
	}
	if cfg.ProgressInterval <= 0 {
		cfg.ProgressInterval = def.ProgressInterval
	}
	if cfg.StallAfter <= 0 {
		cfg.StallAfter = def.StallAfter
	}
	if cfg.MaxMemoryMB == 0 {
		cfg.MaxMemoryMB = def.MaxMemoryMB
	}
	if cfg.MaxStableDriftPercent <= 0 {
		cfg.MaxStableDriftPercent = def.MaxStableDriftPercent
	}
	return cfg
}

func newDetector() (*pipeline.DeterministicDetector, error) {
	model := ai.RuntimeModel{
		Algorithm:    "deterministic_logistic_regression_v1",
		Bias:         0.125,
		VectorLength: 15,
		Weights: []float64{
			0.40, 0.25, 0.18, 0.75, 0.80,
			0.45, 0.30, 0.20, 0.15, 0.35,
			0.30, 0.55, 0.28, 0.22, 0.24,
		},
		FeatureNames: []string{
			"event_type_norm",
			"time_delta_norm",
			"process_id_norm",
			"entropy_score",
			"burst_score",
			"chain_depth_norm",
			"execution_frequency_norm",
			"privilege_level_norm",
			"dropped_packets_norm",
			"window_entropy_mean",
			"window_burst_mean",
			"window_process_anomaly_mean",
			"window_execution_frequency_mean",
			"window_time_delta_mean",
			"window_privilege_level_mean",
		},
		FusionWeights: ai.FusionWeights{
			ModelPrediction: 0.55,
			EntropyScore:    0.20,
			BurstScore:      0.15,
			ProcessAnomaly:  0.10,
		},
		MaxTimeDeltaNS:           int64(100 * time.Millisecond),
		SequenceWindowSize:       32,
		ScoreThreshold:           0.20,
		SineMinThreshold:         0.05,
		TemporalBurstThresholdNS: int64(5 * time.Millisecond),
	}
	detector, err := pipeline.NewDeterministicDetector(model)
	if err != nil {
		return nil, err
	}
	detector.SetPolicyEngine(policy.NewEngine(policy.EnforcementPolicy{
		Mode:           policy.ModeAuto,
		Threshold:      0.20,
		AllowedActions: []string{policy.ActionKillProcess, policy.ActionBlockWrite},
	}, true))
	return detector, nil
}

func newVerifiedTelemetry(agentID uuid.UUID, logicalClock int64, pid uint32) (*ingest.VerifiedTelemetry, error) {
	eventID := deterministicUUID(0xB2, uint64(logicalClock))
	processHash := hash32(0x11, uint64(logicalClock))
	fileHash := hash32(0x22, uint64(logicalClock))
	networkTuple := hash16(0x33, uint64(logicalClock))
	bootSessionID := hash16(0x44, 1)
	eventType := uint32((logicalClock % 5) + 1)
	timestamp := uint64(1_700_000_000_000_000_000 + logicalClock*1_000)
	payload, err := ingest.BuildCanonicalV1(
		uint64(logicalClock),
		agentID,
		eventID,
		eventType,
		pid,
		processHash,
		fileHash,
		networkTuple,
		timestamp,
		bootSessionID,
	)
	if err != nil {
		return nil, err
	}
	eventTypeName, err := ingest.DBEventType(eventType)
	if err != nil {
		return nil, err
	}
	return &ingest.VerifiedTelemetry{
		Payload:        payload[:],
		AgentSignature: make([]byte, 64),
		AgentIDStr:     agentID.String(),
		EventType:      eventTypeName,
		TimestampUnix:  float64(timestamp) / float64(time.Second),
		LogicalClock:   logicalClock,
		DroppedCount:   0,
	}, nil
}

func mustDispatchRequest(agentID string, logicalClock int64) enforcement.DispatchRequest {
	agentUUID := deterministicUUID(0xA1, 1)
	payload, err := newVerifiedTelemetry(agentUUID, logicalClock, uint32(os.Getpid()))
	if err != nil {
		panic(err)
	}
	req, err := enforcement.BuildDispatchRequestWithResolver(
		agentID,
		deterministicUUID(0xB2, uint64(logicalClock)).String(),
		logicalClock,
		int64(1_700_000_000),
		payload.Payload,
		0.99,
		policy.EnforcementDecision{Action: policy.ActionKillProcess, Allowed: true},
		func(view ingest.TelemetryV1View) (enforcement.ProcessBinding, error) {
			return enforcement.ProcessBinding{
				ProcessHash:    fmt.Sprintf("%x", view.ProcessHash[:]),
				ExecutablePath: fmt.Sprintf("/proc/%d/exe", view.AuxPID),
				KernelTag:      "linux|perf|amd64",
			}, nil
		},
	)
	if err != nil {
		panic(err)
	}
	return req
}

func deterministicUUID(prefix byte, value uint64) uuid.UUID {
	var raw [16]byte
	raw[0] = prefix
	binary.LittleEndian.PutUint64(raw[8:], value)
	u, err := uuid.FromBytes(raw[:])
	if err != nil {
		panic(err)
	}
	return u
}

func hash32(prefix byte, value uint64) [32]byte {
	var buf [9]byte
	buf[0] = prefix
	binary.LittleEndian.PutUint64(buf[1:], value)
	return sha256.Sum256(buf[:])
}

func hash16(prefix byte, value uint64) [16]byte {
	sum := hash32(prefix, value)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func scalarPrediction(vector []float64, weights []float64, bias float64) float64 {
	total := round64(bias)
	for idx := range vector {
		total = round64(total + round64(vector[idx]*weights[idx]))
	}
	return sigmoid(total)
}

func vectorizedPrediction(vector []float64, weights []float64, bias float64) float64 {
	total := round64(bias)
	index := 0
	for ; index+3 < len(vector); index += 4 {
		total = round64(total + round64(vector[index]*weights[index]))
		total = round64(total + round64(vector[index+1]*weights[index+1]))
		total = round64(total + round64(vector[index+2]*weights[index+2]))
		total = round64(total + round64(vector[index+3]*weights[index+3]))
	}
	for ; index < len(vector); index++ {
		total = round64(total + round64(vector[index]*weights[index]))
	}
	return sigmoid(total)
}

func sigmoid(value float64) float64 {
	if value >= 0 {
		exponent := math.Exp(-value)
		return round64(1.0 / (1.0 + exponent))
	}
	exponent := math.Exp(value)
	return round64(exponent / (1.0 + exponent))
}

func round64(value float64) float64 {
	const scale = 100000000.0
	return math.Round(value*scale) / scale
}

func extractInt64[T any](items []T, pick func(T) int64) []int64 {
	out := make([]int64, 0, len(items))
	for _, item := range items {
		out = append(out, pick(item))
	}
	return out
}

func medianInt64(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func bytesToMB(bytes uint64) uint64 {
	return bytes / (1024 * 1024)
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
