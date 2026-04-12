package backpressure

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ransomeye/core/internal/config"
)

type State string

const (
	StateNormal   State = "NORMAL"
	StatePressure State = "PRESSURE"
	StateFailsafe State = "FAILSAFE"
)

const SignalResourceExhausted = "RESOURCE_EXHAUSTED"

type Metrics struct {
	QueueDepth       int
	QueueCapacity    int
	PendingBytes     int64
	WALLatency       time.Duration
	QueueUnavailable bool
	DiskExhausted    bool
	FailClosed       bool
}

func (m Metrics) WithAdditionalDepth(delta int) Metrics {
	if delta <= 0 {
		return m
	}
	m.QueueDepth += delta
	return m
}

type Assessment struct {
	State   State
	Reason  string
	Metrics Metrics
}

func Evaluate(metrics Metrics) Assessment {
	thresholds, err := thresholdConfig()
	if err != nil {
		return Assessment{
			State:   StateFailsafe,
			Reason:  fmt.Sprintf("backpressure thresholds unavailable: %v", err),
			Metrics: metrics,
		}
	}
	return evaluateWithThresholds(metrics, thresholds)
}

type Thresholds struct {
	MemoryThreshold    int64
	DiskThresholdBytes int64
	WALLatency         time.Duration
}

var (
	thresholdsMu     sync.Mutex
	loadedThresholds Thresholds
	thresholdsLoaded bool
)

var testThresholdsMu sync.RWMutex
var testThresholdsOverride *Thresholds

// ResetThresholdCache invalidates the internal threshold cache, forcing
// a reload from configuration files on the next call to Evaluate or thresholdConfig.
func ResetThresholdCache() {
	thresholdsMu.Lock()
	defer thresholdsMu.Unlock()
	thresholdsLoaded = false
}

// SetTestThresholds sets a fixed set of thresholds for testing, bypassing
// global configuration files and filesystem access.
func SetTestThresholds(th Thresholds) {
	testThresholdsMu.Lock()
	defer testThresholdsMu.Unlock()
	testThresholdsOverride = &th
}

// ClearTestThresholds removes the test override.
func ClearTestThresholds() {
	testThresholdsMu.Lock()
	defer testThresholdsMu.Unlock()
	testThresholdsOverride = nil
}

// EvaluateWithThresholds evaluates metrics against explicit thresholds without loading global config.
// Use this for deterministic testing and in contexts where global config is unavailable.
func EvaluateWithThresholds(metrics Metrics, thresholds Thresholds) Assessment {
	return evaluateWithThresholds(metrics, thresholds)
}

func evaluateWithThresholds(metrics Metrics, thresholds Thresholds) Assessment {
	assessment := Assessment{
		State:   StateNormal,
		Reason:  "",
		Metrics: metrics,
	}

	switch {
	case metrics.QueueUnavailable:
		assessment.State = StateFailsafe
		assessment.Reason = "queue unavailable"
	case metrics.FailClosed:
		assessment.State = StateFailsafe
		assessment.Reason = "durable queue fail-closed"
	case metrics.DiskExhausted:
		assessment.State = StateFailsafe
		assessment.Reason = "disk exhaustion detected"
	case metrics.QueueCapacity <= 0:
		assessment.State = StateFailsafe
		assessment.Reason = "invalid queue capacity"
	case int64(metrics.QueueDepth) >= thresholds.MemoryThreshold:
		assessment.State = StatePressure
		assessment.Reason = fmt.Sprintf("memory threshold reached (%d/%d)", metrics.QueueDepth, thresholds.MemoryThreshold)
	case metrics.PendingBytes >= thresholds.DiskThresholdBytes:
		assessment.State = StatePressure
		assessment.Reason = fmt.Sprintf("disk threshold reached (%d/%d bytes)", metrics.PendingBytes, thresholds.DiskThresholdBytes)
	case metrics.WALLatency >= thresholds.WALLatency:
		assessment.State = StatePressure
		assessment.Reason = fmt.Sprintf("WAL latency threshold reached (%s/%s)", metrics.WALLatency.Round(time.Millisecond), thresholds.WALLatency)
	}

	return assessment
}

func thresholdConfig() (Thresholds, error) {
	testThresholdsMu.RLock()
	if testThresholdsOverride != nil {
		th := *testThresholdsOverride
		testThresholdsMu.RUnlock()
		return th, nil
	}
	testThresholdsMu.RUnlock()

	thresholdsMu.Lock()
	defer thresholdsMu.Unlock()

	if thresholdsLoaded {
		return loadedThresholds, nil
	}

	var cfg config.CommonConfig
	var ok bool
	if cfg, ok = config.CurrentVerifiedCommonConfig(); !ok {
		loadedCfg, err := config.LoadVerifiedCommonConfig(config.InstalledCommonConfigPath, config.IntermediateCACertPath)
		if err != nil {
			return Thresholds{}, err
		}
		cfg = loadedCfg
	}

	thresholds, err := thresholdsFromCommonConfig(cfg)
	if err != nil {
		return Thresholds{}, err
	}
	loadedThresholds = thresholds
	thresholdsLoaded = true
	return loadedThresholds, nil
}

func thresholdsFromCommonConfig(cfg config.CommonConfig) (Thresholds, error) {
	values, err := config.BackpressureThresholdsFromCommonConfig(cfg)
	if err != nil {
		return Thresholds{}, err
	}
	return Thresholds{
		MemoryThreshold:    values.MemoryThreshold,
		DiskThresholdBytes: values.DiskThresholdBytes,
		WALLatency:         time.Duration(values.WALLatencyThresholdMS) * time.Millisecond,
	}, nil
}

func (a Assessment) AdmissionAllowed() bool {
	return a.State == StateNormal
}

func (a Assessment) AdmissionError() error {
	if a.State == StateNormal {
		return nil
	}
	return &AdmissionError{
		state:  a.State,
		reason: a.Reason,
	}
}

func (a Assessment) Message() string {
	if a.State == StateNormal {
		return ""
	}
	return (&AdmissionError{state: a.State, reason: a.Reason}).Error()
}

type AdmissionError struct {
	state  State
	reason string
}

func (e *AdmissionError) Error() string {
	state := e.State()
	reason := e.reason
	if reason == "" {
		reason = "ingestion unavailable"
	}
	return fmt.Sprintf("%s: %s %s", SignalResourceExhausted, state, reason)
}

func (e *AdmissionError) State() State {
	if e == nil || e.state == "" {
		return StateFailsafe
	}
	return e.state
}

func (e *AdmissionError) Is(target error) bool {
	_, ok := target.(*AdmissionError)
	return ok
}

func NewAdmissionError(state State, reason string) error {
	if state == StateNormal {
		return nil
	}
	return &AdmissionError{
		state:  state,
		reason: reason,
	}
}

func IsResourceExhausted(err error) bool {
	var admissionErr *AdmissionError
	return errors.As(err, &admissionErr)
}

func StateFromError(err error) (State, bool) {
	var admissionErr *AdmissionError
	if !errors.As(err, &admissionErr) {
		return "", false
	}
	return admissionErr.State(), true
}

func MessageFromError(err error) string {
	var admissionErr *AdmissionError
	if errors.As(err, &admissionErr) {
		return admissionErr.Error()
	}
	return (&AdmissionError{
		state:  StateFailsafe,
		reason: "queue admission unavailable",
	}).Error()
}

type Engine struct {
	mu              sync.Mutex
	assessment      Assessment
	signal          Assessment // reason carrier for counter-driven pressure
	pressureCounter int64      // atomic; number of outstanding hub backpressure sources
}

func NewEngine() *Engine {
	return &Engine{
		assessment: Assessment{State: StateNormal},
	}
}

// stateOrder returns a numeric priority for a State so states can be compared.
func stateOrder(s State) int {
	switch s {
	case StatePressure:
		return 1
	case StateFailsafe:
		return 2
	default:
		return 0
	}
}

// Signal forces the engine assessment to at least the given state immediately.
// Called internally by IncrementPressure; not intended for direct use by
// callers outside this package.
func (e *Engine) Signal(state State, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.signal = Assessment{State: state, Reason: reason}
	if stateOrder(state) > stateOrder(e.assessment.State) {
		e.assessment = e.signal
	}
}

// ClearSignal removes the external signal and optimistically resets the cached
// assessment to StateNormal. The next Update call will re-evaluate from metrics
// and may raise the state again if warranted. Called internally by
// DecrementPressure when the counter reaches zero; not intended for direct use.
func (e *Engine) ClearSignal() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.signal = Assessment{}
	e.assessment = Assessment{State: StateNormal}
}

// IncrementPressure records one additional outstanding hub backpressure source
// and immediately signals StatePressure. Every call must be paired with exactly
// one DecrementPressure call when that source resolves.
func (e *Engine) IncrementPressure(reason string) {
	atomic.AddInt64(&e.pressureCounter, 1)
	e.Signal(StatePressure, reason)
}

// DecrementPressure records one hub backpressure source resolving. When the
// counter reaches zero, the external signal is cleared so metric-driven
// evaluation resumes. Panics if called more times than IncrementPressure.
func (e *Engine) DecrementPressure() {
	n := atomic.AddInt64(&e.pressureCounter, -1)
	if n < 0 {
		panic("backpressure: pressure counter went negative")
	}
	if n == 0 {
		e.ClearSignal()
	}
}

func (e *Engine) Update(metrics Metrics) Assessment {
	a := Evaluate(metrics)
	e.mu.Lock()
	defer e.mu.Unlock()

	if atomic.LoadInt64(&e.pressureCounter) > 0 {
		// Preservation of Causality: Signal reasons from hub backpressure MUST be 
		// merged with metric-driven reasons (if any) to preserve the diagnostic chain.
		a.Reason = e.mergeReasons(a.Reason, e.signal.Reason)

		// State Precedence: FAILSAFE > PRESSURE > NORMAL.
		// If the external signal is FAILSAFE, it forces the assessment to FAILSAFE.
		// Otherwise, an outstanding pressureCounter forces at least StatePressure.
		if stateOrder(e.signal.State) > stateOrder(a.State) {
			a.State = e.signal.State
		}

		if stateOrder(a.State) < stateOrder(StatePressure) {
			a.State = StatePressure
		}
	}

	e.assessment = a
	return a
}

// mergeReasons combines reasons following the mandated canonical pipeline:
// TRIM (whitespace) -> FILTER (non-empty) -> DEDUP (set) -> SORT (lexicographic) -> JOIN (" | ").
func (e *Engine) mergeReasons(r1, r2 string) string {
	reasonSet := make(map[string]struct{})
	
	splitAndAdd := func(s string) {
		for _, part := range strings.Split(s, " | ") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				reasonSet[trimmed] = struct{}{}
			}
		}
	}

	splitAndAdd(r1)
	splitAndAdd(r2)

	if len(reasonSet) == 0 {
		return ""
	}

	reasons := make([]string, 0, len(reasonSet))
	for r := range reasonSet {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)

	return strings.Join(reasons, " | ")
}

func (e *Engine) Snapshot() Assessment {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.assessment
}

func (e *Engine) State() State {
	return e.Snapshot().State
}

func (e *Engine) AdmissionAllowed() bool {
	return e.Snapshot().AdmissionAllowed()
}
