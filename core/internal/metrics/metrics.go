package metrics

import (
	"errors"
	"math/bits"
	"sync"
	"sync/atomic"
)

const (
	sineStateOK uint32 = iota
	sineStateDegraded
)

var (
	eventsIngested      atomic.Uint64
	eventsDropped       atomic.Uint64
	enforcementBlocked  atomic.Uint64
	backpressureDrops   atomic.Uint64
	backpressureLastSec atomic.Uint64
	dpiPacketsTotal     atomic.Uint64
	dpiPacketsDropped   atomic.Uint64
	dpiThrottleMode     atomic.Uint32
	dpiSamplingRate     atomic.Uint32
	dpiControlLatency   atomic.Uint64

	coreQueueDrops             atomic.Uint64
	perSubscriberDrops         atomic.Uint64
	criticalPerSubscriberDrops atomic.Uint64
	clientDisconnects          atomic.Uint64
	sineFailuresTotal          atomic.Uint64
	sineStateValue             atomic.Uint32
)

// Rolling drop rate: ring of last 10 seconds; rotated every second for PRD-18 alerting.
var (
	dropRateMu        sync.Mutex
	dropRateRing      [10]uint64
	dropRateLastTotal uint64
)

// ErrDropped is a sentinel error for non-blocking drop-on-backpressure behavior.
var ErrDropped = errors.New("dropped due to backpressure")

func IncEventsIngested(n uint64) {
	eventsIngested.Add(n)
}

func IncEventsDropped(n uint64) {
	eventsDropped.Add(n)
}

func IncEnforcementBlocked(n uint64) {
	enforcementBlocked.Add(n)
}

func IncDPIPacketsTotal(n uint64) {
	dpiPacketsTotal.Add(n)
}

func IncDPIPacketsDropped(n uint64) {
	dpiPacketsDropped.Add(n)
}

func IncSINEFailuresTotal(n uint64) {
	sineFailuresTotal.Add(n)
}

func SetDPIThrottleMode(mode uint32) {
	dpiThrottleMode.Store(mode)
}

func SetDPISamplingRate(rate uint32) {
	dpiSamplingRate.Store(rate)
}

func SetDPIControlLatency(latencyMicros uint64) {
	dpiControlLatency.Store(latencyMicros)
}

func EventsIngested() uint64     { return eventsIngested.Load() }
func EventsDropped() uint64      { return eventsDropped.Load() }
func EnforcementBlocked() uint64 { return enforcementBlocked.Load() }
func DPIPacketsTotal() uint64    { return dpiPacketsTotal.Load() }
func DPIPacketsDropped() uint64  { return dpiPacketsDropped.Load() }
func DPIThrottleMode() uint32    { return dpiThrottleMode.Load() }
func DPISamplingRate() uint32    { return dpiSamplingRate.Load() }
func DPIControlLatency() uint64  { return dpiControlLatency.Load() }
func SINEFailuresTotal() uint64  { return sineFailuresTotal.Load() }

func DPIDropSnapshot() (total uint64, dropped uint64) {
	total = DPIPacketsTotal()
	dropped = DPIPacketsDropped()
	if dropped > total {
		panic("invalid drop accounting state")
	}
	return total, dropped
}

// DPIDropRatio returns the integer DPI drop ratio in parts per million.
func DPIDropRatio() uint64 {
	total, dropped := DPIDropSnapshot()
	if total == 0 {
		return 0
	}
	return (dropped * 1_000_000) / total
}

func DPIThresholdExceeded(dropped, total, thresholdNum, thresholdDen uint64) bool {
	if thresholdDen == 0 {
		panic("invalid drop accounting threshold")
	}
	if dropped > total {
		panic("invalid drop accounting state")
	}
	leftHi, leftLo := bits.Mul64(dropped, thresholdDen)
	rightHi, rightLo := bits.Mul64(total, thresholdNum)
	if leftHi != rightHi {
		return leftHi > rightHi
	}
	return leftLo > rightLo
}

func SetSINEStateOK() {
	sineStateValue.Store(sineStateOK)
}

func SetSINEStateDegraded() {
	sineStateValue.Store(sineStateDegraded)
}

func SINEState() string {
	if sineStateValue.Load() == sineStateDegraded {
		return "DEGRADED"
	}
	return "OK"
}

// IncBackpressureDrops counts one or more backpressure occurrences (e.g. full channel, slow subscriber).
func IncBackpressureDrops(n uint64) {
	backpressureDrops.Add(n)
	backpressureLastSec.Add(n)
}

// IncCoreQueueDrops counts drops when the core hub input queue is full (legacy; zero with direct fan-out).
func IncCoreQueueDrops(n uint64) { coreQueueDrops.Add(n) }

// CoreQueueDrops returns total core hub input queue drops since process start.
func CoreQueueDrops() uint64 { return coreQueueDrops.Load() }

// IncPerSubscriberDrops counts drops when any subscriber channel is full (non-critical events).
func IncPerSubscriberDrops(n uint64) { perSubscriberDrops.Add(n) }

// PerSubscriberDrops returns total per-subscriber drops since process start.
func PerSubscriberDrops() uint64 { return perSubscriberDrops.Load() }

// IncCriticalPerSubscriberDrops counts drops of critical (detection) events when a subscriber channel is full.
// Required for alerting: critical events must not be dropped at hub level; per-sub drops are tracked here.
func IncCriticalPerSubscriberDrops(n uint64) { criticalPerSubscriberDrops.Add(n) }

// CriticalPerSubscriberDrops returns total critical per-subscriber drops since process start.
func CriticalPerSubscriberDrops() uint64 { return criticalPerSubscriberDrops.Load() }

// IncClientDisconnects counts SOC client disconnects due to backpressure.
func IncClientDisconnects(n uint64) { clientDisconnects.Add(n) }

// ClientDisconnects returns total SOC client disconnects since process start.
func ClientDisconnects() uint64 { return clientDisconnects.Load() }

// BackpressureDrops returns total backpressure drop count since process start.
func BackpressureDrops() uint64 {
	return backpressureDrops.Load()
}

// BackpressureLastSecond returns the number of backpressure drops in the current 1s window (best-effort).
// Call RotateBackpressureWindow every second from a ticker to get per-second rate.
func BackpressureLastSecond() uint64 {
	return backpressureLastSec.Load()
}

// RotateBackpressureWindow resets the per-second counter. Call once per second (e.g. from alerting goroutine).
func RotateBackpressureWindow() {
	backpressureLastSec.Store(0)
}

// SustainedBackpressureAlert returns true if backpressure rate is sustained above threshold.
// threshold is the max allowed drops per second; window is the number of consecutive seconds to check.
// RotateBackpressureWindow must be called every second for this to be meaningful.
func SustainedBackpressureAlert(threshold uint64, windowSeconds int) bool {
	if windowSeconds <= 0 {
		return false
	}
	return backpressureLastSec.Load() > threshold
}

// RotateDropRateWindow updates the rolling drop rate ring. Call every 1s (e.g. from health sweeper or main ticker).
// Drops = PerSubscriberDrops + CoreQueueDrops + CriticalPerSubscriberDrops (hub-related drops).
func RotateDropRateWindow() {
	total := PerSubscriberDrops() + CoreQueueDrops() + CriticalPerSubscriberDrops()
	dropRateMu.Lock()
	delta := total - dropRateLastTotal
	dropRateLastTotal = total
	for i := 9; i > 0; i-- {
		dropRateRing[i] = dropRateRing[i-1]
	}
	dropRateRing[0] = delta
	dropRateMu.Unlock()
}

// DropRate1s returns the number of hub-related drops in the most recent completed 1s window.
// RotateDropRateWindow must be called every second for accurate values.
func DropRate1s() uint64 {
	dropRateMu.Lock()
	v := dropRateRing[0]
	dropRateMu.Unlock()
	return v
}

// DropRate10s returns the sum of hub-related drops over the last 10s (rolling window).
// RotateDropRateWindow must be called every second for accurate values.
func DropRate10s() uint64 {
	dropRateMu.Lock()
	var sum uint64
	for i := 0; i < 10; i++ {
		sum += dropRateRing[i]
	}
	dropRateMu.Unlock()
	return sum
}
