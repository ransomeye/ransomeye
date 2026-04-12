package enforcement

import "sync"

type RateLimiter struct {
	mu          sync.Mutex
	counter     int
	windowStart int64
	windowSize  int64
	maxAllowed  int
}

func NewRateLimiter(windowSize int64, maxAllowed int) *RateLimiter {
	if windowSize <= 0 {
		windowSize = 1
	}
	if maxAllowed <= 0 {
		maxAllowed = 1
	}
	return &RateLimiter{
		windowSize: windowSize,
		maxAllowed: maxAllowed,
	}
}

func (r *RateLimiter) Allow(logicalClock int64) bool {
	if r == nil {
		return true
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	windowStart := logicalClock
	if r.windowSize > 0 {
		windowStart = logicalClock - (logicalClock % r.windowSize)
	}

	if r.counter == 0 || windowStart != r.windowStart {
		r.windowStart = windowStart
		r.counter = 0
	}

	r.counter++
	return r.counter <= r.maxAllowed
}
