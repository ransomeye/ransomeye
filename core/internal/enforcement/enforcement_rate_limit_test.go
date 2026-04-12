package enforcement

import "testing"

func TestEnforcementRateLimit(t *testing.T) {
	limiter := NewRateLimiter(10, 2)

	if !limiter.Allow(10) {
		t.Fatal("first event in window should pass")
	}
	if !limiter.Allow(11) {
		t.Fatal("second event in window should pass")
	}
	if limiter.Allow(19) {
		t.Fatal("third event in same window must be blocked")
	}
	if !limiter.Allow(20) {
		t.Fatal("new logical-clock window should reset limiter")
	}
	if !limiter.Allow(21) {
		t.Fatal("second event after reset should pass")
	}
	if limiter.Allow(29) {
		t.Fatal("third event after reset must be blocked")
	}
}
