package bootstrap

import (
	"strings"
	"testing"
	"time"

	"ransomeye/core/internal/config"
	"ransomeye/core/internal/keys"
)

func validConfig(now time.Time) config.CommonConfig {
	return config.CommonConfig{
		KeyLifecycle: config.KeyLifecycleConfig{
			PreviousEpoch: 0,
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
}

func TestPreflightRejectsRevokedExpiredInvalidEpoch(t *testing.T) {
	now := time.Now().UTC()
	store := keys.NewStore()
	cfg := validConfig(now)
	cfg.KeyLifecycle.ConfigKey.Status = keys.StatusRevoked
	if err := ValidateLifecyclePreflight(cfg, now, store); err == nil {
		t.Fatal("expected revoked preflight rejection")
	}

	cfg = validConfig(now)
	cfg.KeyLifecycle.WormSigningKey.NotAfterUTC = now.Add(-time.Minute)
	if err := ValidateLifecyclePreflight(cfg, now, store); err == nil {
		t.Fatal("expected expired preflight rejection")
	}

	cfg = validConfig(now)
	cfg.KeyLifecycle.PreviousEpoch = 1
	cfg.KeyLifecycle.ConfigKey.KeyEpoch = 3
	if err := ValidateLifecyclePreflight(cfg, now, store); err == nil {
		t.Fatal("expected invalid epoch preflight rejection")
	}
}
