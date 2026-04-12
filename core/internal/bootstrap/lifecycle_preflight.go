package bootstrap

import (
	"fmt"
	"time"

	"ransomeye/core/internal/config"
	"ransomeye/core/internal/keys"
	"ransomeye/core/internal/lifecycle"
)

func ValidateLifecyclePreflight(cfg config.CommonConfig, now time.Time, store *keys.Store) error {
	engine := lifecycle.NewEngine()
	targets := map[string]keys.Metadata{
		"config":    cfg.KeyLifecycle.ConfigKey,
		"telemetry": cfg.KeyLifecycle.TelemetryVerifyKey,
		"worm":      cfg.KeyLifecycle.WormSigningKey,
	}
	for scope, meta := range targets {
		if err := engine.ValidateRuntimeOperation(meta, "verify", now); err != nil {
			return fmt.Errorf("%s key preflight failed: %w", scope, err)
		}
		if meta.Status == keys.StatusRevoked || meta.Status == keys.StatusExpired {
			return fmt.Errorf("%s key preflight failed: invalid status", scope)
		}
		if store != nil {
			if err := store.Save(scope, meta); err != nil {
				return fmt.Errorf("%s key audit persist failed: %w", scope, err)
			}
		}
	}
	// Rotation law enforcement for bootstrap epoch continuity.
	if cfg.KeyLifecycle.PreviousEpoch > 0 {
		if err := engine.ValidateRotation(cfg.KeyLifecycle.PreviousEpoch, cfg.KeyLifecycle.ConfigKey.KeyEpoch); err != nil {
			return fmt.Errorf("config key epoch continuity failed: %w", err)
		}
	}
	return nil
}
