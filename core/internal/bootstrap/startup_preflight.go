package bootstrap

import (
	"context"
	"fmt"
	"strings"

	"ransomeye/core/internal/config"
	dbbase "ransomeye/core/internal/db"
	"ransomeye/core/internal/db/validator"
)

type StartupHooks struct {
	LoadSignedConfig func() (config.CommonConfig, error)
	ValidateDBSchema func(context.Context, config.CommonConfig) error
}

func RunStartupPreflight(ctx context.Context, dbCfg dbbase.Config) (config.CommonConfig, error) {
	return runStartupPreflight(ctx, StartupHooks{
		LoadSignedConfig: func() (config.CommonConfig, error) {
			return config.LoadVerifiedCommonConfig(config.InstalledCommonConfigPath, config.IntermediateCACertPath)
		},
		ValidateDBSchema: func(ctx context.Context, cfg config.CommonConfig) error {
			dbCfg.ExpectedPostgresServerFingerprint = strings.TrimSpace(cfg.Database.ExpectedServerFingerprint)
			return validator.VerifyReplaySchema(ctx, validator.Config{DB: dbCfg})
		},
	})
}

func runStartupPreflight(ctx context.Context, hooks StartupHooks) (config.CommonConfig, error) {
	if hooks.LoadSignedConfig == nil {
		return config.CommonConfig{}, fmt.Errorf("startup step 1/2 load signed config: loader missing")
	}

	cfg, err := hooks.LoadSignedConfig()
	if err != nil {
		return config.CommonConfig{}, fmt.Errorf("startup step 1/2 load signed config: %w", err)
	}

	if _, err := config.BackpressureThresholdsFromCommonConfig(cfg); err != nil {
		return config.CommonConfig{}, fmt.Errorf("startup step 3 validate thresholds: %w", err)
	}

	if hooks.ValidateDBSchema != nil {
		if err := hooks.ValidateDBSchema(ctx, cfg); err != nil {
			return config.CommonConfig{}, fmt.Errorf("startup step 4 validate db schema: %w", err)
		}
	}

	return cfg, nil
}
