package config

import (
	"log"
	"os"
)

type BootstrapConfig struct {
	DPIPrimaryIP string
	MasterKey    string
}

// LoadBootstrapConfig loads deterministic bootstrap values: DPI IP may default; master key is mandatory (PRD-14).
func LoadBootstrapConfig() BootstrapConfig {
	cfg := BootstrapConfig{}
	vCfg := MustGetVerified()

	// --- DPI PRIMARY IP (NON-CRITICAL → DEFAULT ALLOWED)
	cfg.DPIPrimaryIP = vCfg.Network.DPIPrimaryIP

	// --- MASTER KEY (CRITICAL → MUST EXIST)
	cfg.MasterKey = os.Getenv("RANSOMEYE_MASTER_KEY")
	if cfg.MasterKey == "" {
		log.Fatalf("[FATAL] RANSOMEYE_MASTER_KEY is required (PRD-14)")
	}

	return cfg
}
