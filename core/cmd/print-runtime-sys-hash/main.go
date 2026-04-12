package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	coreconfig "ransomeye/core/internal/config"
)

// Mirrors identity.loadRuntimeSystemIdentityHashFromSignedConfig for operator tooling (enrollment records).
func main() {
	cfg, err := coreconfig.LoadVerifiedCommonConfig(coreconfig.InstalledCommonConfigPath, coreconfig.IntermediateCACertPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	canonicalConfigBytes, err := coreconfig.CanonicalIdentityJSONBytes(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rootCAPEM, err := os.ReadFile(cfg.Security.CACertPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rootCABlock, _ := pem.Decode(rootCAPEM)
	if rootCABlock == nil {
		fmt.Fprintln(os.Stderr, "root CA PEM")
		os.Exit(1)
	}
	dbFingerprint, err := hex.DecodeString(strings.TrimSpace(cfg.Database.ExpectedServerFingerprint))
	if err != nil || len(dbFingerprint) != 32 {
		fmt.Fprintln(os.Stderr, "db fingerprint")
		os.Exit(1)
	}
	wormPub, err := os.ReadFile("/etc/ransomeye/worm_signing.pub")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(wormPub) != 32 {
		fmt.Fprintln(os.Stderr, "worm pub len")
		os.Exit(1)
	}
	rootFingerprint := sha256.Sum256(rootCABlock.Bytes)
	mat := make([]byte, 0, len(canonicalConfigBytes)+len(rootFingerprint)+len(dbFingerprint)+len(wormPub))
	mat = append(mat, canonicalConfigBytes...)
	mat = append(mat, rootFingerprint[:]...)
	mat = append(mat, dbFingerprint...)
	mat = append(mat, wormPub...)
	sum := sha256.Sum256(mat)
	fmt.Println(hex.EncodeToString(sum[:]))
}
