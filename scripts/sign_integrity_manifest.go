//go:build ignore

// Sign integrity.manifest with raw 32-byte Ed25519 seed (same contract as sign-integrity-manifest Rust tool).
// Usage: go run scripts/sign_integrity_manifest.go <manifest> <sig_out> <worm_seed_path>
package main

import (
	"crypto/ed25519"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	manifest, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	seed, err := os.ReadFile(os.Args[3])
	if err != nil {
		panic(err)
	}
	if len(seed) != ed25519.SeedSize {
		panic("seed must be 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, manifest)
	if err := os.WriteFile(os.Args[2], sig, 0o644); err != nil {
		panic(err)
	}
}
