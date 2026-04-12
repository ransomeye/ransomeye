// Phase 6.4–6.6: continuous integrity (manifest + AI vendor); cryptographic hash cache only (single goroutine).
package integrity

import (
	"log"
	"time"

	"ransomeye/core/internal/ai"
)

const runtimeIntegrityInterval = 30 * time.Second

// runtimeHashCache last verified SHA256 digests per absolute path; bounded by pruning to paths seen each pass.
var runtimeHashCache = map[string][32]byte{}

func runIntegrityCheck() error {
	seen := make(map[string]bool, 1024)
	if err := verifySignedManifestWithHashCache(
		DefaultManifestPath,
		DefaultSigPath,
		DefaultWormPubPath,
		runtimeHashCache,
		seen,
	); err != nil {
		return err
	}
	if err := ai.VerifyBeforeStartWithHashCache(runtimeHashCache, seen); err != nil {
		return err
	}
	for k := range runtimeHashCache {
		if !seen[k] {
			delete(runtimeHashCache, k)
		}
	}
	return nil
}

// RunRuntimeIntegrityCheck runs one signed-manifest + vendor pass synchronously (populates hash cache). Call before AI dial so there is no window without verification.
func RunRuntimeIntegrityCheck() error {
	return runIntegrityCheck()
}

// StartRuntimeIntegrityLoop runs an immediate follow-up check, then every 30s (fail-closed).
func StartRuntimeIntegrityLoop() {
	go func() {
		ticker := time.NewTicker(runtimeIntegrityInterval)
		defer ticker.Stop()

		if err := runIntegrityCheck(); err != nil {
			log.Fatalf("[FATAL] Runtime integrity violation: %v", err)
		}
		for range ticker.C {
			if err := runIntegrityCheck(); err != nil {
				log.Fatalf("[FATAL] Runtime integrity violation: %v", err)
			}
		}
	}()
}
