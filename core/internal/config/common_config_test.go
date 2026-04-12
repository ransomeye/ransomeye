package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"ransomeye/core/internal/keys"
)

func TestVerifyCommonConfigRejectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := signedConfig(t, priv)
	signingCert := MustEd25519SelfSignedCertForTest(t, pub, priv)
	if err := VerifyCommonConfig(cfg, signingCert); err != nil {
		t.Fatalf("VerifyCommonConfig(valid): %v", err)
	}

	cfg.Core.GRPCEndpoint = "127.0.0.2:50051"
	if err := VerifyCommonConfig(cfg, signingCert); err == nil {
		t.Fatal("VerifyCommonConfig accepted tampered config")
	}
}

func TestCanonicalJSONDeterministic(t *testing.T) {
	cfg := unsignedConfig()
	a, err := CanonicalJSONBytes(cfg)
	if err != nil {
		t.Fatalf("CanonicalJSONBytes(a): %v", err)
	}
	b, err := CanonicalJSONBytes(cfg)
	if err != nil {
		t.Fatalf("CanonicalJSONBytes(b): %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical bytes differ:\n%s\n%s", a, b)
	}
}

func TestMissingFingerprintFailsStartup(t *testing.T) {
	cfg := unsignedConfig()
	cfg.Database.ExpectedServerFingerprint = ""
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected error for empty database.expected_server_fingerprint")
	}
}

func TestKeyLifecycleEnforcesAirgapOnly(t *testing.T) {
	cfg := unsignedConfig()
	cfg.KeyLifecycle.DistributionMode = "internet"
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected distribution_mode rejection")
	}
	cfg = unsignedConfig()
	cfg.KeyLifecycle.UpdateSource = "internet"
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected update_source rejection")
	}
	cfg = unsignedConfig()
	cfg.KeyLifecycle.RuntimeKeyGeneration = true
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected runtime key generation rejection")
	}
	cfg = unsignedConfig()
	cfg.KeyLifecycle.InternetUpdatesAllowed = true
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected internet updates rejection")
	}
}

func TestVerifyServerCertificateDERRejectsMismatch(t *testing.T) {
	certDER := []byte("fake-core-cert")
	err := VerifyServerCertificateDER(
		certDER,
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	)
	if err == nil {
		t.Fatal("VerifyServerCertificateDER accepted mismatched fingerprint")
	}
}

func signedConfig(t *testing.T, priv ed25519.PrivateKey) CommonConfig {
	t.Helper()
	cfg := unsignedConfig()
	canonical, err := CanonicalJSONBytes(cfg)
	if err != nil {
		t.Fatalf("CanonicalJSONBytes: %v", err)
	}
	sum := sha256.Sum256(canonical)
	cfg.Integrity.Signature = hex.EncodeToString(ed25519.Sign(priv, sum[:]))
	return cfg
}

func unsignedConfig() CommonConfig {
	now := time.Now().UTC()
	return CommonConfig{
		Backpressure: BackpressureConfig{
			MemoryThreshold:       int64Ptr(1024),
			DiskThresholdBytes:    int64Ptr(8 * 1024 * 1024),
			WALLatencyThresholdMS: int64Ptr(500),
		},
		Core: CoreConfig{
			GRPCEndpoint:          "127.0.0.1:50051",
			ServerCertFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		AI: AIConfig{
			ServiceAddr: "127.0.0.1:50052",
		},
		Network: NetworkConfig{
			SOCListenAddr: "127.0.0.1:8443",
			DPIPrimaryIP:  "127.0.0.1",
		},
		Identity: IdentityConfig{
			NodeID: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Role:   "core",
		},
		Security: SecurityConfig{
			CACertPath:     "/opt/ransomeye/core/certs/ca-chain.crt",
			ClientCertPath: "/etc/ransomeye/certs/client.crt",
			ClientKeyPath:  "/etc/ransomeye/certs/client.key",
		},
		Database: DatabaseConfig{
			Host:                      "127.0.0.1",
			Port:                      "5432",
			TLSEnforced:               true,
			ExpectedServerFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		KeyLifecycle: KeyLifecycleConfig{
			DistributionMode:       "airgap",
			UpdateSource:           "airgap",
			RuntimeKeyGeneration:   false,
			InternetUpdatesAllowed: false,
			PreviousEpoch:          0,
			ExpectedIdentityHash:   strings.Repeat("0", 64),
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
		Integrity: IntegrityConfig{},
	}
}

func int64Ptr(v int64) *int64 {
	return &v
}

func TestLifecycleTrustRejectsRevokedExpiredWrongEpochIdentityMismatch(t *testing.T) {
	cfg := unsignedConfig()
	cfg.KeyLifecycle.ConfigKey.Status = keys.StatusRevoked
	if err := ValidateLifecycleTrust(cfg, time.Now().UTC()); err == nil {
		t.Fatal("expected revoked key rejection")
	}

	cfg = unsignedConfig()
	cfg.KeyLifecycle.WormSigningKey.NotAfterUTC = time.Now().UTC().Add(-time.Minute)
	if err := ValidateLifecycleTrust(cfg, time.Now().UTC()); err == nil {
		t.Fatal("expected expired key rejection")
	}

	cfg = unsignedConfig()
	cfg.KeyLifecycle.PreviousEpoch = 1
	cfg.KeyLifecycle.ConfigKey.KeyEpoch = 3
	if err := ValidateLifecycleTrust(cfg, time.Now().UTC()); err == nil {
		t.Fatal("expected wrong epoch rejection")
	}

	cfg = unsignedConfig()
	cfg.KeyLifecycle.ExpectedIdentityHash = "nothex"
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected identity hash format rejection")
	}
}

func TestBackpressureThresholdsRequirePresence(t *testing.T) {
	cfg := unsignedConfig()
	cfg.Backpressure.MemoryThreshold = nil
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected memory threshold rejection")
	}

	cfg = unsignedConfig()
	cfg.Backpressure.DiskThresholdBytes = nil
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected disk threshold rejection")
	}

	cfg = unsignedConfig()
	cfg.Backpressure.WALLatencyThresholdMS = nil
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected wal latency threshold rejection")
	}
}

func TestBackpressureThresholdsRejectNonPositive(t *testing.T) {
	cfg := unsignedConfig()
	cfg.Backpressure.MemoryThreshold = int64Ptr(0)
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected zero memory threshold rejection")
	}

	cfg = unsignedConfig()
	cfg.Backpressure.DiskThresholdBytes = int64Ptr(-1)
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected negative disk threshold rejection")
	}

	cfg = unsignedConfig()
	cfg.Backpressure.WALLatencyThresholdMS = int64Ptr(-5)
	if err := validateCommonConfig(cfg); err == nil {
		t.Fatal("expected negative wal latency threshold rejection")
	}
}
