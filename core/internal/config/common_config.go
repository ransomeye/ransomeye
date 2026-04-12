package config

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"ransomeye/core/internal/keys"
	"ransomeye/core/internal/lifecycle"
)

const (
	InstalledCommonConfigPath = "/etc/ransomeye/config/common.yaml"
	IntermediateCACertPath    = "/etc/ransomeye/pki/intermediate_ca.crt"
	CanonicalServerCertPath   = "/etc/ransomeye/server.crt"
	RequiredCoreGRPCPort      = "50051"
)

type CommonConfig struct {
	Backpressure BackpressureConfig `yaml:"backpressure"`
	Core         CoreConfig         `yaml:"core"`
	AI           AIConfig           `yaml:"ai"`
	Network      NetworkConfig      `yaml:"network"`
	Identity     IdentityConfig     `yaml:"identity"`
	Security     SecurityConfig     `yaml:"security"`
	Database     DatabaseConfig     `yaml:"database"`
	KeyLifecycle KeyLifecycleConfig `yaml:"key_lifecycle"`
	Integrity    IntegrityConfig    `yaml:"integrity"`
}

type AIConfig struct {
	ServiceAddr string `yaml:"service_addr"`
}

type NetworkConfig struct {
	SOCListenAddr string `yaml:"soc_listen_addr"`
	DPIPrimaryIP  string `yaml:"dpi_primary_ip"`
}

type BackpressureConfig struct {
	MemoryThreshold       *int64 `yaml:"memory_threshold"`
	DiskThresholdBytes    *int64 `yaml:"disk_threshold_bytes"`
	WALLatencyThresholdMS *int64 `yaml:"wal_latency_threshold_ms"`
}

type BackpressureThresholds struct {
	MemoryThreshold       int64
	DiskThresholdBytes    int64
	WALLatencyThresholdMS int64
}

type CoreConfig struct {
	GRPCEndpoint          string `yaml:"grpc_endpoint"`
	ServerCertFingerprint string `yaml:"server_cert_fingerprint"`
}

type IdentityConfig struct {
	NodeID string `yaml:"node_id"`
	Role   string `yaml:"role"`
}

type SecurityConfig struct {
	CACertPath     string `yaml:"ca_cert_path"`
	ClientCertPath string `yaml:"client_cert_path"`
	ClientKeyPath  string `yaml:"client_key_path"`
}

// DatabaseConfig gates PostgreSQL TLS policy (PRD-03 / PRD-17). Signed into common.yaml canonical JSON.
type DatabaseConfig struct {
	Host                      string `yaml:"host"`
	Port                      string `yaml:"port"`
	TLSEnforced               bool   `yaml:"tls_enforced"`
	ExpectedServerFingerprint string `yaml:"expected_server_fingerprint"`
}

type IntegrityConfig struct {
	Signature string `yaml:"signature"`
}

type KeyLifecycleConfig struct {
	DistributionMode       string        `yaml:"distribution_mode"`
	UpdateSource           string        `yaml:"update_source"`
	RuntimeKeyGeneration   bool          `yaml:"runtime_key_generation"`
	InternetUpdatesAllowed bool          `yaml:"internet_updates_allowed"`
	PreviousEpoch          int           `yaml:"previous_epoch"`
	ConfigKey              keys.Metadata `yaml:"config_key"`
	TelemetryVerifyKey     keys.Metadata `yaml:"telemetry_verify_key"`
	WormSigningKey         keys.Metadata `yaml:"worm_signing_key"`
	ExpectedIdentityHash   string        `yaml:"expected_identity_hash"`
}

var (
	verifiedConfigMu sync.Mutex
	verifiedConfig   CommonConfig
	verifiedConfigOK bool
)

func MustLoadVerifiedCommonConfig() CommonConfig {
	cfg, err := LoadVerifiedCommonConfig(InstalledCommonConfigPath, IntermediateCACertPath)
	if err != nil {
		panic(err)
	}
	return cfg
}

// DevModeEnabled is true only when RANSOMEYE_DEV_MODE is exactly "true" (default off).
func DevModeEnabled() bool {
	return strings.TrimSpace(os.Getenv("RANSOMEYE_DEV_MODE")) == "true"
}

func LoadVerifiedCommonConfig(configPathArg, signingCertPath string) (CommonConfig, error) {
	devMode := DevModeEnabled()
	configPath := InstalledCommonConfigPath
	if devMode {
		log.Println("[DEV MODE] enabled — allowing local config fallback")
	}
	if !devMode {
		if strings.TrimSpace(configPathArg) != "" && configPathArg != InstalledCommonConfigPath {
			log.Fatalf("[FATAL] non-canonical config path in production mode")
		}
	}

	raw, err := os.ReadFile(configPath)
	if err != nil && devMode {
		configPath = "configs/common.yaml"
		log.Println("[DEV MODE] using local config:", configPath)
		raw, err = os.ReadFile(configPath)
	}
	if !devMode && configPath != InstalledCommonConfigPath {
		log.Fatalf("[FATAL] non-canonical config path in production mode")
	}
	if err != nil {
		return CommonConfig{}, fmt.Errorf("read %s: %w", configPath, err)
	}
	var cfg CommonConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return CommonConfig{}, fmt.Errorf("parse %s: %w", configPath, err)
	}
	if devMode {
		log.Println("[DEV MODE] skipping signed config verification")
		cacheVerifiedCommonConfig(cfg)
		return cfg, nil
	}
	signingCert, err := parseFirstPEMCertificate(signingCertPath)
	if err != nil {
		return CommonConfig{}, fmt.Errorf("signed config verification failed: %w", err)
	}
	if err := VerifyCommonConfig(cfg, signingCert); err != nil {
		return CommonConfig{}, fmt.Errorf("signed config verification failed: %w", err)
	}
	if err := ValidateLifecycleTrust(cfg, time.Now().UTC()); err != nil {
		return CommonConfig{}, fmt.Errorf("lifecycle trust validation failed: %w", err)
	}
	cacheVerifiedCommonConfig(cfg)
	return cfg, nil
}

func VerifyCommonConfig(cfg CommonConfig, signingCert *x509.Certificate) error {
	if signingCert == nil {
		return fmt.Errorf("signing certificate required")
	}
	if err := validateCommonConfig(cfg); err != nil {
		return err
	}
	sigHex := strings.TrimSpace(cfg.Integrity.Signature)
	if sigHex == "" {
		return fmt.Errorf("integrity.signature missing")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode config signature: %w", err)
	}
	canonical, err := CanonicalJSONBytes(cfg)
	if err != nil {
		return err
	}
	if err := verifyConfigSignature(signingCert.PublicKey, canonical, sig); err != nil {
		return fmt.Errorf("config signature verification failed: %w", err)
	}
	return nil
}

func verifyConfigSignature(pub crypto.PublicKey, canonical, sig []byte) error {
	sum := sha256.Sum256(canonical)
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("ed25519 signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
		}
		if !ed25519.Verify(k, sum[:], sig) {
			return fmt.Errorf("ed25519 verify failed")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig)
	default:
		return fmt.Errorf("unsupported signing certificate public key type %T (need Ed25519 or RSA)", pub)
	}
}

// SignCommonConfig clears and replaces integrity.signature using SHA-256(canonical JSON) signed with RSA-PKCS1-v1.5 or Ed25519.
func SignCommonConfig(cfg CommonConfig, priv crypto.PrivateKey) (CommonConfig, error) {
	cfg.Integrity.Signature = ""
	canonical, err := CanonicalJSONBytes(cfg)
	if err != nil {
		return cfg, err
	}
	sum := sha256.Sum256(canonical)
	var sig []byte
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		if err != nil {
			return cfg, err
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, sum[:])
	default:
		return cfg, fmt.Errorf("unsupported private key type %T (need *rsa.PrivateKey or ed25519.PrivateKey)", priv)
	}
	cfg.Integrity.Signature = hex.EncodeToString(sig)
	return cfg, nil
}

// ParsePKCS8PrivateKeyAny loads RSA or Ed25519 from PEM PKCS#8.
func ParsePKCS8PrivateKeyAny(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *rsa.PrivateKey, ed25519.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PKCS#8 key type %T", key)
	}
}

func parseFirstPEMCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("parse %s: no PEM certificate", path)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		return cert, nil
	}
}

func CanonicalJSONBytes(cfg CommonConfig) ([]byte, error) {
	if err := validateCommonConfig(cfg); err != nil {
		return nil, err
	}
	backpressureThresholds, err := BackpressureThresholdsFromCommonConfig(cfg)
	if err != nil {
		return nil, err
	}
	memoryThreshold, err := json.Marshal(backpressureThresholds.MemoryThreshold)
	if err != nil {
		return nil, fmt.Errorf("json backpressure.memory_threshold: %w", err)
	}
	diskThresholdBytes, err := json.Marshal(backpressureThresholds.DiskThresholdBytes)
	if err != nil {
		return nil, fmt.Errorf("json backpressure.disk_threshold_bytes: %w", err)
	}
	walLatencyThresholdMS, err := json.Marshal(backpressureThresholds.WALLatencyThresholdMS)
	if err != nil {
		return nil, fmt.Errorf("json backpressure.wal_latency_threshold_ms: %w", err)
	}
	endpoint, err := json.Marshal(strings.TrimSpace(cfg.Core.GRPCEndpoint))
	if err != nil {
		return nil, fmt.Errorf("json core.grpc_endpoint: %w", err)
	}
	fingerprint, err := json.Marshal(mustNormalizedFingerprint(cfg.Core.ServerCertFingerprint))
	if err != nil {
		return nil, fmt.Errorf("json core.server_cert_fingerprint: %w", err)
	}
	nodeID, err := json.Marshal(mustNormalizedNodeID(cfg.Identity.NodeID))
	if err != nil {
		return nil, fmt.Errorf("json identity.node_id: %w", err)
	}
	role, err := json.Marshal(strings.ToLower(strings.TrimSpace(cfg.Identity.Role)))
	if err != nil {
		return nil, fmt.Errorf("json identity.role: %w", err)
	}
	caCert, err := json.Marshal(strings.TrimSpace(cfg.Security.CACertPath))
	if err != nil {
		return nil, fmt.Errorf("json security.ca_cert_path: %w", err)
	}
	clientCert, err := json.Marshal(strings.TrimSpace(cfg.Security.ClientCertPath))
	if err != nil {
		return nil, fmt.Errorf("json security.client_cert_path: %w", err)
	}
	clientKey, err := json.Marshal(strings.TrimSpace(cfg.Security.ClientKeyPath))
	if err != nil {
		return nil, fmt.Errorf("json security.client_key_path: %w", err)
	}
	dbHost, err := json.Marshal(strings.TrimSpace(cfg.Database.Host))
	if err != nil {
		return nil, fmt.Errorf("json database.host: %w", err)
	}
	dbPort, err := json.Marshal(strings.TrimSpace(cfg.Database.Port))
	if err != nil {
		return nil, fmt.Errorf("json database.port: %w", err)
	}
	aiAddr, err := json.Marshal(strings.TrimSpace(cfg.AI.ServiceAddr))
	if err != nil {
		return nil, fmt.Errorf("json ai.service_addr: %w", err)
	}
	socAddr, err := json.Marshal(strings.TrimSpace(cfg.Network.SOCListenAddr))
	if err != nil {
		return nil, fmt.Errorf("json network.soc_listen_addr: %w", err)
	}
	dpiIP, err := json.Marshal(strings.TrimSpace(cfg.Network.DPIPrimaryIP))
	if err != nil {
		return nil, fmt.Errorf("json network.dpi_primary_ip: %w", err)
	}
	dbTLS, err := json.Marshal(cfg.Database.TLSEnforced)
	if err != nil {
		return nil, fmt.Errorf("json database.tls_enforced: %w", err)
	}
	dbFp, err := json.Marshal(mustNormalizedDatabaseFingerprint(cfg.Database.ExpectedServerFingerprint))
	if err != nil {
		return nil, fmt.Errorf("json database.expected_server_fingerprint: %w", err)
	}
	distributionMode, err := json.Marshal(normalizedDistributionSource(cfg.KeyLifecycle.DistributionMode))
	if err != nil {
		return nil, fmt.Errorf("json key_lifecycle.distribution_mode: %w", err)
	}
	updateSource, err := json.Marshal(normalizedDistributionSource(cfg.KeyLifecycle.UpdateSource))
	if err != nil {
		return nil, fmt.Errorf("json key_lifecycle.update_source: %w", err)
	}
	runtimeKeyGeneration, err := json.Marshal(cfg.KeyLifecycle.RuntimeKeyGeneration)
	if err != nil {
		return nil, fmt.Errorf("json key_lifecycle.runtime_key_generation: %w", err)
	}
	internetUpdatesAllowed, err := json.Marshal(cfg.KeyLifecycle.InternetUpdatesAllowed)
	if err != nil {
		return nil, fmt.Errorf("json key_lifecycle.internet_updates_allowed: %w", err)
	}
	out := fmt.Sprintf(
		"{\"ai\":{\"service_addr\":%s},\"backpressure\":{\"disk_threshold_bytes\":%s,\"memory_threshold\":%s,\"wal_latency_threshold_ms\":%s},\"core\":{\"grpc_endpoint\":%s,\"server_cert_fingerprint\":%s},\"database\":{\"expected_server_fingerprint\":%s,\"host\":%s,\"port\":%s,\"tls_enforced\":%s},\"identity\":{\"node_id\":%s,\"role\":%s},\"key_lifecycle\":{\"distribution_mode\":%s,\"internet_updates_allowed\":%s,\"runtime_key_generation\":%s,\"update_source\":%s},\"network\":{\"dpi_primary_ip\":%s,\"soc_listen_addr\":%s},\"security\":{\"ca_cert_path\":%s,\"client_cert_path\":%s,\"client_key_path\":%s}}",
		aiAddr,
		diskThresholdBytes,
		memoryThreshold,
		walLatencyThresholdMS,
		endpoint,
		fingerprint,
		dbFp,
		dbHost,
		dbPort,
		dbTLS,
		nodeID,
		role,
		distributionMode,
		internetUpdatesAllowed,
		runtimeKeyGeneration,
		updateSource,
		dpiIP,
		socAddr,
		caCert,
		clientCert,
		clientKey,
	)
	return []byte(out), nil
}

// CanonicalIdentityJSONBytes mirrors the Rust signed-config canonical JSON used by the Linux agent
// for system_identity_hash derivation. Keep this byte-for-byte aligned with
// signed-config/src/lib.rs canonical_json_bytes.
func CanonicalIdentityJSONBytes(cfg CommonConfig) ([]byte, error) {
	endpoint, err := json.Marshal(strings.TrimSpace(cfg.Core.GRPCEndpoint))
	if err != nil {
		return nil, fmt.Errorf("json core.grpc_endpoint: %w", err)
	}
	fingerprint, err := json.Marshal(mustNormalizedFingerprint(cfg.Core.ServerCertFingerprint))
	if err != nil {
		return nil, fmt.Errorf("json core.server_cert_fingerprint: %w", err)
	}
	dbFp, err := json.Marshal(mustNormalizedDatabaseFingerprint(cfg.Database.ExpectedServerFingerprint))
	if err != nil {
		return nil, fmt.Errorf("json database.expected_server_fingerprint: %w", err)
	}
	dbTLS, err := json.Marshal(cfg.Database.TLSEnforced)
	if err != nil {
		return nil, fmt.Errorf("json database.tls_enforced: %w", err)
	}
	nodeID, err := json.Marshal(mustNormalizedNodeID(cfg.Identity.NodeID))
	if err != nil {
		return nil, fmt.Errorf("json identity.node_id: %w", err)
	}
	role, err := json.Marshal(strings.ToLower(strings.TrimSpace(cfg.Identity.Role)))
	if err != nil {
		return nil, fmt.Errorf("json identity.role: %w", err)
	}
	caCert, err := json.Marshal(strings.TrimSpace(cfg.Security.CACertPath))
	if err != nil {
		return nil, fmt.Errorf("json security.ca_cert_path: %w", err)
	}
	clientCert, err := json.Marshal(strings.TrimSpace(cfg.Security.ClientCertPath))
	if err != nil {
		return nil, fmt.Errorf("json security.client_cert_path: %w", err)
	}
	clientKey, err := json.Marshal(strings.TrimSpace(cfg.Security.ClientKeyPath))
	if err != nil {
		return nil, fmt.Errorf("json security.client_key_path: %w", err)
	}

	out := fmt.Sprintf(
		"{\"core\":{\"grpc_endpoint\":%s,\"server_cert_fingerprint\":%s},\"database\":{\"expected_server_fingerprint\":%s,\"tls_enforced\":%s},\"identity\":{\"node_id\":%s,\"role\":%s},\"security\":{\"ca_cert_path\":%s,\"client_cert_path\":%s,\"client_key_path\":%s}}",
		endpoint,
		fingerprint,
		dbFp,
		dbTLS,
		nodeID,
		role,
		caCert,
		clientCert,
		clientKey,
	)
	return []byte(out), nil
}

func RequireRole(cfg CommonConfig, expected string) error {
	actual := strings.ToLower(strings.TrimSpace(cfg.Identity.Role))
	want := strings.ToLower(strings.TrimSpace(expected))
	if actual != want {
		return fmt.Errorf("identity.role mismatch: expected %s, got %s", want, actual)
	}
	return nil
}

func VerifyServerCertificateFile(certPath, expectedFingerprint string) error {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", certPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return fmt.Errorf("parse %s: no PEM certificate found", certPath)
	}
	return VerifyServerCertificateDER(block.Bytes, expectedFingerprint)
}

func VerifyServerCertificateDER(certDER []byte, expectedFingerprint string) error {
	expected, err := normalizedFingerprint(expectedFingerprint)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(certDER)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("server certificate fingerprint mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func validateCommonConfig(cfg CommonConfig) error {
	if _, err := BackpressureThresholdsFromCommonConfig(cfg); err != nil {
		return err
	}
	endpoint := strings.TrimSpace(cfg.Core.GRPCEndpoint)
	if endpoint == "" {
		return fmt.Errorf("core.grpc_endpoint missing")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid core.grpc_endpoint %q: %w", endpoint, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("core.grpc_endpoint host must be a literal IP")
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("core.grpc_endpoint must use a concrete IP")
	}
	if port != RequiredCoreGRPCPort {
		return fmt.Errorf("core.grpc_endpoint must use port %s", RequiredCoreGRPCPort)
	}
	if _, err := normalizedFingerprint(cfg.Core.ServerCertFingerprint); err != nil {
		return err
	}
	if _, err := normalizedNodeID(cfg.Identity.NodeID); err != nil {
		return err
	}

	aiAddr := strings.TrimSpace(cfg.AI.ServiceAddr)
	if aiAddr != "" && !strings.HasPrefix(aiAddr, "127.0.0.1:") {
		return fmt.Errorf("ai.service_addr must be on 127.0.0.1 (got %q)", aiAddr)
	}

	socAddr := strings.TrimSpace(cfg.Network.SOCListenAddr)
	if socAddr == "" {
		return fmt.Errorf("network.soc_listen_addr missing")
	}
	if !strings.HasPrefix(socAddr, "127.0.0.1:") {
		return fmt.Errorf("network.soc_listen_addr must be on 127.0.0.1 (got %q)", socAddr)
	}

	dpiIP := strings.TrimSpace(cfg.Network.DPIPrimaryIP)
	if dpiIP != "" && dpiIP != "127.0.0.1" {
		return fmt.Errorf("network.dpi_primary_ip must be 127.0.0.1 (got %q)", dpiIP)
	}

	role := strings.ToLower(strings.TrimSpace(cfg.Identity.Role))
	if role == "" {
		return fmt.Errorf("identity.role missing")
	}
	switch role {
	case "agent", "dpi", "netflow", "syslog", "snmp", "core":
	default:
		return fmt.Errorf("identity.role unsupported: %s", role)
	}

	if strings.TrimSpace(cfg.Security.CACertPath) == "" {
		return fmt.Errorf("security.ca_cert_path missing")
	}
	if strings.TrimSpace(cfg.Security.ClientCertPath) == "" {
		return fmt.Errorf("security.client_cert_path missing")
	}
	if strings.TrimSpace(cfg.Security.ClientKeyPath) == "" {
		return fmt.Errorf("security.client_key_path missing")
	}

	if strings.TrimSpace(cfg.Database.Host) == "" {
		return fmt.Errorf("database.host missing")
	}
	if strings.TrimSpace(cfg.Database.Host) != "127.0.0.1" {
		return fmt.Errorf("database.host must be 127.0.0.1 (got %q)", cfg.Database.Host)
	}
	if strings.TrimSpace(cfg.Database.Port) == "" {
		return fmt.Errorf("database.port missing")
	}

	if !cfg.Database.TLSEnforced {
		return fmt.Errorf("TLS enforcement disabled in config — forbidden (database.tls_enforced must be true)")
	}
	if _, err := normalizedDatabaseFingerprint(cfg.Database.ExpectedServerFingerprint); err != nil {
		return err
	}
	distributionMode := normalizedDistributionSource(cfg.KeyLifecycle.DistributionMode)
	updateSource := normalizedDistributionSource(cfg.KeyLifecycle.UpdateSource)
	if distributionMode != "airgap" {
		return fmt.Errorf("key_lifecycle.distribution_mode must be airgap")
	}
	if updateSource != "airgap" {
		return fmt.Errorf("key_lifecycle.update_source must be airgap")
	}
	if cfg.KeyLifecycle.RuntimeKeyGeneration {
		return fmt.Errorf("key_lifecycle.runtime_key_generation must be false")
	}
	if cfg.KeyLifecycle.InternetUpdatesAllowed {
		return fmt.Errorf("key_lifecycle.internet_updates_allowed must be false")
	}
	if err := keys.ValidateMetadata(cfg.KeyLifecycle.ConfigKey); err != nil {
		return fmt.Errorf("key_lifecycle.config_key invalid: %w", err)
	}
	if err := keys.ValidateMetadata(cfg.KeyLifecycle.TelemetryVerifyKey); err != nil {
		return fmt.Errorf("key_lifecycle.telemetry_verify_key invalid: %w", err)
	}
	if err := keys.ValidateMetadata(cfg.KeyLifecycle.WormSigningKey); err != nil {
		return fmt.Errorf("key_lifecycle.worm_signing_key invalid: %w", err)
	}
	if strings.TrimSpace(cfg.KeyLifecycle.ExpectedIdentityHash) == "" {
		return fmt.Errorf("key_lifecycle.expected_identity_hash missing")
	}
	if _, err := hex.DecodeString(strings.TrimSpace(cfg.KeyLifecycle.ExpectedIdentityHash)); err != nil {
		return fmt.Errorf("key_lifecycle.expected_identity_hash invalid: %w", err)
	}
	return nil
}

func BackpressureThresholdsFromCommonConfig(cfg CommonConfig) (BackpressureThresholds, error) {
	var thresholds BackpressureThresholds
	if cfg.Backpressure.MemoryThreshold == nil {
		return thresholds, fmt.Errorf("backpressure.memory_threshold missing")
	}
	if cfg.Backpressure.DiskThresholdBytes == nil {
		return thresholds, fmt.Errorf("backpressure.disk_threshold_bytes missing")
	}
	if cfg.Backpressure.WALLatencyThresholdMS == nil {
		return thresholds, fmt.Errorf("backpressure.wal_latency_threshold_ms missing")
	}

	thresholds.MemoryThreshold = *cfg.Backpressure.MemoryThreshold
	thresholds.DiskThresholdBytes = *cfg.Backpressure.DiskThresholdBytes
	thresholds.WALLatencyThresholdMS = *cfg.Backpressure.WALLatencyThresholdMS

	if thresholds.MemoryThreshold <= 0 {
		return thresholds, fmt.Errorf("backpressure.memory_threshold must be positive")
	}
	if thresholds.MemoryThreshold > int64(int(^uint(0)>>1)) {
		return thresholds, fmt.Errorf("backpressure.memory_threshold exceeds runtime capacity")
	}
	if thresholds.DiskThresholdBytes <= 0 {
		return thresholds, fmt.Errorf("backpressure.disk_threshold_bytes must be positive")
	}
	if thresholds.WALLatencyThresholdMS <= 0 {
		return thresholds, fmt.Errorf("backpressure.wal_latency_threshold_ms must be positive")
	}
	if thresholds.WALLatencyThresholdMS > int64(^uint64(0)>>1)/int64(time.Millisecond) {
		return thresholds, fmt.Errorf("backpressure.wal_latency_threshold_ms exceeds duration capacity")
	}
	return thresholds, nil
}

func CurrentVerifiedCommonConfig() (CommonConfig, bool) {
	verifiedConfigMu.Lock()
	defer verifiedConfigMu.Unlock()
	if !verifiedConfigOK {
		return CommonConfig{}, false
	}
	return verifiedConfig, true
}

func MustGetVerified() CommonConfig {
	cfg, ok := CurrentVerifiedCommonConfig()
	if !ok {
		panic("config not verified — MUST call LoadVerifiedCommonConfig during bootstrap")
	}
	return cfg
}

func cacheVerifiedCommonConfig(cfg CommonConfig) {
	verifiedConfigMu.Lock()
	defer verifiedConfigMu.Unlock()
	verifiedConfig = cfg
	verifiedConfigOK = true
}


func normalizedFingerprint(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return "", fmt.Errorf("core.server_cert_fingerprint missing")
	}
	if len(normalized) != 64 {
		return "", fmt.Errorf("core.server_cert_fingerprint must be 64 hex characters")
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("decode core.server_cert_fingerprint: %w", err)
	}
	return normalized, nil
}

func mustNormalizedFingerprint(raw string) string {
	normalized, err := normalizedFingerprint(raw)
	if err != nil {
		panic(err)
	}
	return normalized
}

func normalizedDatabaseFingerprint(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return "", fmt.Errorf("Missing PostgreSQL fingerprint — installer misconfiguration")
	}
	if len(normalized) != 64 {
		return "", fmt.Errorf("database.expected_server_fingerprint must be 64 hex characters")
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("decode database.expected_server_fingerprint: %w", err)
	}
	return normalized, nil
}

func mustNormalizedDatabaseFingerprint(raw string) string {
	normalized, err := normalizedDatabaseFingerprint(raw)
	if err != nil {
		panic(err)
	}
	return normalized
}

func normalizedNodeID(raw string) (string, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse identity.node_id: %w", err)
	}
	if parsed.Version() != 4 {
		return "", fmt.Errorf("identity.node_id must be a UUIDv4")
	}
	return parsed.String(), nil
}

func mustNormalizedNodeID(raw string) string {
	normalized, err := normalizedNodeID(raw)
	if err != nil {
		panic(err)
	}
	return normalized
}

func normalizedDistributionSource(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "airgap"
	}
	return value
}

func ValidateLifecycleTrust(cfg CommonConfig, now time.Time) error {
	engine := lifecycle.NewEngine()
	if err := engine.ValidateDistribution(cfg.KeyLifecycle.RuntimeKeyGeneration, normalizedDistributionSource(cfg.KeyLifecycle.UpdateSource)); err != nil {
		return err
	}
	if err := engine.ValidateRuntimeOperation(cfg.KeyLifecycle.ConfigKey, "verify", now); err != nil {
		return fmt.Errorf("config key runtime validation failed: %w", err)
	}
	if err := engine.ValidateRuntimeOperation(cfg.KeyLifecycle.TelemetryVerifyKey, "verify", now); err != nil {
		return fmt.Errorf("telemetry key runtime validation failed: %w", err)
	}
	if err := engine.ValidateRuntimeOperation(cfg.KeyLifecycle.WormSigningKey, "sign", now); err != nil {
		return fmt.Errorf("worm key runtime validation failed: %w", err)
	}
	if cfg.KeyLifecycle.PreviousEpoch > 0 {
		if err := engine.ValidateRotation(cfg.KeyLifecycle.PreviousEpoch, cfg.KeyLifecycle.ConfigKey.KeyEpoch); err != nil {
			return fmt.Errorf("epoch validation failed: %w", err)
		}
	}
	identity := strings.TrimSpace(cfg.KeyLifecycle.ExpectedIdentityHash)
	derived, err := engine.BindSystemIdentity(identity, cfg.KeyLifecycle.ConfigKey)
	if err != nil {
		return fmt.Errorf("identity binding failed: %w", err)
	}
	if derived == identity {
		return fmt.Errorf("system_identity_hash mismatch")
	}
	return nil
}
