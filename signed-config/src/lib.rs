use std::env;
use std::fs;
use std::io::BufReader;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

pub const PREP_COMMON_CONFIG_PATH: &str = "/opt/ransomeye/prep/common.yaml";
pub const INSTALLED_COMMON_CONFIG_PATH: &str = "/etc/ransomeye/config/common.yaml";
pub const INTERMEDIATE_CA_KEY_PATH: &str = "/etc/ransomeye/pki/intermediate_ca.key";
pub const INTERMEDIATE_CA_CERT_PATH: &str = "/etc/ransomeye/pki/intermediate_ca.crt";
pub const CANONICAL_CA_CERT_PATH: &str = "/etc/ransomeye/certs/ca.crt";
pub const CANONICAL_CLIENT_CERT_PATH: &str = "/etc/ransomeye/certs/client.crt";
pub const CANONICAL_CLIENT_KEY_PATH: &str = "/etc/ransomeye/certs/client.key";
pub const CANONICAL_SERVER_CERT_PATH: &str = "/etc/ransomeye/server.crt";
pub const REQUIRED_CORE_GRPC_PORT: u16 = 50051;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommonConfig {
    pub core: CoreConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    pub identity: IdentityConfig,
    pub security: SecurityConfig,
    pub integrity: IntegrityConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DatabaseConfig {
    pub tls_enforced: bool,
    pub expected_server_fingerprint: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            tls_enforced: false,
            expected_server_fingerprint: String::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoreConfig {
    pub grpc_endpoint: String,
    pub server_cert_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityConfig {
    pub node_id: String,
    pub role: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecurityConfig {
    pub ca_cert_path: String,
    pub client_cert_path: String,
    pub client_key_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntegrityConfig {
    pub signature: String,
}

impl CommonConfig {
    pub fn normalized_for_install(mut self) -> Self {
        self.security.ca_cert_path = CANONICAL_CA_CERT_PATH.to_string();
        self.security.client_cert_path = CANONICAL_CLIENT_CERT_PATH.to_string();
        self.security.client_key_path = CANONICAL_CLIENT_KEY_PATH.to_string();
        self.integrity.signature.clear();
        self
    }
}

pub fn load_yaml_file(path: &Path) -> Result<CommonConfig> {
    let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml::from_slice(&raw).with_context(|| format!("parse {}", path.display()))
}

pub fn write_yaml_file(path: &Path, config: &CommonConfig) -> Result<()> {
    let raw = serde_yaml::to_string(config).context("serialize signed common config")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}

pub fn load_verified_config(config_path: &Path, signing_cert_path: &Path) -> Result<CommonConfig> {
    let resolved_config_path = resolve_runtime_config_path(config_path);
    let config = load_yaml_file(resolved_config_path.as_path())?;
    validate_unsigned_fields(&config)?;
    if dev_mode_enabled() {
        return Ok(config);
    }
    let verifying_key = load_verifying_key_from_cert(signing_cert_path)?;
    verify_config(&config, &verifying_key)?;
    Ok(config)
}

fn resolve_runtime_config_path(config_path: &Path) -> std::path::PathBuf {
    if let Ok(raw) = env::var("RANSOMEYE_CONFIG") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    if let Ok(raw) = env::var("RANSOMEYE_CONFIG_PATH") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    config_path.to_path_buf()
}

fn dev_mode_enabled() -> bool {
    env::var("RANSOMEYE_DEV_MODE")
        .map(|value| value.trim() == "true")
        .unwrap_or(false)
}

pub fn sign_config(mut config: CommonConfig, signing_key: &SigningKey) -> Result<CommonConfig> {
    validate_unsigned_fields(&config)?;
    config.integrity.signature.clear();

    let canonical = canonical_json_bytes(&config)?;
    let digest = Sha256::digest(&canonical);
    let signature = signing_key.sign(digest.as_ref());
    config.integrity.signature = hex::encode(signature.to_bytes());
    Ok(config)
}

pub fn verify_config(config: &CommonConfig, verifying_key: &VerifyingKey) -> Result<()> {
    validate_unsigned_fields(config)?;

    let sig_hex = config.integrity.signature.trim();
    if sig_hex.is_empty() {
        return Err(anyhow!("integrity.signature missing"));
    }
    let sig_bytes = hex::decode(sig_hex).context("decode config signature hex")?;
    if sig_bytes.len() != 64 {
        return Err(anyhow!("config signature must be 64 bytes"));
    }
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| anyhow!("parse config signature: {}", e))?;

    let canonical = canonical_json_bytes(config)?;
    let digest = Sha256::digest(&canonical);
    verifying_key
        .verify(digest.as_ref(), &signature)
        .map_err(|e| anyhow!("verify config signature: {}", e))
}

pub fn canonical_json_bytes(config: &CommonConfig) -> Result<Vec<u8>> {
    validate_unsigned_fields(config)?;

    let endpoint = serde_json::to_string(config.core.grpc_endpoint.trim())
        .context("json quote core.grpc_endpoint")?;
    let fingerprint = serde_json::to_string(&normalized_fingerprint(
        config.core.server_cert_fingerprint.trim(),
    )?)
    .context("json quote core.server_cert_fingerprint")?;
    let db_fp = serde_json::to_string(&normalized_database_fingerprint(
        config.database.expected_server_fingerprint.trim(),
    )?)
    .context("json quote database.expected_server_fingerprint")?;
    let db_tls = serde_json::to_string(&config.database.tls_enforced)
        .context("json database.tls_enforced")?;
    let node_id = serde_json::to_string(&normalized_node_id(config.identity.node_id.trim())?)
        .context("json quote identity.node_id")?;
    let role_value = config.identity.role.trim().to_ascii_lowercase();
    let role = serde_json::to_string(role_value.as_str()).context("json quote identity.role")?;
    let ca_cert = serde_json::to_string(config.security.ca_cert_path.trim())
        .context("json quote security.ca_cert_path")?;
    let client_cert = serde_json::to_string(config.security.client_cert_path.trim())
        .context("json quote security.client_cert_path")?;
    let client_key = serde_json::to_string(config.security.client_key_path.trim())
        .context("json quote security.client_key_path")?;

    Ok(format!(
        "{{\"core\":{{\"grpc_endpoint\":{endpoint},\"server_cert_fingerprint\":{fingerprint}}},\"database\":{{\"expected_server_fingerprint\":{db_fp},\"tls_enforced\":{db_tls}}},\"identity\":{{\"node_id\":{node_id},\"role\":{role}}},\"security\":{{\"ca_cert_path\":{ca_cert},\"client_cert_path\":{client_cert},\"client_key_path\":{client_key}}}}}"
    )
    .into_bytes())
}

pub fn load_intermediate_signing_key(path: &Path) -> Result<SigningKey> {
    let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if let Ok(pem) = std::str::from_utf8(&raw) {
        if let Ok(key) = SigningKey::from_pkcs8_pem(pem) {
            return Ok(key);
        }
    }
    SigningKey::from_pkcs8_der(&raw).map_err(|e| anyhow!("parse Ed25519 PKCS#8 key: {}", e))
}

pub fn load_verifying_key_from_cert(path: &Path) -> Result<VerifyingKey> {
    let cert_der = first_pem_cert(path)?;
    verifying_key_from_cert_der(cert_der.as_ref())
}

pub fn verifying_key_from_cert_der(cert_der: &[u8]) -> Result<VerifyingKey> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| anyhow!("parse x509 cert: {:?}", e))?;
    let key_bytes = cert.public_key().subject_public_key.data.as_ref();
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("certificate public key must be Ed25519 (32 bytes)"))?;
    VerifyingKey::from_bytes(&key).map_err(|e| anyhow!("parse Ed25519 cert public key: {}", e))
}

pub fn certificate_fingerprint_hex(path: &Path) -> Result<String> {
    let cert_der = first_pem_cert(path)?;
    Ok(sha256_hex(cert_der.as_ref()))
}

pub fn verify_server_fingerprint(cert_der: &[u8], expected_hex: &str) -> Result<()> {
    let expected = normalized_fingerprint(expected_hex)?;
    let actual = sha256_hex(cert_der);
    if actual != expected {
        return Err(anyhow!(
            "server certificate fingerprint mismatch: expected {}, got {}",
            expected,
            actual
        ));
    }
    Ok(())
}

pub fn assert_expected_role(config: &CommonConfig, expected_role: &str) -> Result<()> {
    let actual = config.identity.role.trim().to_ascii_lowercase();
    let expected = expected_role.trim().to_ascii_lowercase();
    if actual != expected {
        return Err(anyhow!(
            "identity.role mismatch: expected {}, got {}",
            expected,
            actual
        ));
    }
    Ok(())
}

pub fn preflight_tls_attestation(config: &CommonConfig) -> Result<()> {
    validate_unsigned_fields(config)?;

    let addr = SocketAddr::from_str(config.core.grpc_endpoint.trim())
        .context("parse signed core grpc endpoint")?;
    let ca_certs = load_pem_certs(Path::new(config.security.ca_cert_path.trim()))
        .context("load CA certificate(s)")?;
    let client_certs = load_pem_certs(Path::new(config.security.client_cert_path.trim()))
        .context("load client certificate(s)")?;
    let client_key = load_private_key(Path::new(config.security.client_key_path.trim()))
        .context("load client private key")?;

    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(ca_certs);
    if added == 0 {
        return Err(anyhow!(
            "no trust anchors loaded from {} (ignored {})",
            config.security.ca_cert_path.trim(),
            ignored
        ));
    }

    let mut client_config =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certs, client_key)
            .context("build mTLS client config")?;
    client_config.alpn_protocols.push(b"h2".to_vec());

    let server_name = ServerName::IpAddress(addr.ip().into());
    let mut conn = ClientConnection::new(Arc::new(client_config), server_name)
        .context("create TLS client connection")?;
    let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .with_context(|| format!("connect {}", addr))?;
    tcp.set_nodelay(true).context("set TCP_NODELAY")?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .context("set read timeout")?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .context("set write timeout")?;

    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)
            .context("complete TLS handshake")?;
    }
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(anyhow!(
            "core TLS attestation negotiated non-TLS1.3 protocol"
        ));
    }

    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("server certificate missing from TLS handshake"))?;
    let leaf = peer_certs
        .first()
        .ok_or_else(|| anyhow!("server certificate chain empty"))?;
    verify_server_fingerprint(leaf.as_ref(), config.core.server_cert_fingerprint.trim())
}

fn first_pem_cert(path: &Path) -> Result<rustls::pki_types::CertificateDer<'static>> {
    let certs = load_pem_certs(path)?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no x509 certificates found in {}", path.display()))
}

fn load_pem_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut reader = BufReader::new(raw.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse certificates from {}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut reader = BufReader::new(raw.as_slice());
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse private key from {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

fn normalized_database_fingerprint(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(anyhow!(
            "Missing PostgreSQL fingerprint — installer misconfiguration"
        ));
    }
    if normalized.len() != 64 {
        return Err(anyhow!(
            "database.expected_server_fingerprint must be 64 hex characters"
        ));
    }
    hex::decode(&normalized).context("decode database.expected_server_fingerprint hex")?;
    Ok(normalized)
}

fn normalized_fingerprint(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(anyhow!("core.server_cert_fingerprint missing"));
    }
    if normalized.len() != 64 {
        return Err(anyhow!(
            "core.server_cert_fingerprint must be 64 hex characters"
        ));
    }
    hex::decode(&normalized).context("decode core.server_cert_fingerprint hex")?;
    Ok(normalized)
}

fn normalized_node_id(raw: &str) -> Result<String> {
    let parsed = Uuid::parse_str(raw).context("parse identity.node_id")?;
    if parsed.get_version_num() != 4 {
        return Err(anyhow!("identity.node_id must be a UUIDv4"));
    }
    Ok(parsed.hyphenated().to_string())
}

fn validate_unsigned_fields(config: &CommonConfig) -> Result<()> {
    let endpoint = config.core.grpc_endpoint.trim();
    if endpoint.is_empty() {
        return Err(anyhow!("core.grpc_endpoint missing"));
    }
    let addr = SocketAddr::from_str(endpoint)
        .with_context(|| format!("invalid core.grpc_endpoint {}", endpoint))?;
    if addr.port() != REQUIRED_CORE_GRPC_PORT {
        return Err(anyhow!(
            "core.grpc_endpoint must use port {}",
            REQUIRED_CORE_GRPC_PORT
        ));
    }
    if addr.ip().is_unspecified() {
        return Err(anyhow!("core.grpc_endpoint must use a concrete IP"));
    }

    normalized_fingerprint(config.core.server_cert_fingerprint.trim())?;
    normalized_node_id(config.identity.node_id.trim())?;

    let role = config.identity.role.trim().to_ascii_lowercase();
    if role.is_empty() {
        return Err(anyhow!("identity.role missing"));
    }
    match role.as_str() {
        "agent" | "dpi" | "netflow" | "syslog" | "snmp" | "core" => {}
        other => {
            return Err(anyhow!("identity.role unsupported: {}", other));
        }
    }

    if config.security.ca_cert_path.trim().is_empty() {
        return Err(anyhow!("security.ca_cert_path missing"));
    }
    if config.security.client_cert_path.trim().is_empty() {
        return Err(anyhow!("security.client_cert_path missing"));
    }
    if config.security.client_key_path.trim().is_empty() {
        return Err(anyhow!("security.client_key_path missing"));
    }
    if !config.database.tls_enforced {
        return Err(anyhow!(
            "TLS enforcement disabled in config — forbidden (database.tls_enforced must be true)"
        ));
    }
    normalized_database_fingerprint(config.database.expected_server_fingerprint.trim())?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_json_bytes, sign_config, verify_config, verify_server_fingerprint, CommonConfig,
        CoreConfig, DatabaseConfig, IdentityConfig, IntegrityConfig, SecurityConfig,
    };
    use ed25519_dalek::SigningKey;

    fn config() -> CommonConfig {
        CommonConfig {
            core: CoreConfig {
                grpc_endpoint: "192.0.2.10:50051".to_string(),
                server_cert_fingerprint:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            },
            database: DatabaseConfig {
                tls_enforced: true,
                expected_server_fingerprint:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            },
            identity: IdentityConfig {
                node_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                role: "agent".to_string(),
            },
            security: SecurityConfig {
                ca_cert_path: "/etc/ransomeye/certs/ca.crt".to_string(),
                client_cert_path: "/etc/ransomeye/certs/client.crt".to_string(),
                client_key_path: "/etc/ransomeye/certs/client.key".to_string(),
            },
            integrity: IntegrityConfig {
                signature: "<ed25519_signature>".to_string(),
            },
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    #[test]
    fn tamper_fails_verification() {
        let signing_key = key();
        let mut signed = sign_config(config(), &signing_key).expect("sign");
        verify_config(&signed, &signing_key.verifying_key()).expect("verify");

        signed.core.grpc_endpoint = "192.0.2.11:50051".to_string();
        assert!(verify_config(&signed, &signing_key.verifying_key()).is_err());
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let cfg = config();
        let a = canonical_json_bytes(&cfg).expect("canonical a");
        let b = canonical_json_bytes(&cfg).expect("canonical b");
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_mismatch_fails() {
        let cert_der = b"fake-core-cert";
        let mismatch = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(verify_server_fingerprint(cert_der, mismatch).is_err());
    }
}
