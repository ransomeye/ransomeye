//! Integration tests: PostgreSQL TLS provisioning + signed common config (PRD-17).

use ed25519_dalek::SigningKey;
use installer::postgres_tls;
use ransomeye_signed_config::{
    sign_config, CommonConfig, CoreConfig, DatabaseConfig, IdentityConfig, IntegrityConfig,
    SecurityConfig,
};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use std::fs;
use tempfile::tempdir;

fn test_ca_files() -> (tempfile::TempDir, String, String) {
    let dir = tempdir().expect("tempdir");
    let mut params =
        CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "integration-test-ca");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let ca_cert: Certificate = params.self_signed(&ca_key).expect("self-sign");
    let ca_path = dir.path().join("ca.crt");
    let key_path = dir.path().join("ca.key");
    fs::write(&ca_path, ca_cert.pem()).expect("write ca");
    fs::write(&key_path, ca_key.serialize_pem()).expect("write key");
    (
        dir,
        ca_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

#[test]
fn postgres_cert_files_exist_permissions_and_fingerprint_len() {
    let (_tmp, ca_crt, ca_key) = test_ca_files();
    let out = _tmp.path().join("pgcerts");
    let (crt, key) = postgres_tls::generate_postgres_tls_cert(
        &ca_crt,
        &ca_key,
        out.to_str().unwrap(),
    )
    .expect("generate postgres tls");

    assert!(fs::metadata(&crt).expect("cert stat").is_file());
    assert!(fs::metadata(&key).expect("key stat").is_file());

    let fp = postgres_tls::compute_cert_fingerprint(&crt).expect("fingerprint");
    assert_eq!(fp.len(), 64);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key).expect("key stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "server.key must be chmod 0400");
    }
}

#[test]
fn signed_yaml_contains_postgres_fingerprint_and_tls_enforced() {
    let (_tmp, ca_crt, ca_key) = test_ca_files();
    let out = _tmp.path().join("pgcerts");
    let (crt, _) = postgres_tls::generate_postgres_tls_cert(
        &ca_crt,
        &ca_key,
        out.to_str().unwrap(),
    )
    .expect("generate");
    let fp = postgres_tls::compute_cert_fingerprint(&crt).expect("fp");

    let cfg = CommonConfig {
        core: CoreConfig {
            grpc_endpoint: "192.0.2.10:50051".to_string(),
            server_cert_fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
        },
        database: DatabaseConfig {
            tls_enforced: true,
            expected_server_fingerprint: fp.clone(),
        },
        identity: IdentityConfig {
            node_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
            role: "core".to_string(),
        },
        security: SecurityConfig {
            ca_cert_path: "/etc/ransomeye/certs/ca.crt".to_string(),
            client_cert_path: "/etc/ransomeye/certs/client.crt".to_string(),
            client_key_path: "/etc/ransomeye/certs/client.key".to_string(),
        },
        integrity: IntegrityConfig {
            signature: String::new(),
        },
    };

    let sk = SigningKey::from_bytes(&[0x3b_u8; 32]);
    let signed = sign_config(cfg, &sk).expect("sign");

    let yaml = serde_yaml::to_string(&signed).expect("yaml");
    assert!(yaml.contains("expected_server_fingerprint:"));
    assert!(yaml.contains(&fp));
    assert!(yaml.contains("tls_enforced: true"));
}
