//! PostgreSQL server TLS provisioning for the Rust installer (PRD-17 / PRD-14).
//! Issues a leaf certificate signed by the RansomEye intermediate CA using native Rust (rcgen).

use std::fmt;
use std::fs;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls_pemfile::certs;
use sha2::{Digest, Sha256};

/// Errors from PostgreSQL TLS file I/O and certificate operations.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Rcgen(rcgen::Error),
    MissingCertificatePem,
    PemParse(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Rcgen(e) => write!(f, "{e}"),
            Error::MissingCertificatePem => write!(f, "no PEM certificate found in CA file"),
            Error::PemParse(e) => write!(f, "PEM parse error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Rcgen(e) => Some(e),
            Error::PemParse(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

impl From<rcgen::Error> for Error {
    fn from(value: rcgen::Error) -> Self {
        Error::Rcgen(value)
    }
}

fn first_cert_der_from_pem_file(path: &str) -> Result<rustls_pki_types::CertificateDer<'static>, Error> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::PemParse)?;
    certs
        .into_iter()
        .next()
        .ok_or(Error::MissingCertificatePem)
}

/// Load the intermediate CA, issue a PostgreSQL server leaf (P-256 ECDSA, TLS Web Server),
/// and write PEM material to `output_dir/server.crt` and `output_dir/server.key`.
///
/// Subject CN is `postgres` (server identity; OS user is `postgres` per PRD-17 V0); SAN includes `127.0.0.1`. The leaf private key is chmod `0400`.
pub fn generate_postgres_tls_cert(
    ca_cert_path: &str,
    ca_key_path: &str,
    output_dir: &str,
) -> Result<(String, String), Error> {
    let ca_key_pem = fs::read_to_string(ca_key_path)?;
    let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(Error::Rcgen)?;

    let ca_der = first_cert_der_from_pem_file(ca_cert_path)?;
    let ca_import_params = CertificateParams::from_ca_cert_der(&ca_der).map_err(Error::Rcgen)?;
    let ca_cert = ca_import_params.self_signed(&ca_key).map_err(Error::Rcgen)?;

    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "postgres");
    leaf_params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))];
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    leaf_params.not_before = ca_cert.params().not_before;
    leaf_params.not_after = ca_cert.params().not_after;

    let leaf_key =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(Error::Rcgen)?;
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(Error::Rcgen)?;

    let out = Path::new(output_dir);
    fs::create_dir_all(out)?;
    let cert_path: PathBuf = out.join("server.crt");
    let key_path: PathBuf = out.join("server.key");

    fs::write(&cert_path, leaf_cert.pem())?;
    fs::write(&key_path, leaf_key.serialize_pem())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o400))?;
        fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o444))?;
    }

    Ok((
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    ))
}

/// SHA-256 over the first PEM certificate's DER at `cert_path`, lowercase hex (64 characters).
pub fn compute_cert_fingerprint(cert_path: &str) -> Result<String, Error> {
    let der = first_cert_der_from_pem_file(cert_path)?;
    let digest = Sha256::digest(der.as_ref());
    Ok(hex::encode(digest))
}

/// PostgreSQL instance configuration fragment (paths fixed per PRD-17).
pub fn generate_postgres_ssl_config(_cert_dir: &str) -> String {
    "ssl = on\n\
ssl_cert_file = '/opt/ransomeye/postgres/certs/server.crt'\n\
ssl_key_file = '/opt/ransomeye/postgres/certs/server.key'\n\
ssl_min_protocol_version = 'TLSv1.3'\n"
        .to_string()
}

/// Write the SSL snippet alongside PostgreSQL configuration (e.g. `include` from `postgresql.conf`).
pub fn write_postgres_ssl_conf(path: impl AsRef<Path>) -> Result<(), Error> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = generate_postgres_ssl_config("/opt/ransomeye/postgres/certs");
    fs::write(path, body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    use tempfile::tempdir;

    fn test_ca() -> (Certificate, KeyPair, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let mut params =
            CertificateParams::new(Vec::<String>::new()).expect("empty SAN list");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "ransomeye-test-ca");
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_cert = params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();
        let key_pem = ca_key.serialize_pem();
        fs::write(dir.path().join("ca.crt"), ca_pem).unwrap();
        fs::write(dir.path().join("ca.key"), key_pem).unwrap();
        (ca_cert, ca_key, dir)
    }

    #[test]
    fn cert_written_fingerprint_64_and_permissions() {
        let (_ca_cert, _ca_key, tmp) = test_ca();
        let out = tmp.path().join("pg");
        let (crt, key) = generate_postgres_tls_cert(
            tmp.path().join("ca.crt").to_str().unwrap(),
            tmp.path().join("ca.key").to_str().unwrap(),
            out.to_str().unwrap(),
        )
        .expect("generate");

        assert!(Path::new(&crt).is_file());
        assert!(Path::new(&key).is_file());

        let fp = compute_cert_fingerprint(&crt).expect("fp");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&key).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o400);
        }
        let _ = _ca_cert;
        let _ = _ca_key;
    }

    #[test]
    fn ssl_config_snippet_exact() {
        let s = generate_postgres_ssl_config("/ignored");
        assert!(s.contains("ssl = on"));
        assert!(s.contains("'/opt/ransomeye/postgres/certs/server.crt'"));
        assert!(s.contains("'/opt/ransomeye/postgres/certs/server.key'"));
        assert!(s.contains("'TLSv1.3'"));
    }
}
