use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ransomeye_signed_config::{
    certificate_fingerprint_hex, load_intermediate_signing_key, load_yaml_file, sign_config,
    write_yaml_file, CANONICAL_CA_CERT_PATH, CANONICAL_CLIENT_CERT_PATH, CANONICAL_CLIENT_KEY_PATH,
    CANONICAL_SERVER_CERT_PATH, INSTALLED_COMMON_CONFIG_PATH, INTERMEDIATE_CA_KEY_PATH,
    PREP_COMMON_CONFIG_PATH,
};

const OBSOLETE_VENDOR_SIGNING_KEY_PATH: &str = "/etc/ransomeye/vendor_build_signing.key";
const OBSOLETE_VENDOR_PUBLIC_KEY_PATH: &str = "/etc/ransomeye/vendor_build_signing.pub";

pub fn install_signed_common_config(postgres_server_fingerprint_hex: &str) -> Result<(), String> {
    if postgres_server_fingerprint_hex.len() != 64 {
        return Err(format!(
            "PostgreSQL server fingerprint must be 64 hex chars, got {}",
            postgres_server_fingerprint_hex.len()
        ));
    }
    let fp_lower = postgres_server_fingerprint_hex.trim().to_ascii_lowercase();
    if hex::decode(&fp_lower).is_err() {
        return Err("PostgreSQL server fingerprint must be valid hex".to_string());
    }

    let mut config = load_yaml_file(Path::new(PREP_COMMON_CONFIG_PATH))
        .map_err(|e| format!("load prep common config: {e}"))?
        .normalized_for_install();
    let signing_key = load_intermediate_signing_key(Path::new(INTERMEDIATE_CA_KEY_PATH))
        .map_err(|e| format!("load intermediate CA signing key: {e}"))?;

    ensure_parent_dir(CANONICAL_CA_CERT_PATH)?;
    ensure_parent_dir(INSTALLED_COMMON_CONFIG_PATH)?;
    copy_canonical_cert("/etc/ransomeye/ca.crt", CANONICAL_CA_CERT_PATH)?;
    copy_canonical_cert("/etc/ransomeye/client.crt", CANONICAL_CLIENT_CERT_PATH)?;
    copy_canonical_cert("/etc/ransomeye/client.key", CANONICAL_CLIENT_KEY_PATH)?;

    config.core.server_cert_fingerprint =
        certificate_fingerprint_hex(Path::new(CANONICAL_SERVER_CERT_PATH))
            .map_err(|e| format!("compute server certificate fingerprint: {e}"))?;

    config.database.tls_enforced = true;
    config.database.expected_server_fingerprint = fp_lower;
    if !config.database.tls_enforced {
        return Err(
            "FATAL: database.tls_enforced must be true after PostgreSQL TLS provisioning".to_string(),
        );
    }

    config = sign_config(config, &signing_key).map_err(|e| format!("sign common config: {e}"))?;

    write_yaml_file(Path::new(INSTALLED_COMMON_CONFIG_PATH), &config)
        .map_err(|e| format!("write installed common config: {e}"))?;
    fs::set_permissions(
        INSTALLED_COMMON_CONFIG_PATH,
        fs::Permissions::from_mode(0o400),
    )
    .map_err(|e| format!("chmod {}: {}", INSTALLED_COMMON_CONFIG_PATH, e))?;

    remove_obsolete_file(OBSOLETE_VENDOR_SIGNING_KEY_PATH)?;
    remove_obsolete_file(OBSOLETE_VENDOR_PUBLIC_KEY_PATH)?;

    Ok(())
}

fn ensure_parent_dir(path: &str) -> Result<(), String> {
    let parent = Path::new(path)
        .parent()
        .ok_or_else(|| format!("no parent directory for {}", path))?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {}", parent.display(), e))
}

fn copy_canonical_cert(src: &str, dst: &str) -> Result<(), String> {
    if !Path::new(src).is_file() {
        return Err(format!("required source certificate missing: {}", src));
    }
    fs::copy(src, dst).map_err(|e| format!("copy {} -> {}: {}", src, dst, e))?;
    fs::set_permissions(dst, fs::Permissions::from_mode(0o400))
        .map_err(|e| format!("chmod {}: {}", dst, e))?;
    Ok(())
}

fn remove_obsolete_file(path: &str) -> Result<(), String> {
    if !Path::new(path).exists() {
        return Ok(());
    }
    fs::remove_file(path).map_err(|e| format!("remove {}: {}", path, e))
}
