//! Deterministic runtime directory and identity provisioning (fail-closed).
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Prepared common config consumed by `config_signer` (signed-config crate).
pub const PREP_COMMON_YAML: &str = "/opt/ransomeye/prep/common.yaml";

/// Installed common config (signed YAML written here by `config_signer`; preview copy after prep).
pub const CONFIG_COMMON_YAML: &str = "/etc/ransomeye/config/common.yaml";

/// Default template baked at build time (install-phase fallback).
const DEFAULT_COMMON_YAML: &str = include_str!("../../configs/common.yaml");

const PKI_PATHS: [&str; 7] = [
    "/etc/ransomeye/ca.crt",
    "/etc/ransomeye/pki/intermediate_ca.crt",
    "/etc/ransomeye/pki/intermediate_ca.key",
    "/etc/ransomeye/server.crt",
    "/etc/ransomeye/server.key",
    "/etc/ransomeye/client.crt",
    "/etc/ransomeye/client.key",
];

pub fn assert_exists(path: &str) {
    if !Path::new(path).exists() {
        panic!("[FATAL] missing required path: {}", path);
    }
}

/// TASK 1 — canonical directory tree (plus parents required for install).
pub fn ensure_directory_tree() {
    let dirs = [
        "/etc/ransomeye",
        "/etc/ransomeye/config",
        "/etc/ransomeye/certs",
        "/opt/ransomeye",
        "/opt/ransomeye/core",
        "/opt/ransomeye/core/certs",
        "/etc/ransomeye/pki",
        "/opt/ransomeye/prep",
    ];
    for d in dirs {
        fs::create_dir_all(d).unwrap_or_else(|e| panic!("[FATAL] mkdir {}: {}", d, e));
    }
    fs::set_permissions("/etc/ransomeye", fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("[FATAL] chmod /etc/ransomeye: {}", e));
    println!("[INSTALLER] Runtime directory tree ensured.");
}

fn run_openssl(args: &[&str]) {
    let st = Command::new("openssl")
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("[FATAL] openssl spawn: {}", e));
    if !st.success() {
        panic!("[FATAL] openssl failed: {:?}", args);
    }
}

fn assert_file_mode(path: &str, want: u32) {
    let meta = fs::metadata(path).unwrap_or_else(|e| panic!("[FATAL] stat {}: {}", path, e));
    let mode = meta.permissions().mode() & 0o7777;
    if mode != want {
        panic!(
            "[FATAL] {} permissions want {:o} got {:o}",
            path, want, mode
        );
    }
}

/// Canonical WORM signing seed (Ed25519); raw 32 bytes only (no PEM wrappers; no OpenSSL keygen).
pub const WORM_SIGNING_KEY_PATH: &str = "/etc/ransomeye/worm_signing.key";
const WORM_SIGNING_PUB_PATH: &str = "/etc/ransomeye/worm_signing.pub";

fn chown_root(path: &str) {
    let st = Command::new("chown")
        .args(["root:root", path])
        .status()
        .unwrap_or_else(|e| panic!("[FATAL] chown root:root {}: {}", path, e));
    if !st.success() {
        panic!("[FATAL] chown root:root {} failed", path);
    }
}

fn is_weak_worm_seed(seed: &[u8]) -> bool {
    if seed.len() != 32 {
        return true;
    }
    if seed.iter().all(|&b| b == seed[0]) {
        return true;
    }
    if seed.iter().enumerate().all(|(i, &b)| b == i as u8) {
        return true;
    }
    seed.iter().enumerate().all(|(i, &b)| b == (i + 1) as u8)
}

/// Reject PEM-shaped blobs, zero/sequential test patterns, and non-32-byte material.
fn validate_worm_seed_bytes(seed: &[u8]) {
    if seed.len() != 32 {
        panic!(
            "[FATAL] Legacy WORM key format detected (expected 32-byte raw seed): size {} bytes",
            seed.len()
        );
    }
    const PEM_BEGIN: &[u8] = b"-----BEGIN";
    if seed.starts_with(PEM_BEGIN) {
        panic!("[FATAL] WORM key must be raw bytes only (PEM-like prefix rejected)");
    }
    if is_weak_worm_seed(seed) {
        panic!("[FATAL] WORM key rejected: weak or predictable seed pattern");
    }
}

fn assert_worm_key_seed_len(path: &str) {
    let len = fs::metadata(path)
        .unwrap_or_else(|e| panic!("[FATAL] stat {}: {}", path, e))
        .len();
    if len != 32 {
        panic!(
            "[FATAL] Legacy WORM key format detected (expected 32-byte raw seed): {} (size {} bytes)",
            path, len
        );
    }
    let raw = fs::read(path).unwrap_or_else(|e| panic!("[FATAL] read {}: {}", path, e));
    validate_worm_seed_bytes(&raw);
}

fn signing_key_from_seed_file(path: &str) -> SigningKey {
    let key_bytes =
        fs::read(path).unwrap_or_else(|e| panic!("[FATAL] read {}: {}", path, e));
    validate_worm_seed_bytes(&key_bytes);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key_bytes);
    SigningKey::from_bytes(&seed)
}

fn write_worm_pubkey_raw_from_key(key_path: &str, pub_path: &str) {
    let sk = signing_key_from_seed_file(key_path);
    fs::write(pub_path, sk.verifying_key().as_bytes()).unwrap_or_else(|e| {
        panic!("[FATAL] write {}: {}", pub_path, e);
    });
    chown_root(pub_path);
    fs::set_permissions(pub_path, fs::Permissions::from_mode(0o444))
        .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", pub_path, e));
}

fn assert_worm_pubkey_matches_key(key_path: &str, pub_path: &str) {
    let sk = signing_key_from_seed_file(key_path);
    let vk = sk.verifying_key();
    let want = vk.as_bytes();
    let got = fs::read(pub_path).unwrap_or_else(|e| panic!("[FATAL] read {}: {}", pub_path, e));
    if got.len() != 32 || got.as_slice() != want {
        panic!(
            "[FATAL] {} does not match {} (expected 32-byte Ed25519 public key from seed)",
            pub_path, key_path
        );
    }
}

/// Ed25519 WORM signing **seed** (32 bytes) + raw 32-byte public half for integrity verification.
pub fn provision_worm_signing_if_missing() {
    if Path::new(WORM_SIGNING_KEY_PATH).exists() {
        assert_worm_key_seed_len(WORM_SIGNING_KEY_PATH);
        assert_file_mode(WORM_SIGNING_KEY_PATH, 0o400);
        chown_root(WORM_SIGNING_KEY_PATH);

        if Path::new(WORM_SIGNING_PUB_PATH).exists() {
            assert_worm_pubkey_matches_key(WORM_SIGNING_KEY_PATH, WORM_SIGNING_PUB_PATH);
            println!("[INSTALLER] WORM signing material already present.");
            return;
        }

        write_worm_pubkey_raw_from_key(WORM_SIGNING_KEY_PATH, WORM_SIGNING_PUB_PATH);
        println!("[INSTALLER] WORM public key derived from existing 32-byte seed.");
        return;
    }

    if Path::new(WORM_SIGNING_PUB_PATH).exists() {
        panic!(
            "[FATAL] {} exists without {} — refuse orphan public key",
            WORM_SIGNING_PUB_PATH, WORM_SIGNING_KEY_PATH
        );
    }

    let mut seed = [0u8; 32];
    for attempt in 0..256 {
        OsRng.fill_bytes(&mut seed);
        if !is_weak_worm_seed(&seed) {
            break;
        }
        if attempt == 255 {
            panic!("[FATAL] CSPRNG produced weak WORM seed material repeatedly — abort");
        }
    }

    fs::write(WORM_SIGNING_KEY_PATH, &seed)
        .unwrap_or_else(|e| panic!("[FATAL] unable to write worm signing key: {}", e));

    let key_bytes = fs::read(WORM_SIGNING_KEY_PATH)
        .unwrap_or_else(|e| panic!("[FATAL] read-back {}: {}", WORM_SIGNING_KEY_PATH, e));
    if key_bytes.len() != 32 {
        panic!("[FATAL] WORM key integrity violation — must be 32 bytes");
    }
    validate_worm_seed_bytes(&key_bytes);

    fs::set_permissions(
        WORM_SIGNING_KEY_PATH,
        fs::Permissions::from_mode(0o400),
    )
    .unwrap_or_else(|e| panic!("[FATAL] chmod worm signing key: {}", e));
    chown_root(WORM_SIGNING_KEY_PATH);
    assert_file_mode(WORM_SIGNING_KEY_PATH, 0o400);

    println!("[INSTALLER][OK] Generated 32-byte WORM signing key (raw seed)");
    println!("[INSTALLER][OK] WORM key size = {} bytes", key_bytes.len());
    println!(
        "[INSTALLER][OK] WORM key first 16 bytes (hex) = {}",
        hex::encode(&key_bytes[..16])
    );

    write_worm_pubkey_raw_from_key(WORM_SIGNING_KEY_PATH, WORM_SIGNING_PUB_PATH);
}

fn count_existing_pki() -> usize {
    PKI_PATHS.iter().filter(|p| Path::new(p).exists()).count()
}

/// When **no** PKI material exists, provision a full internal chain (root → intermediate → server/client).
/// Partial trees are rejected (fail-closed).
pub fn provision_pki_greenfield_if_no_identity() {
    let n = count_existing_pki();
    if n == PKI_PATHS.len() {
        println!("[INSTALLER] PKI identity bundle already complete.");
        return;
    }
    if n != 0 {
        panic!(
            "[FATAL] incomplete PKI under /etc/ransomeye (found {}/{} files). \
             Remove partial files or supply the full seven-file bundle.",
            n,
            PKI_PATHS.len()
        );
    }

    let tmp = std::env::temp_dir();
    let im_csr = tmp.join("ransomeye-im.csr");
    let im_ext = tmp.join("ransomeye-im.ext");
    let srv_csr = tmp.join("ransomeye-srv.csr");
    let srv_ext = tmp.join("ransomeye-srv.ext");
    let cl_csr = tmp.join("ransomeye-cl.csr");

    fs::write(
        &im_ext,
        b"basicConstraints=CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n",
    )
    .unwrap_or_else(|e| panic!("[FATAL] write im.ext: {}", e));
    fs::write(&srv_ext, b"subjectAltName=IP:127.0.0.1\n")
        .unwrap_or_else(|e| panic!("[FATAL] write srv.ext: {}", e));

    // Root CA
    run_openssl(&[
        "genrsa",
        "-out",
        "/etc/ransomeye/pki/root_ca.key",
        "4096",
    ]);
    run_openssl(&[
        "req",
        "-x509",
        "-new",
        "-nodes",
        "-key",
        "/etc/ransomeye/pki/root_ca.key",
        "-sha256",
        "-days",
        "3650",
        "-out",
        "/etc/ransomeye/ca.crt",
        "-subj",
        "/CN=RansomEye-Root-CA",
    ]);

    // Intermediate CA
    run_openssl(&[
        "genrsa",
        "-out",
        "/etc/ransomeye/pki/intermediate_ca.key",
        "4096",
    ]);
    run_openssl(&[
        "req",
        "-new",
        "-key",
        "/etc/ransomeye/pki/intermediate_ca.key",
        "-out",
        im_csr.to_str().unwrap(),
        "-subj",
        "/CN=RansomEye-Intermediate-CA",
    ]);
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        im_csr.to_str().unwrap(),
        "-CA",
        "/etc/ransomeye/ca.crt",
        "-CAkey",
        "/etc/ransomeye/pki/root_ca.key",
        "-CAcreateserial",
        "-out",
        "/etc/ransomeye/pki/intermediate_ca.crt",
        "-days",
        "1825",
        "-extfile",
        im_ext.to_str().unwrap(),
    ]);

    // Server leaf (TASK 4 intent: CN loopback + SAN; signed by intermediate, not ad-hoc self-signed alone)
    run_openssl(&[
        "genrsa",
        "-out",
        "/etc/ransomeye/server.key",
        "2048",
    ]);
    run_openssl(&[
        "req",
        "-new",
        "-key",
        "/etc/ransomeye/server.key",
        "-out",
        srv_csr.to_str().unwrap(),
        "-subj",
        "/CN=127.0.0.1",
    ]);
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        srv_csr.to_str().unwrap(),
        "-CA",
        "/etc/ransomeye/pki/intermediate_ca.crt",
        "-CAkey",
        "/etc/ransomeye/pki/intermediate_ca.key",
        "-CAcreateserial",
        "-out",
        "/etc/ransomeye/server.crt",
        "-days",
        "365",
        "-extfile",
        srv_ext.to_str().unwrap(),
    ]);

    // Client mTLS leaf
    run_openssl(&[
        "genrsa",
        "-out",
        "/etc/ransomeye/client.key",
        "2048",
    ]);
    run_openssl(&[
        "req",
        "-new",
        "-key",
        "/etc/ransomeye/client.key",
        "-out",
        cl_csr.to_str().unwrap(),
        "-subj",
        "/CN=ransomeye-core-client",
    ]);
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        cl_csr.to_str().unwrap(),
        "-CA",
        "/etc/ransomeye/pki/intermediate_ca.crt",
        "-CAkey",
        "/etc/ransomeye/pki/intermediate_ca.key",
        "-CAcreateserial",
        "-out",
        "/etc/ransomeye/client.crt",
        "-days",
        "825",
    ]);

    for p in [
        "/etc/ransomeye/pki/root_ca.key",
        "/etc/ransomeye/pki/intermediate_ca.key",
        "/etc/ransomeye/server.key",
        "/etc/ransomeye/client.key",
    ] {
        fs::set_permissions(p, fs::Permissions::from_mode(0o400))
            .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", p, e));
        let _ = Command::new("chown").args(["root:root", p]).status();
    }
    for p in [
        "/etc/ransomeye/ca.crt",
        "/etc/ransomeye/pki/intermediate_ca.crt",
        "/etc/ransomeye/server.crt",
        "/etc/ransomeye/client.crt",
    ] {
        fs::set_permissions(p, fs::Permissions::from_mode(0o444))
            .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", p, e));
        let _ = Command::new("chown").args(["root:root", p]).status();
    }

    let _ = fs::remove_file(im_csr);
    let _ = fs::remove_file(im_ext);
    let _ = fs::remove_file(srv_csr);
    let _ = fs::remove_file(srv_ext);
    let _ = fs::remove_file(cl_csr);

    println!("[INSTALLER] Greenfield PKI provisioned (root → intermediate → server/client).");
}

/// TASK 5 — prepare `common.yaml` for signing if absent (template from repo at build time, or explicit path).
pub fn provision_prep_common_yaml_if_missing() {
    if Path::new(PREP_COMMON_YAML).exists() {
        println!("[INSTALLER] Prepared common.yaml already present.");
        return;
    }
    if let Ok(p) = std::env::var("RANSOMEYE_PREP_COMMON_YAML") {
        let src = p.trim();
        assert_exists(src);
        fs::copy(src, PREP_COMMON_YAML).unwrap_or_else(|e| {
            panic!(
                "[FATAL] copy prepared common {} -> {}: {}",
                src, PREP_COMMON_YAML, e
            )
        });
        println!(
            "[INSTALLER] Prepared common.yaml from RANSOMEYE_PREP_COMMON_YAML={}",
            src
        );
        return;
    }
    let cwd_try = Path::new("configs/common.yaml");
    if cwd_try.is_file() {
        fs::copy(cwd_try, PREP_COMMON_YAML).unwrap_or_else(|e| {
            panic!(
                "[FATAL] copy configs/common.yaml -> {}: {}",
                PREP_COMMON_YAML, e
            )
        });
        println!("[INSTALLER] Prepared common.yaml from ./configs/common.yaml");
        return;
    }
    fs::write(PREP_COMMON_YAML, DEFAULT_COMMON_YAML.as_bytes()).unwrap_or_else(|e| {
        panic!(
            "[FATAL] write embedded default to {}: {}",
            PREP_COMMON_YAML, e
        )
    });
    println!("[INSTALLER] Prepared common.yaml from embedded build template.");
}

/// TASK 1 — materialize prepared common into `/etc/.../config` immediately after prep (signer overwrites with signed YAML later).
pub fn copy_prep_common_to_config_dir() {
    eprintln!("[INSTALLER][STEP] copy prepared common.yaml → {}", CONFIG_COMMON_YAML);
    assert_exists(PREP_COMMON_YAML);
    fs::create_dir_all(
        Path::new(CONFIG_COMMON_YAML)
            .parent()
            .expect("common.yaml path has parent"),
    )
    .unwrap_or_else(|e| panic!("[FATAL] mkdir config: {}", e));
    fs::copy(PREP_COMMON_YAML, CONFIG_COMMON_YAML).unwrap_or_else(|e| {
        panic!(
            "[FATAL] copy {} -> {}: {}",
            PREP_COMMON_YAML, CONFIG_COMMON_YAML, e
        )
    });
    assert_exists(CONFIG_COMMON_YAML);
    eprintln!(
        "[INSTALLER][OK] common.yaml present at {} (unsigned preview; signed at install_signed_common_config)",
        CONFIG_COMMON_YAML
    );
}

/// If destination missing, copy from source; if present, require byte-identical to source (fail-closed).
pub fn copy_if_missing_or_verify_identical(src: &str, dst: &str, dst_mode: u32) {
    assert_exists(src);
    let want = fs::read(src).unwrap_or_else(|e| panic!("[FATAL] read {}: {}", src, e));
    if Path::new(dst).exists() {
        let got = fs::read(dst).unwrap_or_else(|e| panic!("[FATAL] read {}: {}", dst, e));
        if want != got {
            eprintln!(
                "[INSTALLER][FAIL] TLS content mismatch: source {} differs from {}",
                src, dst
            );
            panic!("INSTALLATION FAILED — SYSTEM NOT OPERATIONAL");
        }
        eprintln!(
            "[INSTALLER][OK] TLS verified identical {} → {}",
            src, dst
        );
        return;
    }
    fs::copy(src, dst).unwrap_or_else(|e| panic!("[FATAL] copy {} -> {}: {}", src, dst, e));
    fs::set_permissions(dst, fs::Permissions::from_mode(dst_mode))
        .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", dst, e));
    let _ = Command::new("chown").args(["root:root", dst]).status();
    eprintln!("[INSTALLER][OK] TLS copied {} → {}", src, dst);
}

/// TASK 2 — keep Core DB trust store aligned with canonical `/etc/ransomeye` identity material.
pub fn sync_etc_identity_certs_to_core_certs() {
    eprintln!("[INSTALLER][STEP] synchronize /etc/ransomeye/*.crt|*.key → /opt/ransomeye/core/certs/");
    copy_if_missing_or_verify_identical(
        "/etc/ransomeye/ca.crt",
        "/opt/ransomeye/core/certs/ca.crt",
        0o444,
    );
    copy_if_missing_or_verify_identical(
        "/etc/ransomeye/client.crt",
        "/opt/ransomeye/core/certs/client.crt",
        0o444,
    );
    copy_if_missing_or_verify_identical(
        "/etc/ransomeye/client.key",
        "/opt/ransomeye/core/certs/client.key",
        0o400,
    );
}

/// TASK 6 — mandatory artifacts before `systemctl start` / health gate.
pub fn assert_boot_artifacts_for_health_gate() {
    for p in [
        "/etc/ransomeye/config/common.yaml",
        "/etc/ransomeye/server.crt",
        "/etc/ransomeye/server.key",
        WORM_SIGNING_KEY_PATH,
        "/opt/ransomeye/core/certs/ca.crt",
        "/opt/ransomeye/core/certs/client.crt",
        "/opt/ransomeye/core/certs/client.key",
    ] {
        assert_exists(p);
    }
    assert_file_mode(WORM_SIGNING_KEY_PATH, 0o400);
    assert_worm_key_seed_len(WORM_SIGNING_KEY_PATH);
    eprintln!("[INSTALLER][OK] boot artifact validation complete");
}
