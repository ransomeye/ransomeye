use std::env;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{exit, Command};
use std::str;
use std::thread;
use std::time::Duration;

use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use pkcs8::EncodePublicKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

mod config_signer;
mod filesystem;
mod nginx_setup;
mod postgres_setup;

// 1. PREFLIGHT CHECKS
fn preflight_checks() {
    let output = Command::new("id").arg("-u").output();
    match output {
        Ok(out) => {
            let uid_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if uid_str != "0" {
                eprintln!(
                    "CRITICAL ERROR: Installer must be run as root. Current UID: {}",
                    uid_str
                );
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("CRITICAL ERROR: Failed to execute 'id -u': {}", e);
            exit(1);
        }
    }

    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_else(|_| String::new());
    if !cpuinfo.contains("avx2") {
        eprintln!("CRITICAL ERROR: CPU does not support AVX2 instruction set.");
        exit(1);
    }

    println!("[SUCCESS] Preflight checks passed.");
}

// 2. DIRECTORY SETUP
fn directory_setup() {
    let dirs = [
        "/opt/ransomeye/core/",
        "/opt/ransomeye/core/certs/",
        "/opt/ransomeye/ui/",
        "/opt/ransomeye/ui/dist/",
        "/opt/ransomeye/prep/",
        "/opt/ransomeye/logs/",
        "/opt/ransomeye/postgres/certs/",
        "/etc/ransomeye/",
        "/etc/ransomeye/config/",
        "/etc/ransomeye/certs/",
        "/etc/ransomeye/pki/",
        "/etc/postgresql/",
    ];

    for dir in dirs.iter() {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("CRITICAL ERROR: Failed to create directory {}: {}", dir, e);
            exit(1);
        }
    }

    if fs::set_permissions("/etc/ransomeye/", Permissions::from_mode(0o700)).is_err() {
        eprintln!("CRITICAL ERROR: Failed to chmod 700 /etc/ransomeye/");
        exit(1);
    }

    let opt_dirs = [
        "/opt/ransomeye/core/",
        "/opt/ransomeye/prep/",
        "/opt/ransomeye/logs/",
    ];
    for dir in opt_dirs.iter() {
        if fs::set_permissions(dir, Permissions::from_mode(0o755)).is_err() {
            eprintln!("CRITICAL ERROR: Failed to chmod 755 {}", dir);
            exit(1);
        }
    }
    println!("[SUCCESS] Directory setup completed strictly.");
}

/// Phase 6.7: state dir for monotonic manifest version (root-only; version file 0600).
fn setup_integrity_state_dir() {
    let state = Path::new("/var/lib/ransomeye/state");
    if let Err(e) = fs::create_dir_all(state) {
        eprintln!("CRITICAL ERROR: mkdir /var/lib/ransomeye/state: {}", e);
        exit(1);
    }
    let _ = Command::new("chown")
        .args(["root:root", "/var/lib/ransomeye/state"])
        .status();
    if fs::set_permissions(state, Permissions::from_mode(0o700)).is_err() {
        eprintln!("CRITICAL ERROR: chmod 700 /var/lib/ransomeye/state failed");
        exit(1);
    }
    println!("[SUCCESS] Integrity state directory ready (/var/lib/ransomeye/state).");
}

/// Phase 6.2: only `/opt/ransomeye/...` is in the trusted execution domain — never `/usr/local/bin`.
fn remove_stale_usrlocal_ai_verify() {
    let stale = Path::new("/usr/local/bin/ransomeye-ai-verify");
    if stale.is_file() {
        if fs::remove_file(stale).is_err() {
            eprintln!(
                "CRITICAL ERROR: remove stale {} (Phase 6.2 — untrusted path)",
                stale.display()
            );
            exit(1);
        }
        println!("[SUCCESS] Removed stale /usr/local/bin/ransomeye-ai-verify.");
    }
}

fn verify_file_sha256(path: &str, expected_hex: &str) -> Result<(), String> {
    let data = fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    let sum = Sha256::digest(&data);
    let actual = hex::encode(sum);
    if actual != expected_hex.to_ascii_lowercase() {
        return Err(format!(
            "SHA256 mismatch for {} — tampered or wrong build (Phase 6.3)",
            path
        ));
    }
    Ok(())
}

fn parse_manifest_version_first_line(manifest_str: &str) -> Result<u64, String> {
    let first = manifest_str
        .lines()
        .next()
        .ok_or_else(|| "integrity.manifest: empty".to_string())?
        .trim();
    if first.is_empty() {
        return Err("integrity.manifest: first line must be version header".into());
    }
    let Some((key, val)) = first.split_once(':') else {
        return Err("integrity.manifest: first line must be version header".into());
    };
    if key.trim().to_ascii_lowercase() != "version" {
        return Err("integrity.manifest: first line must be version header".into());
    }
    val.trim()
        .parse::<u64>()
        .map_err(|e| format!("integrity.manifest: version: {}", e))
}

fn read_stored_manifest_version(path: &Path) -> Result<u64, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    raw.trim()
        .parse::<u64>()
        .map_err(|e| format!("stored version parse: {}", e))
}

fn write_stored_manifest_version_atomic(v: u64) -> Result<(), String> {
    const TMP: &str = "/var/lib/ransomeye/state/version.tmp";
    const FINAL: &str = "/var/lib/ransomeye/state/version";
    if let Err(e) = fs::create_dir_all("/var/lib/ransomeye/state") {
        return Err(format!("mkdir state: {}", e));
    }
    if fs::write(TMP, format!("{}\n", v)).is_err() {
        return Err("write version.tmp failed".into());
    }
    if fs::set_permissions(Path::new(TMP), Permissions::from_mode(0o600)).is_err() {
        return Err("chmod version.tmp failed".into());
    }
    if fs::rename(TMP, FINAL).is_err() {
        return Err("rename version.tmp failed".into());
    }
    let _ = Command::new("chown").args(["root:root", FINAL]).status();
    if fs::set_permissions(Path::new(FINAL), Permissions::from_mode(0o600)).is_err() {
        return Err("chmod version failed".into());
    }
    Ok(())
}

// --- Phase 6.8–7.1: dual-anchor hash chain, multi-source anchor, append-only anchor.history (Go parity) ---
const VERSION_CHAIN_PATH: &str = "/var/lib/ransomeye/state/version.chain";
const ANCHOR_PATH: &str = "/var/lib/ransomeye/state/anchor";
const ANCHOR_TMP: &str = "/var/lib/ransomeye/state/anchor.tmp";
const ANCHOR_HISTORY_PATH: &str = "/var/lib/ransomeye/state/anchor.history";
const ANCHOR_HISTORY_TMP: &str = "/var/lib/ransomeye/state/anchor.history.tmp";
const MACHINE_ID_PATH: &str = "/etc/machine-id";
const PROC_CPUINFO: &str = "/proc/cpuinfo";

fn normalize_anchor_component(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

fn anchor_preimage() -> Result<String, String> {
    let mid = read_normalized_machine_id()?;
    let cpu = read_normalized_cpu_identity()?;
    let uuid = read_normalized_root_fs_uuid()?;
    if mid.is_empty() || cpu.is_empty() || uuid.is_empty() {
        return Err("anchor material: empty component".into());
    }
    Ok(format!("{}\n{}\n{}", mid, cpu, uuid))
}

fn read_normalized_machine_id() -> Result<String, String> {
    let raw = fs::read_to_string(MACHINE_ID_PATH).map_err(|e| format!("read machine-id: {}", e))?;
    let s = normalize_anchor_component(&raw);
    if s.is_empty() {
        return Err("machine-id empty".into());
    }
    Ok(s)
}

fn read_normalized_cpu_identity() -> Result<String, String> {
    let raw = fs::read_to_string(PROC_CPUINFO).map_err(|e| format!("cpuinfo: {}", e))?;
    let id = cpu_identity_from_cpuinfo(&raw)?;
    let s = normalize_anchor_component(&id);
    if s.is_empty() {
        return Err("cpu identity empty".into());
    }
    Ok(s)
}

fn cpu_identity_from_cpuinfo(content: &str) -> Result<String, String> {
    let block =
        first_cpuinfo_block(content).ok_or_else(|| "cpuinfo: no processor block".to_string())?;
    if let Some(v) = block.get("serial") {
        if !v.is_empty() {
            return Ok(v.clone());
        }
    }
    if let Some(v) = block.get("model name") {
        if !v.is_empty() {
            return Ok(v.clone());
        }
    }
    let mut parts: Vec<&str> = Vec::new();
    for k in ["vendor_id", "cpu family", "model", "model name"] {
        if let Some(v) = block.get(k) {
            let t = v.trim();
            if !t.is_empty() {
                parts.push(t);
            }
        }
    }
    if parts.is_empty() {
        return Err("cpuinfo: no serial, model name, or vendor tuple".into());
    }
    Ok(parts.join("|"))
}

fn first_cpuinfo_block(content: &str) -> Option<std::collections::HashMap<String, String>> {
    let mut m = std::collections::HashMap::new();
    let mut saw_processor = false;
    for line in content.lines() {
        let ls = line.trim();
        if ls.is_empty() {
            if !m.is_empty() {
                break;
            }
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let key = normalize_anchor_component(&line[..colon]);
        let val = line[colon + 1..].trim().to_string();
        if key.is_empty() {
            continue;
        }
        if key == "processor" {
            if saw_processor && !m.is_empty() {
                break;
            }
            saw_processor = true;
            continue;
        }
        if saw_processor {
            m.insert(key, val);
        }
    }
    if m.is_empty() {
        None
    } else {
        Some(m)
    }
}

fn read_normalized_root_fs_uuid() -> Result<String, String> {
    let u = root_fs_raw_uuid()?;
    let s = normalize_anchor_component(&u);
    if s.is_empty() {
        return Err("root filesystem UUID empty".into());
    }
    Ok(s)
}

fn root_fs_raw_uuid() -> Result<String, String> {
    let uuid_try = Command::new("findmnt")
        .args(["-n", "-o", "UUID", "/"])
        .output();
    if let Ok(out) = uuid_try {
        if out.status.success() {
            let u = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let nu = normalize_anchor_component(&u);
            if !nu.is_empty() && nu != "unknown" {
                return Ok(u);
            }
        }
    }
    let src_try = Command::new("findmnt")
        .args(["-n", "-o", "SOURCE", "/"])
        .output();
    match src_try {
        Ok(out) if out.status.success() => {
            let src = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Some(u) = uuid_from_mount_source(&src) {
                return Ok(u);
            }
            root_fs_uuid_from_proc_mounts()
        }
        _ => root_fs_uuid_from_proc_mounts(),
    }
}

fn uuid_from_mount_source(src: &str) -> Option<String> {
    let s = src.trim();
    let lower = s.to_ascii_lowercase();
    if lower.strip_prefix("uuid=").is_some() {
        return Some(s[5..].trim().to_string());
    }
    let out = Command::new("blkid")
        .args(["-o", "value", "-s", "UUID", s])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let u = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if u.is_empty() {
        None
    } else {
        Some(u)
    }
}

fn root_fs_uuid_from_proc_mounts() -> Result<String, String> {
    let raw = fs::read_to_string("/proc/mounts").map_err(|e| format!("/proc/mounts: {}", e))?;
    for line in raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "/" {
            if let Some(u) = uuid_from_mount_source(fields[0]) {
                return Ok(u);
            }
        }
    }
    Err("root filesystem UUID unavailable from /proc/mounts".into())
}

fn compute_machine_anchor() -> Result<[u8; 32], String> {
    let preimage = anchor_preimage()?;
    let z = [0u8; 32];
    let mut h = Sha256::new();
    h.update(preimage.as_bytes());
    h.update(z);
    Ok(h.finalize().into())
}

fn anchor_history_line_hash(prev: &[u8; 32], anchor: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(anchor);
    h.update(prev);
    h.finalize().into()
}

fn parse_chained_anchor_history_line(
    line: &str,
    line_no: usize,
) -> Result<([u8; 32], [u8; 32]), String> {
    let t = line.trim();
    let tl = t.to_ascii_lowercase();
    if !tl.starts_with("anchor:") {
        return Err(format!("anchor.history line {}: want anchor:", line_no));
    }
    let rest = t[7..].trim();
    let il = rest.to_ascii_lowercase();
    let i = il
        .find("hash:")
        .ok_or_else(|| format!("anchor.history line {}: want hash:", line_no))?;
    let a_hex = rest[..i].trim();
    let h_part = rest[i..].trim();
    let hpl = h_part.to_ascii_lowercase();
    if !hpl.starts_with("hash:") {
        return Err(format!("anchor.history line {}: bad hash field", line_no));
    }
    let h_hex = h_part[5..].trim();
    if a_hex.len() != 64 || h_hex.len() != 64 {
        return Err(format!(
            "anchor.history line {}: want 64-char hex fields",
            line_no
        ));
    }
    let mut an = [0u8; 32];
    let mut lh = [0u8; 32];
    hex::decode_to_slice(a_hex, &mut an).map_err(|e| format!("line {} anchor: {}", line_no, e))?;
    hex::decode_to_slice(h_hex, &mut lh).map_err(|e| format!("line {} hash: {}", line_no, e))?;
    Ok((an, lh))
}

fn verify_chained_anchor_history(raw: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut prev = [0u8; 32];
    let mut anchors: Vec<[u8; 32]> = Vec::new();
    let mut line_no = 0usize;
    for line in raw.lines() {
        line_no += 1;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (an, rec) = parse_chained_anchor_history_line(t, line_no)?;
        let want = anchor_history_line_hash(&prev, &an);
        if want != rec {
            return Err(format!(
                "anchor.history line {}: chain hash mismatch (tamper or reorder)",
                line_no
            ));
        }
        anchors.push(an);
        prev = want;
    }
    if anchors.is_empty() {
        return Err("anchor.history has no entries".into());
    }
    Ok(anchors)
}

fn is_flat_anchor_history(raw: &str) -> bool {
    let mut any = false;
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        any = true;
        if t.to_ascii_lowercase().contains("hash:") {
            return false;
        }
    }
    any
}

fn parse_flat_anchor_history_anchors(raw: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    let mut line_no = 0usize;
    for line in raw.lines() {
        line_no += 1;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let low = t.to_ascii_lowercase();
        let rest = low
            .strip_prefix("anchor:")
            .ok_or_else(|| format!("flat-format line {}: want anchor:", line_no))?;
        let h = rest.trim();
        if h.len() != 64 {
            return Err(format!("flat-format line {}: want 64 hex", line_no));
        }
        let mut d = [0u8; 32];
        hex::decode_to_slice(h, &mut d).map_err(|e| format!("flat-format line {}: {}", line_no, e))?;
        out.push(d);
    }
    if out.is_empty() {
        return Err("flat-format anchor.history empty".into());
    }
    Ok(out)
}

fn discard_stale_anchor_history_tmp() {
    let _ = fs::remove_file(ANCHOR_HISTORY_TMP);
}

fn sync_parent_dir_of(path: &str) -> Result<(), String> {
    let parent = Path::new(path)
        .parent()
        .ok_or_else(|| "anchor.history: no parent dir".to_string())?;
    let f = fs::File::open(parent).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}

/// Phase 7.2.1: tmp → fsync → verify → rename → fsync(parent) → verify final.
fn atomic_write_verified_anchor_history(content: &[u8]) -> Result<(), String> {
    discard_stale_anchor_history_tmp();
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(ANCHOR_HISTORY_TMP)
        .map_err(|e| e.to_string())?;
    f.write_all(content).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    let _ = Command::new("chown")
        .args(["root:root", ANCHOR_HISTORY_TMP])
        .status();
    fs::set_permissions(Path::new(ANCHOR_HISTORY_TMP), Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let s = std::str::from_utf8(content).map_err(|_| "anchor.history: invalid utf8".to_string())?;
    verify_chained_anchor_history(s).map_err(|e| format!("pre-rename verify: {}", e))?;
    fs::rename(ANCHOR_HISTORY_TMP, ANCHOR_HISTORY_PATH).map_err(|e| e.to_string())?;
    sync_parent_dir_of(ANCHOR_HISTORY_PATH)?;
    let raw = fs::read_to_string(ANCHOR_HISTORY_PATH).map_err(|e| e.to_string())?;
    verify_chained_anchor_history(&raw).map_err(|e| format!("migration corruption: {}", e))?;
    let _ = Command::new("chown")
        .args(["root:root", ANCHOR_HISTORY_PATH])
        .status();
    fs::set_permissions(
        Path::new(ANCHOR_HISTORY_PATH),
        Permissions::from_mode(0o600),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn rewrite_anchor_history_chained(anchors: &[[u8; 32]]) -> Result<(), String> {
    let mut prev = [0u8; 32];
    let mut buf = String::new();
    for a in anchors {
        let lh = anchor_history_line_hash(&prev, a);
        buf.push_str(&format!(
            "anchor:{} hash:{}\n",
            hex::encode(a),
            hex::encode(lh)
        ));
        prev = lh;
    }
    atomic_write_verified_anchor_history(buf.as_bytes())?;
    println!(
        "[AUDIT] anchor.history migrated to Phase 7.2 chained format ({} entries)",
        anchors.len()
    );
    Ok(())
}

fn migrate_flat_anchor_history_if_needed() -> Result<(), String> {
    discard_stale_anchor_history_tmp();
    if !Path::new(ANCHOR_HISTORY_PATH).is_file() {
        return Ok(());
    }
    let raw = fs::read_to_string(ANCHOR_HISTORY_PATH).map_err(|e| e.to_string())?;
    if raw.trim().is_empty() {
        return Err("anchor.history empty".into());
    }
    if !is_flat_anchor_history(&raw) {
        return Ok(());
    }
    let anchors = parse_flat_anchor_history_anchors(&raw)?;
    rewrite_anchor_history_chained(&anchors)
}

fn read_anchor_history_entries() -> Result<Vec<[u8; 32]>, String> {
    migrate_flat_anchor_history_if_needed()?;
    let raw =
        fs::read_to_string(ANCHOR_HISTORY_PATH).map_err(|e| format!("anchor.history: {}", e))?;
    verify_chained_anchor_history(&raw)
}

fn history_contains(entries: &[[u8; 32]], want: &[u8; 32]) -> bool {
    entries.iter().any(|e| e == want)
}

fn write_anchor_history_first_line(digest: &[u8; 32]) -> Result<(), String> {
    fs::create_dir_all("/var/lib/ransomeye/state").map_err(|e| format!("mkdir state: {}", e))?;
    let z = [0u8; 32];
    let lh = anchor_history_line_hash(&z, digest);
    let line = format!("anchor:{} hash:{}\n", hex::encode(digest), hex::encode(lh));
    atomic_write_verified_anchor_history(line.as_bytes())
}

fn append_anchor_history_line(digest: &[u8; 32]) -> Result<(), String> {
    discard_stale_anchor_history_tmp();
    migrate_flat_anchor_history_if_needed()?;
    let raw = fs::read_to_string(ANCHOR_HISTORY_PATH).map_err(|e| e.to_string())?;
    let anchors = verify_chained_anchor_history(&raw)?;
    let mut prev = [0u8; 32];
    for a in &anchors {
        prev = anchor_history_line_hash(&prev, a);
    }
    let new_h = anchor_history_line_hash(&prev, digest);
    let line = format!(
        "anchor:{} hash:{}\n",
        hex::encode(digest),
        hex::encode(new_h)
    );
    let mut f = OpenOptions::new()
        .append(true)
        .mode(0o600)
        .open(ANCHOR_HISTORY_PATH)
        .map_err(|e| format!("anchor.history append: {}", e))?;
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    let _ = Command::new("chown")
        .args(["root:root", ANCHOR_HISTORY_PATH])
        .status();
    fs::set_permissions(
        Path::new(ANCHOR_HISTORY_PATH),
        Permissions::from_mode(0o600),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn sync_materialized_anchor_file(exp: &[u8; 32]) -> Result<(), String> {
    fs::create_dir_all("/var/lib/ransomeye/state").map_err(|e| format!("mkdir state: {}", e))?;
    if Path::new(ANCHOR_PATH).is_file() {
        let cur = fs::read(ANCHOR_PATH).map_err(|e| e.to_string())?;
        if cur.len() == 32 && cur.as_slice() == exp.as_slice() {
            return Ok(());
        }
    }
    fs::write(ANCHOR_TMP, exp).map_err(|e| e.to_string())?;
    fs::set_permissions(Path::new(ANCHOR_TMP), Permissions::from_mode(0o400))
        .map_err(|e| e.to_string())?;
    fs::rename(ANCHOR_TMP, ANCHOR_PATH).map_err(|e| e.to_string())?;
    let _ = Command::new("chown")
        .args(["root:root", ANCHOR_PATH])
        .status();
    fs::set_permissions(Path::new(ANCHOR_PATH), Permissions::from_mode(0o400))
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Verify current anchor ∈ anchor.history; return chain genesis (first history line). Phase 7.1.
fn ensure_integrity_anchor_file() -> Result<[u8; 32], String> {
    discard_stale_anchor_history_tmp();
    let exp = compute_machine_anchor()?;
    if Path::new(ANCHOR_HISTORY_PATH).is_file() {
        let meta = fs::metadata(ANCHOR_HISTORY_PATH).map_err(|e| e.to_string())?;
        if meta.len() == 0 {
            return Err("anchor.history empty".into());
        }
        let b = read_anchor_history_entries()?;
        if b.is_empty() {
            return Err("anchor.history has no anchor lines".into());
        }
        if !history_contains(&b, &exp) {
            return Err("root-of-trust violation: current anchor not in anchor.history".into());
        }
        sync_materialized_anchor_file(&exp)?;
        return Ok(b[0]);
    }
    if Path::new(ANCHOR_PATH).is_file() {
        let got = fs::read(ANCHOR_PATH).map_err(|e| format!("read anchor: {}", e))?;
        if got.len() != 32 {
            return Err(format!("anchor file want 32 bytes, got {}", got.len()));
        }
        let mut ga = [0u8; 32];
        ga.copy_from_slice(&got[..32]);
        if ga != exp {
            return Err(
                "root-of-trust violation: anchor.history missing and flat anchor mismatch".into(),
            );
        }
        write_anchor_history_first_line(&exp)?;
        sync_materialized_anchor_file(&exp)?;
        return Ok(exp);
    }
    fs::create_dir_all("/var/lib/ransomeye/state").map_err(|e| format!("mkdir state: {}", e))?;
    fs::write(ANCHOR_TMP, exp).map_err(|e| format!("write anchor.tmp: {}", e))?;
    fs::set_permissions(Path::new(ANCHOR_TMP), Permissions::from_mode(0o400))
        .map_err(|e| format!("chmod anchor.tmp: {}", e))?;
    fs::rename(ANCHOR_TMP, ANCHOR_PATH).map_err(|e| format!("rename anchor: {}", e))?;
    write_anchor_history_first_line(&exp)?;
    println!(
        "[AUDIT] integrity anchor fingerprint (sha256 first 8 bytes hex): {}",
        hex::encode(&exp[..8])
    );
    let _ = Command::new("chown")
        .args(["root:root", ANCHOR_PATH])
        .status();
    fs::set_permissions(Path::new(ANCHOR_PATH), Permissions::from_mode(0o400))
        .map_err(|e| format!("chmod anchor: {}", e))?;
    Ok(exp)
}

/// Append live anchor to anchor.history if not already present (controlled rotation).
fn reprovision_integrity_anchor() -> Result<(), String> {
    let exp = compute_machine_anchor()?;
    let entries = read_anchor_history_entries().map_err(|_| {
        "anchor.history missing — run full install before --reprovision-anchor".to_string()
    })?;
    if entries.is_empty() {
        return Err("anchor.history empty".into());
    }
    if history_contains(&entries, &exp) {
        println!(
            "[AUDIT] reprovision-anchor: current digest already in history fingerprint {}",
            hex::encode(&exp[..8])
        );
        return Ok(());
    }
    append_anchor_history_line(&exp)?;
    sync_materialized_anchor_file(&exp)?;
    println!(
        "[AUDIT] reprovision-anchor: appended fingerprint {}",
        hex::encode(&exp[..8])
    );
    Ok(())
}

fn chain_step_hash(version: u64, prev: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(version.to_string());
    h.update(prev);
    h.finalize().into()
}

fn parse_version_chain_line(line: &str) -> Result<(u64, [u8; 32]), String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 2 {
        return Err("want \"version:N sha256:<hex>\"".into());
    }
    let key = parts[0].to_ascii_lowercase();
    let vpart = key
        .strip_prefix("version:")
        .ok_or_else(|| "missing version: prefix".to_string())?
        .trim();
    let n: u64 = vpart
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let sp = parts[1].to_ascii_lowercase();
    let hexpart = sp
        .strip_prefix("sha256:")
        .ok_or_else(|| "missing sha256: prefix".to_string())?;
    if hexpart.len() != 64 {
        return Err("sha256 want 64 hex chars".into());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hexpart, &mut out).map_err(|e| e.to_string())?;
    Ok((n, out))
}

fn replay_version_chain(chain_genesis: &[u8; 32]) -> Result<(u64, [u8; 32]), String> {
    let raw =
        fs::read_to_string(VERSION_CHAIN_PATH).map_err(|e| format!("version.chain read: {}", e))?;
    if raw.trim().is_empty() {
        return Err("version.chain empty".into());
    }
    let mut prev = *chain_genesis;
    let mut max_ver: u64 = 0;
    for (idx, raw_line) in raw.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (n, got) =
            parse_version_chain_line(line).map_err(|e| format!("line {}: {}", idx + 1, e))?;
        if n <= max_ver {
            return Err(format!(
                "line {}: version {} must exceed prior {}",
                idx + 1,
                n,
                max_ver
            ));
        }
        let want = chain_step_hash(n, &prev);
        if got != want {
            return Err(format!(
                "line {}: hash mismatch (tamper or truncate)",
                idx + 1
            ));
        }
        prev = want;
        max_ver = n;
    }
    if max_ver == 0 {
        return Err("version.chain has no entries".into());
    }
    Ok((max_ver, prev))
}

fn bootstrap_version_chain_1_to_v(v: u64, chain_genesis: &[u8; 32]) -> Result<(), String> {
    if v == 0 {
        return Err("cannot bootstrap version.chain from version 0".into());
    }
    if let Err(e) = fs::create_dir_all("/var/lib/ransomeye/state") {
        return Err(format!("mkdir state: {}", e));
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(VERSION_CHAIN_PATH)
        .map_err(|e| format!("version.chain create: {}", e))?;
    let mut prev = *chain_genesis;
    for i in 1..=v {
        let hi = chain_step_hash(i, &prev);
        writeln!(f, "version:{} sha256:{}", i, hex::encode(hi)).map_err(|e| e.to_string())?;
        prev = hi;
    }
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    let _ = Command::new("chown")
        .args(["root:root", VERSION_CHAIN_PATH])
        .status();
    fs::set_permissions(Path::new(VERSION_CHAIN_PATH), Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn append_version_chain_line(version: u64, digest: &[u8; 32]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .append(true)
        .mode(0o600)
        .open(VERSION_CHAIN_PATH)
        .map_err(|e| format!("version.chain append: {}", e))?;
    writeln!(f, "version:{} sha256:{}", version, hex::encode(digest)).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    let _ = Command::new("chown")
        .args(["root:root", VERSION_CHAIN_PATH])
        .status();
    fs::set_permissions(Path::new(VERSION_CHAIN_PATH), Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn installer_prepare_dual_anchor(manifest_ver: u64, ver_path: &Path) -> Result<(), String> {
    let anchor = ensure_integrity_anchor_file()?;
    if Path::new(VERSION_CHAIN_PATH).is_file() {
        let (tip, _) = replay_version_chain(&anchor)?;
        if !ver_path.is_file() {
            return Err("integrity: version.chain exists but version file missing".into());
        }
        let fv = read_stored_manifest_version(ver_path)?;
        if fv != tip {
            return Err(format!(
                "integrity: version file vs chain mismatch (chain={} file={})",
                tip, fv
            ));
        }
        if manifest_ver < tip {
            return Err(format!(
                "rollback vs chain: manifest version {} < chain tip {}",
                manifest_ver, tip
            ));
        }
        return Ok(());
    }
    if ver_path.is_file() {
        let v = read_stored_manifest_version(ver_path)?;
        bootstrap_version_chain_1_to_v(v, &anchor)?;
        let (tip, _) = replay_version_chain(&anchor)?;
        if tip != v {
            return Err("integrity: version.chain bootstrap tip mismatch".into());
        }
        if manifest_ver < tip {
            return Err(format!(
                "rollback vs chain: manifest version {} < chain tip {}",
                manifest_ver, tip
            ));
        }
    }
    Ok(())
}

fn installer_finalize_dual_anchor(manifest_ver: u64) -> Result<(), String> {
    const FINAL_VER: &str = "/var/lib/ransomeye/state/version";
    let anchor = ensure_integrity_anchor_file()?;
    if !Path::new(VERSION_CHAIN_PATH).is_file() {
        bootstrap_version_chain_1_to_v(manifest_ver, &anchor)?;
        write_stored_manifest_version_atomic(manifest_ver)?;
        let (tip, _) = replay_version_chain(&anchor)?;
        if tip != manifest_ver {
            return Err(format!(
                "version.chain bootstrap tip {} want {}",
                tip, manifest_ver
            ));
        }
        let fv = read_stored_manifest_version(Path::new(FINAL_VER))?;
        if fv != manifest_ver {
            return Err("version file out of sync after bootstrap".into());
        }
        return Ok(());
    }
    let (tip, th) = replay_version_chain(&anchor)?;
    if manifest_ver > tip {
        let nh = chain_step_hash(manifest_ver, &th);
        append_version_chain_line(manifest_ver, &nh)?;
    } else if manifest_ver < tip {
        return Err(format!(
            "install manifest {} behind chain tip {} — refuse",
            manifest_ver, tip
        ));
    }
    write_stored_manifest_version_atomic(manifest_ver)?;
    let (tip2, _) = replay_version_chain(&anchor)?;
    if tip2 != manifest_ver {
        return Err(format!(
            "chain tip {} after finalize want {}",
            tip2, manifest_ver
        ));
    }
    let fv = read_stored_manifest_version(Path::new(FINAL_VER))?;
    if fv != manifest_ver {
        return Err("version file out of sync after finalize".into());
    }
    Ok(())
}

fn line_is_manifest_version_header(line: &str) -> bool {
    line.split_once(':')
        .map(|(k, _)| k.trim().eq_ignore_ascii_case("version"))
        .unwrap_or(false)
}

fn parse_integrity_manifest_line(line: &str) -> Result<(String, String), String> {
    let line = line.trim();
    const PFX: &str = "sha256:";
    if !line.starts_with(PFX) {
        return Err(format!("manifest line must start with {:?}", PFX));
    }
    let rest = &line[PFX.len()..];
    let mut i = 0usize;
    for c in rest.chars() {
        if !c.is_ascii_hexdigit() {
            break;
        }
        i += c.len_utf8();
    }
    if i != 64 {
        return Err(format!("manifest: want 64 hex digest chars, got {}", i));
    }
    let (hex_part, tail) = rest.split_at(i);
    let path_part = tail.trim_start();
    if path_part.is_empty() || !path_part.starts_with('/') {
        return Err("manifest: missing absolute path after digest".to_string());
    }
    Ok((path_part.to_string(), hex_part.to_ascii_lowercase()))
}

fn verify_manifest_ed25519_first(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    pubkey_bytes: &[u8; 32],
) -> Result<(), String> {
    if sig_bytes.len() != 64 {
        return Err(format!(
            "integrity.sig: must be exactly 64 bytes (Ed25519), got {}",
            sig_bytes.len()
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|e| format!("worm_signing.pub invalid Ed25519 key: {:?}", e))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "integrity.sig: bad length".to_string())?;
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(manifest_bytes, &signature)
        .map_err(|_| {
            "integrity.manifest Ed25519 verification FAILED — tampered manifest or wrong key"
                .to_string()
        })
}

/// Phase 6.3: signature MUST be validated before any SHA256 line is trusted (fail-closed, same WORM key as AI tar).
fn verify_signed_integrity_manifest_and_harden() {
    const MANIFEST_PATH: &str = "/etc/ransomeye/integrity.manifest";
    const SIG_PATH: &str = "/etc/ransomeye/integrity.sig";
    const WORM_PUB: &str = "/etc/ransomeye/worm_signing.pub";

    remove_stale_usrlocal_ai_verify();

    if !Path::new(MANIFEST_PATH).is_file() {
        eprintln!(
            "CRITICAL ERROR: {} missing — run `make generate-integrity` + install (Phase 6.3)",
            MANIFEST_PATH
        );
        exit(1);
    }
    if !Path::new(SIG_PATH).is_file() {
        eprintln!(
            "CRITICAL ERROR: {} missing — signed manifest required (Phase 6.3)",
            SIG_PATH
        );
        exit(1);
    }
    if !Path::new(WORM_PUB).is_file() {
        eprintln!("CRITICAL ERROR: {} missing", WORM_PUB);
        exit(1);
    }

    let manifest_bytes = match fs::read(MANIFEST_PATH) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("CRITICAL ERROR: read {}: {}", MANIFEST_PATH, e);
            exit(1);
        }
    };
    let sig_bytes = match fs::read(SIG_PATH) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("CRITICAL ERROR: read {}: {}", SIG_PATH, e);
            exit(1);
        }
    };
    let pubkey_raw = match fs::read(WORM_PUB) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("CRITICAL ERROR: read {}: {}", WORM_PUB, e);
            exit(1);
        }
    };
    if pubkey_raw.len() != 32 {
        eprintln!(
            "CRITICAL ERROR: {} must contain exactly 32 bytes (Ed25519 public key)",
            WORM_PUB
        );
        exit(1);
    }
    let pubkey_arr: [u8; 32] = pubkey_raw.as_slice().try_into().unwrap();

    if let Err(e) = verify_manifest_ed25519_first(&manifest_bytes, &sig_bytes, &pubkey_arr) {
        eprintln!("CRITICAL ERROR: {}", e);
        exit(1);
    }

    let manifest_str = String::from_utf8_lossy(&manifest_bytes);
    let manifest_ver = match parse_manifest_version_first_line(&manifest_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("CRITICAL ERROR: {}", e);
            exit(1);
        }
    };
    let ver_path = Path::new("/var/lib/ransomeye/state/version");
    if let Err(e) = installer_prepare_dual_anchor(manifest_ver, ver_path) {
        eprintln!("CRITICAL ERROR: {}", e);
        exit(1);
    }
    if ver_path.is_file() {
        let stored = match read_stored_manifest_version(ver_path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("CRITICAL ERROR: {}", e);
                exit(1);
            }
        };
        if manifest_ver < stored {
            eprintln!(
                "CRITICAL ERROR: rollback detected: manifest version {} < stored {}",
                manifest_ver, stored
            );
            exit(1);
        }
    }

    let mut verified = 0usize;
    for (n, raw_line) in manifest_str.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line_is_manifest_version_header(line) {
            continue;
        }
        let (path, hex_exp) = match parse_integrity_manifest_line(line) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("CRITICAL ERROR: manifest line {}: {}", n + 1, e);
                exit(1);
            }
        };
        if let Err(e) = verify_file_sha256(&path, &hex_exp) {
            eprintln!("CRITICAL ERROR: {}", e);
            exit(1);
        }
        verified += 1;
    }
    if verified == 0 {
        eprintln!("CRITICAL ERROR: integrity.manifest contains no entries");
        exit(1);
    }

    for p in [MANIFEST_PATH, SIG_PATH] {
        if !Command::new("chown")
            .args(["root:root", p])
            .status()
            .map_or(false, |s| s.success())
        {
            eprintln!("CRITICAL ERROR: chown root:root {} failed", p);
            exit(1);
        }
        if fs::set_permissions(Path::new(p), Permissions::from_mode(0o444)).is_err() {
            eprintln!("CRITICAL ERROR: chmod 0444 {} failed", p);
            exit(1);
        }
    }

    if let Err(e) = installer_finalize_dual_anchor(manifest_ver) {
        eprintln!("CRITICAL ERROR: {}", e);
        exit(1);
    }

    println!(
        "[SUCCESS] Signed integrity manifest OK (Ed25519 + {} file hash(es)); anti-rollback dual-anchor version {} persisted; artifacts locked.",
        verified, manifest_ver
    );
}

/// PEM must contain at least one well-formed X.509 certificate (fail-closed, PRD-14).
fn validate_x509_cert_pem(path: &str) {
    let metadata = fs::metadata(path).expect(&format!("CRITICAL ERROR: Missing cert: {}", path));
    if metadata.permissions().mode() & 0o777 != 0o400 {
        panic!(
            "[FATAL] Invalid cert permissions on {}: Must be exactly 400",
            path
        );
    }
    let f = File::open(path).expect("[FATAL] cert open");
    let mut reader = BufReader::new(f);
    let mut found = false;
    for ent in rustls_pemfile::certs(&mut reader) {
        let der = ent.unwrap_or_else(|e| panic!("[FATAL] PEM error on {}: {}", path, e));
        let der_bytes: &[u8] = der.as_ref();
        let (_, _parsed) = X509Certificate::from_der(der_bytes)
            .unwrap_or_else(|e| panic!("[FATAL] Invalid X.509 structure on {}: {:?}", path, e));
        found = true;
    }
    if !found {
        panic!("[FATAL] No X.509 certificate in PEM: {}", path);
    }
}

/// PEM must contain private key material (PKCS#8, PKCS#1 RSA, or EC SEC1).
fn validate_private_key_pem(path: &str) {
    let metadata = fs::metadata(path).expect(&format!("CRITICAL ERROR: Missing key: {}", path));
    if metadata.permissions().mode() & 0o777 != 0o400 {
        panic!(
            "[FATAL] Invalid key permissions on {}: Must be exactly 400",
            path
        );
    }
    let f = File::open(path).expect("[FATAL] key open");
    let mut reader = BufReader::new(f);
    let key = rustls_pemfile::private_key(&mut reader)
        .unwrap_or_else(|e| panic!("[FATAL] PEM error: {}", e));
    if key.is_none() {
        panic!("[FATAL] No private key in PEM: {}", path);
    }
}

/// SubjectPublicKeyInfo DER from certificate PEM (native, no shell crypto).
fn subject_pki_der_from_cert_pem(path: &str) -> Vec<u8> {
    let f = File::open(path).expect("[FATAL] cert open for SPKI");
    let mut reader = BufReader::new(f);
    for ent in rustls_pemfile::certs(&mut reader) {
        let der = ent.unwrap_or_else(|e| panic!("[FATAL] cert PEM on {}: {}", path, e));
        let (_, cert) = X509Certificate::from_der(der.as_ref())
            .unwrap_or_else(|e| panic!("[FATAL] cert DER on {}: {:?}", path, e));
        return cert.tbs_certificate.subject_pki.raw.to_vec();
    }
    panic!("[FATAL] No X.509 certificate in {}", path);
}

fn private_pem_to_public_spki_der(pem: &str) -> Option<Vec<u8>> {
    if let Ok(sk) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
        let pk = sk.to_public_key();
        return rsa::pkcs8::EncodePublicKey::to_public_key_der(&pk)
            .ok()
            .map(|d| d.to_vec());
    }
    if let Ok(sk) = rsa::RsaPrivateKey::from_pkcs1_pem(pem) {
        let pk = sk.to_public_key();
        return rsa::pkcs8::EncodePublicKey::to_public_key_der(&pk)
            .ok()
            .map(|d| d.to_vec());
    }
    if let Ok(sk) = p256::SecretKey::from_pkcs8_pem(pem) {
        let pk = sk.public_key();
        return pk.to_public_key_der().ok().map(|d| d.to_vec());
    }
    if let Ok(sk) = p256::SecretKey::from_sec1_pem(pem) {
        let pk = sk.public_key();
        return pk.to_public_key_der().ok().map(|d| d.to_vec());
    }
    if let Ok(sk) = SigningKey::from_pkcs8_pem(pem) {
        let pk = sk.verifying_key();
        return pk.to_public_key_der().ok().map(|d| d.to_vec());
    }
    None
}

// KEY PARITY CHECK (native SPKI comparison)
fn validate_key_match(cert_path: &str, key_path: &str) {
    let expected = subject_pki_der_from_cert_pem(cert_path);
    let pem = fs::read_to_string(key_path)
        .unwrap_or_else(|e| panic!("[FATAL] key read {}: {}", key_path, e));
    let Some(actual) = private_pem_to_public_spki_der(&pem) else {
        panic!(
            "[FATAL] Unsupported private key for {} (need RSA, P-256, or Ed25519 PKCS#8 PEM)",
            key_path
        );
    };
    if actual != expected {
        panic!(
            "[FATAL] Cryptographic Mismatch: {} does not match the public key in {}",
            key_path, cert_path
        );
    }
}

// 3. CERTIFICATE PLACEMENT
fn certificate_placement() {
    let certs = [
        "/etc/ransomeye/ca.crt",
        "/etc/ransomeye/pki/intermediate_ca.crt",
        "/etc/ransomeye/pki/intermediate_ca.key",
        "/etc/ransomeye/server.crt",
        "/etc/ransomeye/server.key",
        "/etc/ransomeye/client.crt",
        "/etc/ransomeye/client.key",
    ];

    for path in certs.iter() {
        if !Path::new(path).exists() {
            eprintln!("CRITICAL ERROR: Required certificate/key missing: {}", path);
            exit(1);
        }

        // Strict permission binding
        if fs::set_permissions(path, Permissions::from_mode(0o400)).is_err() {
            eprintln!("CRITICAL ERROR: Failed to chmod 400 {}", path);
            exit(1);
        }
    }

    // Strict PEM + structure (certs vs keys distinguished)
    validate_x509_cert_pem("/etc/ransomeye/ca.crt");
    validate_x509_cert_pem("/etc/ransomeye/pki/intermediate_ca.crt");
    validate_private_key_pem("/etc/ransomeye/pki/intermediate_ca.key");
    validate_x509_cert_pem("/etc/ransomeye/server.crt");
    validate_private_key_pem("/etc/ransomeye/server.key");
    validate_x509_cert_pem("/etc/ransomeye/client.crt");
    validate_private_key_pem("/etc/ransomeye/client.key");

    // Mathematically robust key pairing check
    validate_key_match(
        "/etc/ransomeye/pki/intermediate_ca.crt",
        "/etc/ransomeye/pki/intermediate_ca.key",
    );
    validate_key_match("/etc/ransomeye/server.crt", "/etc/ransomeye/server.key");
    validate_key_match("/etc/ransomeye/client.crt", "/etc/ransomeye/client.key");

    println!("[SUCCESS] Cryptographic identity verification and key parity passed.");
}

/// Copy server TLS material and CA chain for nginx upstream verification (PRD-14 / PRD-17).
fn copy_tls_material_for_ui_nginx() {
    let pairs = [
        (
            "/etc/ransomeye/server.crt",
            "/opt/ransomeye/core/certs/server.crt",
        ),
        (
            "/etc/ransomeye/server.key",
            "/opt/ransomeye/core/certs/server.key",
        ),
    ];
    for (src, dst) in pairs {
        if let Err(e) = fs::copy(src, dst) {
            eprintln!("CRITICAL ERROR: copy {} -> {}: {}", src, dst, e);
            exit(1);
        }
        if fs::set_permissions(dst, Permissions::from_mode(0o400)).is_err() {
            eprintln!("CRITICAL ERROR: chmod 400 {}", dst);
            exit(1);
        }
    }

    // `/opt/ransomeye/core/certs/ca.crt` is synchronized from `/etc/ransomeye/ca.crt` via
    // `filesystem::sync_etc_identity_certs_to_core_certs` (TASK 2).

    println!("[SUCCESS] nginx TLS server material installed under /opt/ransomeye/core/certs/ (server.*); CA via etc→opt sync.");
}

const NGINX_CONF: &str = include_str!("../nginx/ransomeye.conf");

/// Extract ui/dist tarball to /opt/ransomeye/ui/dist and install nginx site (static UI + /api /ws proxy).
fn install_ui_bundle_and_nginx() {
    nginx_setup::preflight_nginx_binary_or_exit();

    const UI_TAR: &str = "/opt/ransomeye/prep/ui-dist.tar.gz";
    const UI_DIST: &str = "/opt/ransomeye/ui/dist";

    if !Path::new(UI_TAR).is_file() {
        eprintln!("CRITICAL ERROR: UI bundle missing: {}", UI_TAR);
        eprintln!("  Build: ( cd ui && npm ci && npm run build )");
        eprintln!("  Pack: tar -czf {} -C ui/dist .", UI_TAR);
        exit(1);
    }

    if Path::new(UI_DIST).exists() {
        if let Err(e) = fs::remove_dir_all(UI_DIST) {
            eprintln!(
                "CRITICAL ERROR: cannot clear {}: {}",
                UI_DIST, e
            );
            exit(1);
        }
    }
    if let Err(e) = fs::create_dir_all(UI_DIST) {
        eprintln!("CRITICAL ERROR: mkdir {}: {}", UI_DIST, e);
        exit(1);
    }

    if !Command::new("tar")
        .args(["-xzf", UI_TAR, "-C", UI_DIST])
        .status()
        .map_or(false, |s| s.success())
    {
        eprintln!("CRITICAL ERROR: tar extract UI bundle failed");
        exit(1);
    }

    let conf_path = "/etc/nginx/conf.d/ransomeye.conf";
    if let Err(e) = fs::write(conf_path, NGINX_CONF) {
        eprintln!("CRITICAL ERROR: write {}: {}", conf_path, e);
        exit(1);
    }

    let _ = Command::new("rm")
        .args(["-f", "/etc/nginx/sites-enabled/default"])
        .status();

    nginx_setup::nginx_test_config_or_exit();

    let _ = Command::new("systemctl")
        .args(["disable", "--now", "nginx"])
        .status();
    if !Command::new("systemctl")
        .args(["enable", "ransomeye-nginx"])
        .status()
        .map_or(false, |s| s.success())
    {
        eprintln!("WARNING: systemctl enable ransomeye-nginx failed.");
    }
    if !Command::new("systemctl")
        .args(["restart", "ransomeye-nginx"])
        .status()
        .map_or(false, |s| s.success())
    {
        eprintln!("CRITICAL ERROR: systemctl restart ransomeye-nginx failed");
        exit(1);
    }

    println!(
        "[SUCCESS] UI static root {} and nginx reverse proxy (443) configured.",
        UI_DIST
    );
}

// 4. SYSTEMD SERVICES (Mishka default: postgres + core + nginx only)
fn create_systemd_services() {
    let mishka_target = r#"[Unit]
Description=RansomEye Mishka default slice (PostgreSQL + Core + Nginx)
Wants=ransomeye-postgres.service ransomeye-core.service ransomeye-nginx.service
After=network-online.target
Wants=network-online.target

[Install]
WantedBy=multi-user.target
"#;
    if fs::write("/etc/systemd/system/ransomeye.target", mishka_target).is_err() {
        eprintln!("CRITICAL ERROR: Failed to write ransomeye.target");
        exit(1);
    }

    let nginx_unit = r#"[Unit]
Description=RansomEye Nginx (Mishka UI/API reverse proxy; stock nginx binary)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=-/usr/sbin/nginx -s quit
KillMode=mixed
KillSignal=SIGQUIT
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
"#;
    if fs::write("/etc/systemd/system/ransomeye-nginx.service", nginx_unit).is_err() {
        eprintln!("CRITICAL ERROR: Failed to write ransomeye-nginx.service");
        exit(1);
    }

    let core_unit = r#"[Unit]
Description=RansomEye Core Engine (postgres + core gRPC + SOC; Mishka 3-service slice)
Requires=ransomeye-postgres.service
After=ransomeye-postgres.service

[Service]
Type=simple
User=root
Group=root
UMask=0077
WorkingDirectory=/opt/ransomeye/core
EnvironmentFile=/etc/ransomeye/core.env
ExecStart=/opt/ransomeye/core/ransomeye-core
Restart=always
RestartSec=3
TimeoutStopSec=45
LimitNOFILE=65536
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET
IPAddressDeny=any
IPAddressAllow=127.0.0.1/32
ReadWritePaths=/var/lib/ransomeye /run/ransomeye /opt/ransomeye/core/postgres

[Install]
WantedBy=multi-user.target
"#;
    if fs::write("/etc/systemd/system/ransomeye-core.service", core_unit).is_err() {
        eprintln!("CRITICAL ERROR: Failed to write ransomeye-core.service");
        exit(1);
    }

    if !Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .map_or(false, |s| s.success())
    {
        eprintln!("WARNING: Failed to reload systemd daemon (systemctl daemon-reload). Proceeding safely.");
    }

    println!("[SUCCESS] Mishka systemd units installed (core + nginx + targets; no AI/SINE/DPI by default).");
}

// 5. FIREWALL LOCKDOWN (SAFE NO-FLUSH)
fn firewall_lockdown() {
    println!("Applying idempotent namespaces to Firewall...");

    // Create RANSOMEYE chain idempotently via `|| true` mapping
    let _ = Command::new("iptables").args(&["-N", "RANSOMEYE"]).output();

    // Flush only our namespace
    if !Command::new("iptables")
        .args(&["-F", "RANSOMEYE"])
        .status()
        .map_or(false, |s| s.success())
    {
        eprintln!("CRITICAL ERROR: Failed to isolate RANSOMEYE firewall namespace.");
        exit(1);
    }

    // Allow loopback on specific air-gapped ports using multiport syntax
    if !Command::new("iptables")
        .args(&[
            "-A",
            "RANSOMEYE",
            "-i",
            "lo",
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            "50051,50052,50053,50054,8443,80,443",
            "-j",
            "ACCEPT",
        ])
        .status()
        .map_or(false, |s| s.success())
    {
        eprintln!("CRITICAL ERROR: Failed to bind STRICT ACCEPT multiport rule.");
        exit(1);
    }

    // Also explicitly allow purely internal loopback communication universally on the isolated chain as requested
    let _ = Command::new("iptables")
        .args(&["-A", "RANSOMEYE", "-i", "lo", "-j", "ACCEPT"])
        .status();

    // End of isolated chain
    if !Command::new("iptables")
        .args(&["-A", "RANSOMEYE", "-j", "RETURN"])
        .status()
        .map_or(false, |s| s.success())
    {
        eprintln!("CRITICAL ERROR: Failed to attach RETURN rule to namespace.");
        exit(1);
    }

    // Attach RANSOMEYE to INPUT idempotently
    let check_input = Command::new("iptables")
        .args(&["-C", "INPUT", "-j", "RANSOMEYE"])
        .status();
    let needs_append = match check_input {
        Ok(status) => !status.success(),
        Err(_) => true,
    };

    if needs_append {
        if !Command::new("iptables")
            .args(&["-A", "INPUT", "-j", "RANSOMEYE"])
            .status()
            .map_or(false, |s| s.success())
        {
            eprintln!("CRITICAL ERROR: Failed to hook RANSOMEYE namespace onto INPUT chain.");
            exit(1);
        }
    }

    println!("[SUCCESS] Non-destructive Idempotent Firewall rules enforced.");
}

fn systemctl_or_panic(args: &[&str]) {
    let st = Command::new("systemctl")
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("[FATAL] systemctl {:?}: {}", args, e));
    if !st.success() {
        panic!("[FATAL] systemctl {:?} failed (status={})", args, st);
    }
}

const CURL_TMP_BODY: &str = "/tmp/ransomeye-installer.curl.body";

fn curl_http_code_and_body(url: &str) -> Option<(u16, String)> {
    let _ = fs::remove_file(CURL_TMP_BODY);
    let o = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "5",
            "-o",
            CURL_TMP_BODY,
            "-w",
            "%{http_code}",
            url,
        ])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    let code_s = str::from_utf8(&o.stdout).ok()?.trim();
    let code: u16 = code_s.parse().ok()?;
    let body = fs::read_to_string(CURL_TMP_BODY).ok()?;
    Some((code, body))
}

fn ss_ltnp_includes_8443() -> bool {
    Command::new("ss")
        .args(["-ltnp"])
        .output()
        .map(|o| {
            o.status.success()
                && str::from_utf8(&o.stdout)
                    .map(|s| s.contains(":8443"))
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// STEP 2–5: health must be `ok`, `http_plaintext`, and `db == true` (pool healthy).
fn operational_health_ok(body: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    v.get("status").and_then(|x| x.as_str()) == Some("ok")
        && v.get("transport").and_then(|x| x.as_str()) == Some("http_plaintext")
        && v.get("db").and_then(|x| x.as_bool()) == Some(true)
}

/// STEP 3: `/api/v1/system/ingestion-status` has no `db` field in Core; we require HTTP 200 + metrics JSON.
/// Operational meaning of "db" is enforced via `/api/v1/health` (`db: true`) in STEP 2.
fn operational_ingestion_ok(body: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    v.is_object()
        && v.get("events_ingested")
            .map(|x| x.as_u64().is_some() || x.as_i64().is_some())
            .unwrap_or(false)
        && v.get("sine_state").and_then(|x| x.as_str()).is_some()
}

/// STEP 4: recent detections — 200 + JSON array (empty allowed).
fn operational_detections_ok(status: u16, body: &str) -> bool {
    if status != 200 {
        return false;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    v.is_array()
}

fn operational_gate_all_steps_pass() -> bool {
    if !ss_ltnp_includes_8443() {
        eprintln!("[INSTALLER][FAIL] STEP1 ss -ltnp does not show :8443");
        return false;
    }
    let Some((hc, hbody)) =
        curl_http_code_and_body("http://127.0.0.1:8443/api/v1/health")
    else {
        eprintln!("[INSTALLER][FAIL] STEP2 curl health transport error");
        return false;
    };
    if hc != 200 || !operational_health_ok(&hbody) {
        eprintln!(
            "[INSTALLER][FAIL] STEP2 health want status=ok transport=http_plaintext db=true got http={} body_len={}",
            hc,
            hbody.len()
        );
        return false;
    }
    let Some((ic, ibody)) =
        curl_http_code_and_body("http://127.0.0.1:8443/api/v1/system/ingestion-status")
    else {
        eprintln!("[INSTALLER][FAIL] STEP3 curl ingestion-status transport error");
        return false;
    };
    if ic != 200 || !operational_ingestion_ok(&ibody) {
        eprintln!(
            "[INSTALLER][FAIL] STEP3 ingestion-status want 200 + metrics JSON got http={}",
            ic
        );
        return false;
    }
    let Some((dc, dbody)) =
        curl_http_code_and_body("http://127.0.0.1:8443/api/v1/detections/recent")
    else {
        eprintln!("[INSTALLER][FAIL] STEP4 curl detections/recent transport error");
        return false;
    };
    if !operational_detections_ok(dc, &dbody) {
        eprintln!(
            "[INSTALLER][FAIL] STEP4 detections/recent want 200 + JSON array got http={}",
            dc
        );
        return false;
    }
    true
}

fn log_operational_proof() {
    eprintln!("[INSTALLER][OK] STEP1 ss -ltnp (8443 listeners):");
    if let Ok(o) = Command::new("ss").args(["-ltnp"]).output() {
        if o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if line.contains("8443") {
                    eprintln!("[INSTALLER][OK]   {}", line);
                }
            }
        }
    }
    if let Some((_, h)) = curl_http_code_and_body("http://127.0.0.1:8443/api/v1/health") {
        eprintln!("[INSTALLER][OK] STEP2 GET /api/v1/health → {}", h.trim());
    }
    if let Some((_, i)) =
        curl_http_code_and_body("http://127.0.0.1:8443/api/v1/system/ingestion-status")
    {
        eprintln!(
            "[INSTALLER][OK] STEP3 GET /api/v1/system/ingestion-status → {}",
            i.trim()
        );
    }
    if let Some((_, d)) =
        curl_http_code_and_body("http://127.0.0.1:8443/api/v1/detections/recent")
    {
        eprintln!(
            "[INSTALLER][OK] STEP4 GET /api/v1/detections/recent → {}",
            d.trim()
        );
    }
}

/// Final boot orchestration: systemd + blocking operational gate (≤10 min, 2 s cadence).
fn start_core_and_block_until_healthy() {
    eprintln!("[INSTALLER][STEP] systemctl daemon-reexec + enable/start ransomeye-core");
    systemctl_or_panic(&["daemon-reexec"]);
    systemctl_or_panic(&["daemon-reload"]);
    systemctl_or_panic(&["enable", "ransomeye-core"]);
    systemctl_or_panic(&["start", "ransomeye-core"]);
    eprintln!("[INSTALLER][OK] ransomeye-core start requested");

    for attempt in 1..=300 {
        thread::sleep(Duration::from_secs(2));
        if operational_gate_all_steps_pass() {
            eprintln!("[INSTALLER][OK] STEP5 all operational conditions satisfied");
            log_operational_proof();
            return;
        }
        if attempt % 15 == 0 {
            eprintln!(
                "[INSTALLER][STEP] operational gate polling {}/300 (~{} s elapsed)",
                attempt,
                attempt * 2
            );
        }
    }
    eprintln!("[INSTALLER][FAIL] timeout waiting for operational SOC (10 minutes)");
    panic!("INSTALLATION FAILED — SYSTEM NOT OPERATIONAL");
}

// 6. FAIL-CLOSED ORCHESTRATOR
fn main() {
    println!(">>> RANSOMEYE DETERMINISTIC INSTALLER (PRD-17) <<<");
    let pg_pass = std::env::var("POSTGRES_PASSWORD")
        .expect("[FATAL] POSTGRES_PASSWORD must be provided");
    if pg_pass.len() < 12 {
        panic!("[FATAL] POSTGRES_PASSWORD too weak");
    }
    let reprovision_anchor = env::args().any(|a| a == "--reprovision-anchor");

    filesystem::ensure_directory_tree();
    filesystem::provision_worm_signing_if_missing();
    filesystem::provision_pki_greenfield_if_no_identity();
    filesystem::provision_prep_common_yaml_if_missing();
    filesystem::copy_prep_common_to_config_dir();

    preflight_checks();
    if let Err(e) = fs::create_dir_all("/opt/ransomeye/prep/") {
        eprintln!("CRITICAL ERROR: Failed to create prep directory: {}", e);
        exit(1);
    }
    directory_setup();
    setup_integrity_state_dir();
    if reprovision_anchor {
        if let Err(e) = reprovision_integrity_anchor() {
            eprintln!("CRITICAL ERROR: --reprovision-anchor: {}", e);
            exit(1);
        }
    }
    certificate_placement();
    copy_tls_material_for_ui_nginx();
    filesystem::sync_etc_identity_certs_to_core_certs();

    const PG_SERVER_CERT_OPT: &str = "/opt/ransomeye/core/certs/server.crt";

    for f in [
        "ca.crt",
        "client.crt",
        "client.key",
        "server.crt",
        "server.key",
    ] {
        let p = format!("/opt/ransomeye/core/certs/{}", f);
        if !Path::new(&p).exists() {
            panic!("[FATAL] missing TLS cert: {}", p);
        }
    }

    postgres_setup::prepare_postgresql_tls_installer_pki_and_verify();

    let pg_fingerprint = match installer::postgres_tls::compute_cert_fingerprint(PG_SERVER_CERT_OPT) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!(
                "CRITICAL ERROR: PostgreSQL server certificate fingerprint failed: {}",
                e
            );
            exit(1);
        }
    };

    if pg_fingerprint.len() != 64 {
        eprintln!(
            "CRITICAL ERROR: PostgreSQL fingerprint must be 64 hex chars, got {}",
            pg_fingerprint.len()
        );
        exit(1);
    }

    println!(
        "[SUCCESS] PostgreSQL TLS fingerprint from {} ({}…)",
        PG_SERVER_CERT_OPT,
        &pg_fingerprint[..8]
    );

    postgres_setup::setup_database();
    postgres_setup::verify_connection();

    if let Err(e) = config_signer::install_signed_common_config(&pg_fingerprint) {
        eprintln!("CRITICAL ERROR: {}", e);
        exit(1);
    }
    verify_signed_integrity_manifest_and_harden();
    create_systemd_services();
    install_ui_bundle_and_nginx();
    firewall_lockdown();

    filesystem::assert_boot_artifacts_for_health_gate();
    start_core_and_block_until_healthy();

    println!("\n[SECURE] Safe enterprise deployment.");
    println!("[SECURE] Repeatable idempotent install.");
    println!("[SECURE] No host breakage.");
    println!("[SECURE] Full PRD compliance.");
}
