//! Sign raw manifest bytes with a 32-byte Ed25519 seed file (same format as WORM signing key).
//! Usage: sign-integrity-manifest [--mode worm-integrity|vendor-build] <manifest_in> <sig_out> [key_path] [pub_out]
//! `--mode` is accepted for compatibility and ignored (all modes use Ed25519 raw seed only).
//! Default key: /etc/ransomeye/worm_signing.key

use ed25519_dalek::{Signer, SigningKey};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_ED25519_SEED_PATH: &str = "/etc/ransomeye/worm_signing.key";
const PEM_BEGIN: &[u8] = b"-----BEGIN";

struct ParsedArgs {
    manifest_path: PathBuf,
    sig_out: PathBuf,
    signing_key_path: PathBuf,
    pub_out: Option<PathBuf>,
}

fn usage(bin: &str) {
    eprintln!(
        "usage: {} [--mode worm-integrity|vendor-build] <manifest_in> <sig_out> [key_path] [pub_out]",
        bin
    );
    eprintln!("Note: --mode is deprecated; signing always uses a 32-byte Ed25519 seed (WORM key format).");
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

fn validate_worm_seed(seed: &[u8]) -> Result<(), String> {
    if seed.len() != 32 {
        return Err(format!(
            "signing key must be exactly 32 bytes (raw Ed25519 seed), got {}",
            seed.len()
        ));
    }
    if seed.starts_with(PEM_BEGIN) {
        return Err("PEM-like prefix rejected — use raw 32-byte seed only".into());
    }
    if is_weak_worm_seed(seed) {
        return Err("weak or predictable seed pattern rejected".into());
    }
    Ok(())
}

fn load_signing_key(signing_key_path: &Path) -> Result<SigningKey, String> {
    let key_bytes = fs::read(signing_key_path).map_err(|e| format!("read {}: {}", signing_key_path.display(), e))?;
    validate_worm_seed(&key_bytes)?;
    let seed: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "seed length".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, ()> {
    let mut pos = 0usize;
    if args.len() >= 2 && args[0] == "--mode" {
        pos = 2;
    }

    let remaining = args.len().saturating_sub(pos);
    if !(2..=4).contains(&remaining) {
        return Err(());
    }

    let manifest_path = PathBuf::from(&args[pos]);
    let sig_out = PathBuf::from(&args[pos + 1]);
    let signing_key_path = if remaining >= 3 {
        PathBuf::from(&args[pos + 2])
    } else {
        PathBuf::from(DEFAULT_ED25519_SEED_PATH)
    };
    let pub_out = if remaining == 4 {
        Some(PathBuf::from(&args[pos + 3]))
    } else {
        None
    };

    Ok(ParsedArgs {
        manifest_path,
        sig_out,
        signing_key_path,
        pub_out,
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let parsed = parse_args(&args[1..]).unwrap_or_else(|_| {
        usage(&args[0]);
        std::process::exit(2);
    });

    if !parsed.signing_key_path.is_file() {
        eprintln!(
            "FATAL: Ed25519 seed file missing at {}",
            parsed.signing_key_path.display()
        );
        std::process::exit(1);
    }
    let manifest_bytes = fs::read(&parsed.manifest_path).unwrap_or_else(|e| {
        eprintln!("FATAL: read {}: {}", parsed.manifest_path.display(), e);
        std::process::exit(1);
    });
    let signing_key = load_signing_key(&parsed.signing_key_path).unwrap_or_else(|e| {
        eprintln!("FATAL: {}", e);
        std::process::exit(1);
    });
    let sig = signing_key.sign(&manifest_bytes);

    if let Some(parent) = parsed.sig_out.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&parsed.sig_out, sig.to_bytes()).unwrap_or_else(|e| {
        eprintln!("FATAL: write {}: {}", parsed.sig_out.display(), e);
        std::process::exit(1);
    });

    if let Some(pub_out) = parsed.pub_out {
        if let Some(parent) = pub_out.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&pub_out, signing_key.verifying_key().as_bytes()).unwrap_or_else(|e| {
            eprintln!("FATAL: write {}: {}", pub_out.display(), e);
            std::process::exit(1);
        });
    }

    println!(
        "OK: signed {} -> {}",
        parsed.manifest_path.display(),
        parsed.sig_out.display()
    );
}
