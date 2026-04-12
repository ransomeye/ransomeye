//! Nginx preflight and configuration validation (PRD-17).

use std::process::{exit, Command};

/// Fail installation if `nginx` is not on PATH (`which nginx`).
pub fn preflight_nginx_binary_or_exit() {
    match Command::new("which").arg("nginx").output() {
        Ok(out) if out.status.success() => {}
        _ => {
            eprintln!("CRITICAL ERROR: dependency missing — the `nginx` executable is not on PATH.");
            eprintln!("Install nginx (e.g. apt install nginx / dnf install nginx) and ensure `which nginx` succeeds.");
            eprintln!("RansomEye UI reverse proxy (TLS 1.3, CSP, rate limits) cannot be installed without nginx.");
            exit(40);
        }
    }
    println!("[SUCCESS] nginx binary present.");
}

/// Run `nginx -t` after config files are installed.
pub fn nginx_test_config_or_exit() {
    if !Command::new("nginx")
        .arg("-t")
        .status()
        .map_or(false, |s| s.success())
    {
        eprintln!("CRITICAL ERROR: nginx configuration test failed (nginx -t).");
        exit(41);
    }
    println!("[SUCCESS] nginx -t OK.");
}
