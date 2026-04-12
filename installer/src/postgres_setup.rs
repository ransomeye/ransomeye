use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Canonical DB TLS material path (PRD-14 / parity with Core `canonicalDBCertsPath`).
/// PostgreSQL MUST use this directory exclusively (deploy/postgres/postgresql.conf).
const DB_CERT_PATH: &str = "/opt/ransomeye/core/certs";
/// Full-chain trust bundle (intermediate + root); single canonical path for clients, OpenSSL, and `ssl_ca_file`.
const CANONICAL_CA_CHAIN: &str = "/opt/ransomeye/core/certs/ca-chain.crt";
const SRC_INTERMEDIATE_CA: &str = "/etc/ransomeye/pki/intermediate_ca.crt";
const SRC_ROOT_CA: &str = "/etc/ransomeye/ca.crt";

/// PostgreSQL reads TLS material as the `postgres` OS user; keys must not be root-only.
const PG_TLS_FILE_OWNER: &str = "postgres:postgres";

const EXPECTED_SSL_CERT_FILE: &str = "/opt/ransomeye/core/certs/server.crt";
const EXPECTED_SSL_KEY_FILE: &str = "/opt/ransomeye/core/certs/server.key";
const EXPECTED_SSL_CA_FILE: &str = CANONICAL_CA_CHAIN;

/// RansomEye-managed PostgreSQL via systemd unit **`ransomeye-postgres.service`** only — **OS `User`/`Group` = `postgres`** (unit name ≠ OS user; no `ransomeye-postgres` OS account in V0).
const PG_BIN: &str = "/usr/lib/postgresql/16/bin/postgres";
const PG_DATA_DIR: &str = "/opt/ransomeye/core/postgres/data";
const PG_CONFIG_FILE: &str = "/opt/ransomeye/core/postgres/postgresql.conf";
const EXPECTED_CONFIG_FILE_GUC: &str = "/opt/ransomeye/core/postgres/postgresql.conf";
const RANSOMEYE_POSTGRES_UNIT_NAME: &str = "ransomeye-postgres";
const RANSOMEYE_POSTGRES_UNIT_PATH: &str = "/etc/systemd/system/ransomeye-postgres.service";

/// Exact unit content for `/etc/systemd/system/ransomeye-postgres.service` (PRD-17 / deterministic control plane).
const RANSOMEYE_POSTGRES_UNIT: &str = r#"[Unit]
Description=RansomEye PostgreSQL (Deterministic Instance)
After=network.target

[Service]
Type=forking
User=postgres
Group=postgres

ExecStart=/usr/lib/postgresql/16/bin/pg_ctl start \
  -D /opt/ransomeye/core/postgres/data \
  -l /opt/ransomeye/core/postgres/log/postgres.log \
  -o "-c config_file=/opt/ransomeye/core/postgres/postgresql.conf"

ExecStop=/usr/lib/postgresql/16/bin/pg_ctl stop \
  -D /opt/ransomeye/core/postgres/data

ExecReload=/usr/lib/postgresql/16/bin/pg_ctl reload \
  -D /opt/ransomeye/core/postgres/data

PIDFile=/opt/ransomeye/core/postgres/data/postmaster.pid

Restart=on-failure
RestartSec=2

NoNewPrivileges=true

PrivateTmp=true
PrivateIPC=false
PrivateDevices=false

ProtectSystem=strict
ProtectHome=true
ProtectProc=invisible

RuntimeDirectory=postgresql
RuntimeDirectoryMode=0755

ReadOnlyPaths=/opt/ransomeye/core/certs

ReadWritePaths=/opt/ransomeye/core/postgres
ReadWritePaths=/opt/ransomeye/core/postgres/data
ReadWritePaths=/opt/ransomeye/core/postgres/log

ReadWritePaths=/run/postgresql
ReadWritePaths=/var/run/postgresql
ReadWritePaths=/dev/shm
ReadWritePaths=/tmp

LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"#;

/// Canonical PostgreSQL config from `deploy/postgres/` (embedded at compile time — no runtime path dependency).
const DEPLOY_POSTGRESQL_CONF: &str = include_str!("../../deploy/postgres/postgresql.conf");
const DEPLOY_PG_HBA: &str = include_str!("../../deploy/postgres/pg_hba.conf");
const DEPLOY_PG_IDENT: &str = include_str!("../../deploy/postgres/pg_ident.conf");

const PG_RUNTIME_DIR: &str = "/opt/ransomeye/core/postgres";
const PG_PATH_OPT: &str = "/opt";
const PG_PATH_VENDOR: &str = "/opt/ransomeye";
const PG_PATH_CORE: &str = "/opt/ransomeye/core";
const PG_LOG_DIR: &str = "/opt/ransomeye/core/postgres/log";
const PG_HBA_PATH: &str = "/opt/ransomeye/core/postgres/pg_hba.conf";
const PG_IDENT_PATH: &str = "/opt/ransomeye/core/postgres/pg_ident.conf";

fn pg_password() -> String {
    std::env::var("POSTGRES_PASSWORD")
        .expect("[FATAL] POSTGRES_PASSWORD required for installer")
}

/// Deterministic ownership: PostgreSQL postmaster must own PGDATA; TLS key must match (PRD-14 / PRD-17 V0).
fn assert_owner(path: &str, expected_owner: &str) {
    let out = Command::new("stat")
        .args(["-c", "%U:%G", path])
        .output()
        .unwrap_or_else(|e| panic!("[FATAL] stat {}: {}", path, e));
    if !out.status.success() {
        panic!(
            "[FATAL] stat {} failed: {}",
            path,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let got = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if got != expected_owner {
        panic!(
            "[FATAL] ownership mismatch on {}: {} expected {} (PostgreSQL V0 requires postgres:postgres for PGDATA/TLS; remove alternate service users)",
            path, got, expected_owner
        );
    }
}

/// Fail hard if mode (permission bits) or owner (`user:group` from `stat %U:%G`) do not match.
fn assert_postgres_tls_permissions(path: &str, expected_mode: u32, expected_owner: &str) {
    let out = Command::new("stat")
        .args(["-c", "%a %U:%G", path])
        .output()
        .unwrap_or_else(|e| panic!("[FATAL] stat {}: {}", path, e));
    if !out.status.success() {
        panic!(
            "[FATAL] stat {} failed: {}",
            path,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let mut parts = s.split_whitespace();
    let mode_str = parts.next().unwrap_or("");
    let owner_str = parts.next().unwrap_or("");
    if mode_str.is_empty() || owner_str.is_empty() {
        panic!(
            "[FATAL] unexpected stat output for {}: {:?}",
            path,
            s.trim()
        );
    }
    let got_mode = u32::from_str_radix(mode_str, 8).unwrap_or_else(|_| {
        panic!(
            "[FATAL] could not parse mode from stat for {}: {:?}",
            path, mode_str
        )
    });
    let exp_mode = expected_mode & 0o777;
    if got_mode != exp_mode {
        panic!(
            "[FATAL] TLS permission mismatch on {}: mode {:o} (stat {}) expected {:o}",
            path, got_mode, mode_str, exp_mode
        );
    }
    if owner_str != expected_owner {
        panic!(
            "[FATAL] TLS ownership mismatch on {}: {} expected {}",
            path, owner_str, expected_owner
        );
    }
}

fn chown_for_postgres_tls(dst: &str, owner: &str) {
    let st = Command::new("chown")
        .args([owner, dst])
        .status()
        .unwrap_or_else(|e| panic!("[FATAL] chown {} {}: {}", owner, dst, e));
    if !st.success() {
        panic!("[FATAL] chown {} {} failed (PostgreSQL must read TLS material)", owner, dst);
    }
}

fn run_chmod(path: &str, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
        .unwrap_or_else(|e| panic!("[FATAL] chmod {} → {:o}: {}", path, mode & 0o777, e));
}

fn run_chown(path: &str, owner: &str) {
    chown_for_postgres_tls(path, owner);
}

/// Enforce traversable ancestors (≥0755 on RansomEye roots) and `postgres:postgres` + 0750 on PG runtime dir before `initdb`.
fn ensure_postgres_path_permissions() {
    eprintln!("[INSTALLER][STEP] Validating PostgreSQL path traversal permissions");

    let mode_of = |path: &str| -> u32 {
        let metadata = fs::metadata(path)
            .unwrap_or_else(|e| panic!("[FATAL] Cannot stat {}: {}", path, e));
        metadata.permissions().mode() & 0o777
    };

    let require_other_execute = |path: &str| {
        let mode = mode_of(path);
        if mode & 0o001 == 0 {
            panic!(
                "[FATAL] Path not traversable (other execute required): {} (mode {:o})",
                path, mode
            );
        }
    };

    // `/opt` is host-owned — fail closed if world cannot traverse (postgres is not root).
    require_other_execute(PG_PATH_OPT);

    // Deterministic install: RansomEye roots must be ≥0755 and traversable.
    for p in [PG_PATH_VENDOR, PG_PATH_CORE] {
        if Path::new(p).exists() {
            run_chmod(p, 0o755);
        }
    }

    for p in [PG_PATH_VENDOR, PG_PATH_CORE] {
        if !Path::new(p).is_dir() {
            panic!(
                "[FATAL] Required directory missing: {} (expected after config install)",
                p
            );
        }
        let mode = mode_of(p);
        if mode < 0o755 {
            panic!(
                "[FATAL] Path must be at least mode 0755: {} (got {:o})",
                p, mode
            );
        }
        require_other_execute(p);
    }

    if !Path::new(PG_RUNTIME_DIR).is_dir() {
        panic!(
            "[FATAL] PostgreSQL runtime directory missing: {}",
            PG_RUNTIME_DIR
        );
    }

    // While still root-owned, `postgres` may need `o+x` on this path to descend; final state is 0750 + owner postgres.
    require_other_execute(PG_RUNTIME_DIR);

    run_chown(PG_RUNTIME_DIR, PG_TLS_FILE_OWNER);
    run_chmod(PG_RUNTIME_DIR, 0o750);

    println!("[INSTALLER][OK] PostgreSQL path permissions validated");
}

/// Write deploy-sourced PostgreSQL config; **`postgres:postgres`** ownership and exact mode (PRD-17).
fn install_postgres_deploy_file(content: &str, dst: &str, mode: u32, expected_owner: &str) {
    fs::write(dst, content).unwrap_or_else(|e| panic!("[FATAL] write {}: {}", dst, e));
    fs::set_permissions(dst, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", dst, e));
    chown_for_postgres_tls(dst, expected_owner);
    assert_postgres_tls_permissions(dst, mode, expected_owner);
}

/// Install `postgresql.conf`, `pg_hba.conf`, `pg_ident.conf` from repository `deploy/postgres/` before any PostgreSQL start.
fn install_postgres_config_files() {
    eprintln!(
        "[INSTALLER][STEP] Install PostgreSQL config from deploy/ → {}",
        PG_RUNTIME_DIR
    );
    fs::create_dir_all(PG_RUNTIME_DIR).unwrap_or_else(|e| {
        panic!(
            "[FATAL] create_dir_all {}: {}",
            PG_RUNTIME_DIR, e
        )
    });
    fs::create_dir_all(PG_LOG_DIR).unwrap_or_else(|e| {
        panic!("[FATAL] create_dir_all {}: {}", PG_LOG_DIR, e)
    });
    fs::set_permissions(PG_LOG_DIR, fs::Permissions::from_mode(0o750))
        .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", PG_LOG_DIR, e));
    chown_for_postgres_tls(PG_LOG_DIR, PG_TLS_FILE_OWNER);

    install_postgres_deploy_file(
        DEPLOY_POSTGRESQL_CONF,
        PG_CONFIG_FILE,
        0o644,
        PG_TLS_FILE_OWNER,
    );
    install_postgres_deploy_file(DEPLOY_PG_HBA, PG_HBA_PATH, 0o600, PG_TLS_FILE_OWNER);
    install_postgres_deploy_file(
        DEPLOY_PG_IDENT,
        PG_IDENT_PATH,
        0o600,
        PG_TLS_FILE_OWNER,
    );

    eprintln!("[INSTALLER][OK] PostgreSQL config files installed");
}

fn assert_postgres_config_integrity() {
    let required = [PG_CONFIG_FILE, PG_HBA_PATH, PG_IDENT_PATH];
    for path in required {
        if !Path::new(path).is_file() {
            panic!(
                "[FATAL] Missing required PostgreSQL config file: {}",
                path
            );
        }
    }
}

/// Run `initdb` once when `PG_VERSION` is absent — no external/manual cluster init (PRD-17).
fn initialize_postgres_data_dir() {
    let data = Path::new(PG_DATA_DIR);
    let pg_version = data.join("PG_VERSION");
    if pg_version.is_file() {
        eprintln!("[INSTALLER][OK] PostgreSQL data directory already initialized");
        return;
    }
    if data.exists() && !data.is_dir() {
        panic!(
            "[FATAL] PGDATA path exists but is not a directory: {}",
            PG_DATA_DIR
        );
    }
    if data.exists() {
        let mut nonempty = false;
        if let Ok(rd) = fs::read_dir(data) {
            nonempty = rd.count() > 0;
        }
        if nonempty {
            panic!(
                "[FATAL] PostgreSQL data directory exists but is not initialized (PG_VERSION missing; partial or corrupt state). Remove {} and retry.",
                PG_DATA_DIR
            );
        }
    }

    eprintln!("[INSTALLER][STEP] Initializing PostgreSQL data directory");

    // SCRAM auth methods require a superuser password at initdb time (`POSTGRES_PASSWORD`).
    let pw_path = std::env::temp_dir().join(format!(
        "ransomeye-initdb-pw.{}",
        std::process::id()
    ));
    let pw_display = pw_path.to_string_lossy().into_owned();
    fs::write(&pw_path, format!("{}\n", pg_password().trim_end()))
        .unwrap_or_else(|e| panic!("[FATAL] write initdb pwfile {}: {}", pw_display, e));
    fs::set_permissions(&pw_path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("[FATAL] chmod initdb pwfile: {}", e));
    chown_for_postgres_tls(&pw_display, PG_TLS_FILE_OWNER);

    let pwfile_arg = format!("--pwfile={}", pw_display);
    let status = Command::new("runuser")
        .args([
            "-u",
            "postgres",
            "--",
            "/usr/lib/postgresql/16/bin/initdb",
            "-D",
            PG_DATA_DIR,
            "--username=postgres",
            "--auth-local=scram-sha-256",
            "--auth-host=scram-sha-256",
            "--encoding=UTF8",
            "--locale=C.UTF-8",
            pwfile_arg.as_str(),
        ])
        .status();

    let _ = fs::remove_file(&pw_path);

    let status = status.unwrap_or_else(|e| panic!("[FATAL] initdb failed to execute: {}", e));

    if !status.success() {
        panic!("[FATAL] PostgreSQL initdb failed");
    }

    eprintln!("[INSTALLER][OK] PostgreSQL data directory initialized");
}

fn assert_pgdata_valid() {
    let data = Path::new(PG_DATA_DIR);
    if !data.is_dir() {
        panic!(
            "[FATAL] PostgreSQL data directory is not a directory: {}",
            PG_DATA_DIR
        );
    }
    let version = data.join("PG_VERSION");
    if !version.is_file() {
        panic!("[FATAL] PostgreSQL data directory not initialized (PG_VERSION missing)");
    }
}

fn tls_install_or_verify_identical(src: &str, dst: &str, mode: u32) {
    eprintln!(
        "[INSTALLER][STEP] PostgreSQL TLS: enforce {} → {}",
        src, dst
    );
    let want = fs::read(src).unwrap_or_else(|e| panic!("[FATAL] read {}: {}", src, e));
    if Path::new(dst).exists() {
        let got = fs::read(dst).unwrap_or_else(|e| panic!("[FATAL] read {}: {}", dst, e));
        if got != want {
            eprintln!(
                "[INSTALLER][FAIL] TLS trust mismatch: {} differs from {}",
                dst, src
            );
            panic!("INSTALLATION FAILED — TLS TRUST MISMATCH");
        }
    } else {
        fs::copy(src, dst).unwrap_or_else(|e| panic!("[FATAL] copy {} -> {}: {}", src, dst, e));
    }
    fs::set_permissions(dst, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", dst, e));
    chown_for_postgres_tls(dst, PG_TLS_FILE_OWNER);
    assert_postgres_tls_permissions(dst, mode, PG_TLS_FILE_OWNER);
    eprintln!("[INSTALLER][OK] PostgreSQL TLS file {}", dst);
}

fn stop_postgresql_units() {
    eprintln!("[INSTALLER][STEP] PostgreSQL: stop RansomEye + disable distro cluster (installer PKI sync)");
    let _ = Command::new("systemctl")
        .args(["stop", RANSOMEYE_POSTGRES_UNIT_NAME])
        .status();
    let _ = Command::new("systemctl")
        .args(["disable", "--now", "postgresql"])
        .status();
    let _ = Command::new("systemctl").args(["stop", "postgresql"]).status();
    let _ = Command::new("systemctl")
        .args(["stop", "postgresql@14-main"])
        .status();
    let _ = Command::new("systemctl")
        .args(["stop", "postgresql@16-main"])
        .status();
    let _ = Command::new("sh")
        .arg("-c")
        .arg("systemctl list-units --type=service --no-legend 'postgresql@*.service' 2>/dev/null | awk '{print $1}' | xargs -r systemctl stop 2>/dev/null || true")
        .status();
}

fn install_ransomeye_postgres_systemd_unit() {
    eprintln!(
        "[INSTALLER][STEP] Install {}",
        RANSOMEYE_POSTGRES_UNIT_PATH
    );
    fs::write(RANSOMEYE_POSTGRES_UNIT_PATH, RANSOMEYE_POSTGRES_UNIT.as_bytes())
        .unwrap_or_else(|e| {
            panic!(
                "[FATAL] write {}: {} (installer must run as root)",
                RANSOMEYE_POSTGRES_UNIT_PATH, e
            )
        });
    fs::set_permissions(
        RANSOMEYE_POSTGRES_UNIT_PATH,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", RANSOMEYE_POSTGRES_UNIT_PATH, e));
    eprintln!("[INSTALLER][OK] {}", RANSOMEYE_POSTGRES_UNIT_PATH);
}

fn dump_postgresql_failure_logs() {
    eprintln!("[INSTALLER][DIAG] --- systemctl status postgresql --no-pager ---");
    let _ = Command::new("systemctl")
        .args(["status", "postgresql", "--no-pager"])
        .status();
    eprintln!("[INSTALLER][DIAG] --- journalctl -xeu postgresql --no-pager (last 50) ---");
    let j = Command::new("journalctl")
        .args(["-xeu", "postgresql", "--no-pager", "-n", "50"])
        .output();
    match j {
        Ok(out) => {
            eprintln!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            }
        }
        Err(e) => eprintln!("[INSTALLER][DIAG] journalctl postgresql: {}", e),
    }
    for unit in ["postgresql@16-main", "postgresql@14-main"] {
        let out = Command::new("journalctl")
            .args(["-xeu", unit, "--no-pager", "-n", "25"])
            .output();
        if let Ok(o) = out {
            if o.stdout.is_empty() {
                continue;
            }
            eprintln!(
                "[INSTALLER][DIAG] --- journalctl -xeu {} (last 25) ---",
                unit
            );
            eprintln!("{}", String::from_utf8_lossy(&o.stdout));
        }
    }
    dump_ransomeye_postgres_failure_logs();
}

fn dump_ransomeye_postgres_failure_logs() {
    eprintln!(
        "[INSTALLER][DIAG] --- systemctl status {} --no-pager ---",
        RANSOMEYE_POSTGRES_UNIT_NAME
    );
    let _ = Command::new("systemctl")
        .args(["status", RANSOMEYE_POSTGRES_UNIT_NAME, "--no-pager"])
        .status();
    eprintln!(
        "[INSTALLER][DIAG] --- journalctl -xeu {} --no-pager (last 80) ---",
        RANSOMEYE_POSTGRES_UNIT_NAME
    );
    let j = Command::new("journalctl")
        .args([
            "-xeu",
            RANSOMEYE_POSTGRES_UNIT_NAME,
            "--no-pager",
            "-n",
            "80",
        ])
        .output();
    match j {
        Ok(out) => {
            eprintln!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            }
        }
        Err(e) => eprintln!(
            "[INSTALLER][DIAG] journalctl {}: {}",
            RANSOMEYE_POSTGRES_UNIT_NAME, e
        ),
    }
}

fn assert_postgresql_listen_loopback_5432() {
    let ss_out = Command::new("ss")
        .args(["-ltn"])
        .output()
        .expect("failed to run ss");

    let stdout = String::from_utf8_lossy(&ss_out.stdout);

    let mut found_valid = false;

    for line in stdout.lines() {
        if line.contains(":5432") {
            if line.contains("127.0.0.1:5432") {
                found_valid = true;
            }

            if line.contains("0.0.0.0:5432")
                || line.contains("*:5432")
                || line.contains("[::1]:5432")
            {
                dump_postgresql_failure_logs();
                panic!("[FATAL] PostgreSQL bound to non-loopback interface (PRD violation)");
            }
        }
    }

    if !found_valid {
        dump_postgresql_failure_logs();
        panic!("[FATAL] PostgreSQL not bound to 127.0.0.1:5432");
    }
}

/// `SHOW config_file` must be the RansomEye path — never `/etc/postgresql/...`.
fn verify_postgresql_config_file_guc() {
    eprintln!("[INSTALLER][STEP] PostgreSQL: verify config_file (RansomEye-owned postgresql.conf)");
    let conninfo = psql_conninfo_verify_full("postgres", "postgres");
    let out = Command::new("psql")
        .arg("-d")
        .arg(&conninfo)
        .arg("-tAc")
        .arg("SHOW config_file;")
        .env("PGPASSWORD", pg_password())
        .output()
        .unwrap_or_else(|e| panic!("[FATAL] psql SHOW config_file: {}", e));
    if !out.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
        dump_postgresql_failure_logs();
        panic!("[FATAL] psql SHOW config_file failed");
    }
    let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if val.contains("/etc/postgresql") || val != EXPECTED_CONFIG_FILE_GUC {
        eprintln!(
            "[INSTALLER][FAIL] SHOW config_file → {:?} (expected {:?})",
            val, EXPECTED_CONFIG_FILE_GUC
        );
        dump_postgresql_failure_logs();
        panic!("[FATAL] PostgreSQL using non-RansomEye config");
    }
    eprintln!(
        "[INSTALLER][OK] PostgreSQL config_file = {}",
        EXPECTED_CONFIG_FILE_GUC
    );
}

/// P0: PostgreSQL MUST be supervised by systemd — no manual/orphan `postgres` processes.
fn assert_postgresql_managed_by_systemd() {
    eprintln!(
        "[INSTALLER][STEP] Verify PostgreSQL is active under {} (systemd control plane)",
        RANSOMEYE_POSTGRES_UNIT_NAME
    );
    let out = Command::new("systemctl")
        .args(["is-active", RANSOMEYE_POSTGRES_UNIT_NAME])
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "[FATAL] systemctl is-active {}: {}",
                RANSOMEYE_POSTGRES_UNIT_NAME, e
            )
        });
    let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if state != "active" {
        eprintln!(
            "[INSTALLER][FAIL] systemctl is-active {} → {:?}",
            RANSOMEYE_POSTGRES_UNIT_NAME, state
        );
        dump_postgresql_failure_logs();
        panic!("[FATAL] PostgreSQL is not running under ransomeye-postgres.service (systemd required; manual/orphan start forbidden)");
    }
    eprintln!(
        "[INSTALLER][OK] {} is-active",
        RANSOMEYE_POSTGRES_UNIT_NAME
    );
}

/// Start and validate PostgreSQL **only** via `ransomeye-postgres.service` (no manual `postgres` process).
fn restart_postgresql_units() {
    println!("[INSTALLER][STEP] Starting RansomEye PostgreSQL via systemd");

    if !Path::new(PG_BIN).is_file() {
        panic!(
            "[FATAL] PostgreSQL binary missing at {} (install PostgreSQL 16 server packages)",
            PG_BIN
        );
    }
    if !Path::new(PG_DATA_DIR).is_dir() {
        panic!(
            "[FATAL] PostgreSQL data directory missing: {}",
            PG_DATA_DIR
        );
    }
    if !Path::new(PG_CONFIG_FILE).is_file() {
        panic!(
            "[FATAL] RansomEye postgresql.conf missing: {}",
            PG_CONFIG_FILE
        );
    }

    assert_owner(PG_DATA_DIR, PG_TLS_FILE_OWNER);
    assert_owner(EXPECTED_SSL_KEY_FILE, PG_TLS_FILE_OWNER);

    let st = Command::new("systemctl")
        .arg("daemon-reexec")
        .status()
        .unwrap_or_else(|e| panic!("[FATAL] systemctl daemon-reexec: {}", e));
    if !st.success() {
        dump_postgresql_failure_logs();
        panic!("[FATAL] systemctl daemon-reexec failed");
    }

    let st = Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .unwrap_or_else(|e| panic!("[FATAL] systemctl daemon-reload: {}", e));
    if !st.success() {
        dump_postgresql_failure_logs();
        panic!("[FATAL] systemctl daemon-reload failed");
    }

    let status = Command::new("systemctl")
        .args(["restart", RANSOMEYE_POSTGRES_UNIT_NAME])
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "[FATAL] systemctl restart {}: {}",
                RANSOMEYE_POSTGRES_UNIT_NAME, e
            )
        });

    if !status.success() {
        dump_postgresql_failure_logs();
        panic!("[FATAL] Failed to start ransomeye-postgres.service");
    }

    let en = Command::new("systemctl")
        .args(["enable", RANSOMEYE_POSTGRES_UNIT_NAME])
        .status()
        .unwrap_or_else(|e| panic!("[FATAL] systemctl enable {}: {}", RANSOMEYE_POSTGRES_UNIT_NAME, e));
    if !en.success() {
        dump_postgresql_failure_logs();
        panic!(
            "[FATAL] systemctl enable {} failed",
            RANSOMEYE_POSTGRES_UNIT_NAME
        );
    }

    wait_pg_isready_loop();

    assert_postgresql_listen_loopback_5432();

    verify_postgresql_config_file_guc();

    assert_postgresql_managed_by_systemd();

    println!("[INSTALLER][OK] PostgreSQL running under RansomEye systemd control");
}

fn pg_isready_ok() -> bool {
    Command::new("pg_isready")
        .args(["-q", "-h", "127.0.0.1", "-p", "5432"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Ten one-second polls; diagnostic dump at `i == 2` (no blind silence).
fn wait_pg_isready_loop() {
    for i in 0..10 {
        if pg_isready_ok() {
            eprintln!("[INSTALLER][OK] pg_isready 127.0.0.1:5432");
            return;
        }
        if i == 2 {
            dump_postgresql_failure_logs();
            dump_ransomeye_postgres_failure_logs();
        }
        thread::sleep(Duration::from_secs(1));
    }
    dump_postgresql_failure_logs();
    panic!("[FATAL] PostgreSQL did not become ready within 10 seconds");
}

/// Fail hard if the deployed `postgresql.conf` still references non-canonical `pg_server.*` TLS files.
fn assert_deployed_postgresql_conf_no_pg_server_paths() {
    const CONF: &str = "/opt/ransomeye/core/postgres/postgresql.conf";
    if !Path::new(CONF).is_file() {
        return;
    }
    let content = fs::read_to_string(CONF)
        .unwrap_or_else(|e| panic!("[FATAL] read {}: {}", CONF, e));
    if content.contains("pg_server.crt") || content.contains("pg_server.key") {
        panic!("[FATAL] PostgreSQL TLS misconfiguration — non-canonical certificate path detected (pg_server.* forbidden)");
    }
}

fn verify_postgresql_ssl_guc_paths() {
    eprintln!("[INSTALLER][STEP] PostgreSQL: verify ssl_cert_file / ssl_key_file / ssl_ca_file");
    let conninfo = psql_conninfo_verify_full("postgres", "postgres");
    let checks = [
        ("ssl_cert_file", EXPECTED_SSL_CERT_FILE),
        ("ssl_key_file", EXPECTED_SSL_KEY_FILE),
        ("ssl_ca_file", EXPECTED_SSL_CA_FILE),
    ];
    for (guc, expected) in checks {
        let q = format!("SHOW {guc};");
        let out = Command::new("psql")
            .arg("-d")
            .arg(&conninfo)
            .arg("-tAc")
            .arg(&q)
            .env("PGPASSWORD", pg_password())
            .output()
            .unwrap_or_else(|e| panic!("[FATAL] psql SHOW {guc}: {}", e));
        if !out.status.success() {
            eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            dump_postgresql_failure_logs();
            panic!("[FATAL] psql SHOW {guc} failed");
        }
        let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if (guc == "ssl_cert_file" || guc == "ssl_key_file") && val.contains("pg_server") {
            dump_postgresql_failure_logs();
            panic!("[FATAL] PostgreSQL TLS misconfiguration — non-canonical certificate path detected (pg_server.* forbidden)");
        }
        if val != expected {
            eprintln!(
                "[INSTALLER][FAIL] SHOW {} → {:?} (expected {:?})",
                guc, val, expected
            );
            dump_postgresql_failure_logs();
            panic!("[FATAL] PostgreSQL not using installer-managed TLS paths");
        }
    }
    eprintln!("[INSTALLER][OK] PostgreSQL GUC TLS paths verified (full-chain trust enforced)");
}

/// Full trust store for OpenSSL / client verification: **intermediate first**, then root (order critical).
fn write_ca_chain_file() {
    eprintln!(
        "[INSTALLER][STEP] PostgreSQL TLS: build {} (intermediate + root)",
        CANONICAL_CA_CHAIN
    );
    let intermediate = fs::read_to_string(SRC_INTERMEDIATE_CA)
        .unwrap_or_else(|e| panic!("[FATAL] read {}: {}", SRC_INTERMEDIATE_CA, e));
    let root = fs::read_to_string(SRC_ROOT_CA)
        .unwrap_or_else(|e| panic!("[FATAL] read {}: {}", SRC_ROOT_CA, e));
    let mut chain = intermediate.trim_end().to_string();
    chain.push('\n');
    chain.push_str(root.trim_end());
    chain.push('\n');
    fs::write(CANONICAL_CA_CHAIN, chain.as_bytes())
        .unwrap_or_else(|e| panic!("[FATAL] write {}: {}", CANONICAL_CA_CHAIN, e));
    fs::set_permissions(CANONICAL_CA_CHAIN, fs::Permissions::from_mode(0o444))
        .unwrap_or_else(|e| panic!("[FATAL] chmod {}: {}", CANONICAL_CA_CHAIN, e));
    chown_for_postgres_tls(CANONICAL_CA_CHAIN, PG_TLS_FILE_OWNER);
    assert_postgres_tls_permissions(CANONICAL_CA_CHAIN, 0o444, PG_TLS_FILE_OWNER);
    eprintln!("[INSTALLER][OK] wrote {}", CANONICAL_CA_CHAIN);
}

fn verify_postgres_tls_chain_openssl() {
    eprintln!("[INSTALLER][STEP] openssl s_client STARTTLS postgres (full chain verify)");
    let chain = CANONICAL_CA_CHAIN.to_string();
    let out = Command::new("openssl")
        .args([
            "s_client",
            "-starttls",
            "postgres",
            "-connect",
            "127.0.0.1:5432",
            "-CAfile",
            &chain,
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("[FATAL] openssl s_client: {}", e));
    let text = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{}{}", text, err);
    if !combined.contains("Verify return code: 0 (ok)") {
        eprintln!("[INSTALLER][FAIL] openssl output:\n{}", combined);
        panic!("[FATAL] PostgreSQL TLS chain incomplete or invalid");
    }
    println!("[INSTALLER][OK] PostgreSQL TLS verified (chain trusted)");
}

/// Stop distro PostgreSQL, install TLS under `/opt/ransomeye/core/certs/`, write `ransomeye-postgres.service`,
/// then `systemctl restart ransomeye-postgres`, `pg_isready`, GUC checks, and `openssl s_client`.
pub fn prepare_postgresql_tls_installer_pki_and_verify() {
    stop_postgresql_units();

    tls_install_or_verify_identical(
        "/etc/ransomeye/server.crt",
        "/opt/ransomeye/core/certs/server.crt",
        0o444,
    );
    tls_install_or_verify_identical(
        "/etc/ransomeye/server.key",
        "/opt/ransomeye/core/certs/server.key",
        0o400,
    );
    tls_install_or_verify_identical(
        "/etc/ransomeye/ca.crt",
        "/opt/ransomeye/core/certs/ca.crt",
        0o444,
    );

    write_ca_chain_file();

    install_postgres_config_files();
    ensure_postgres_path_permissions();
    assert_postgres_config_integrity();
    assert_owner(PG_HBA_PATH, PG_TLS_FILE_OWNER);
    assert_owner(PG_IDENT_PATH, PG_TLS_FILE_OWNER);

    initialize_postgres_data_dir();
    assert_pgdata_valid();
    assert_owner(PG_DATA_DIR, PG_TLS_FILE_OWNER);

    install_ransomeye_postgres_systemd_unit();

    assert_deployed_postgresql_conf_no_pg_server_paths();
    restart_postgresql_units();
    println!(
        "[INSTALLER][DEBUG] Using sslmode=verify-full with CA={}",
        CANONICAL_CA_CHAIN
    );
    run_psql_result("SELECT 1;", "postgres", "postgres").unwrap_or_else(|e| {
        eprintln!("{}", e);
        dump_postgresql_failure_logs();
        panic!("[FATAL] PostgreSQL TLS connection failed after pg_isready");
    });
    verify_postgresql_ssl_guc_paths();
    verify_postgres_tls_chain_openssl();
}

/// Belt-and-suspenders start (e.g. after external restarts). Primary bring-up is
/// [`prepare_postgresql_tls_installer_pki_and_verify`].
#[allow(dead_code)]
pub fn wait_for_postgres_ready() {
    println!("[INSTALLER] Ensuring PostgreSQL is running (ransomeye-postgres.service)");
    if pg_isready_ok() {
        verify_postgresql_config_file_guc();
        assert_postgresql_managed_by_systemd();
        println!("[INSTALLER] PostgreSQL already accepting connections");
        return;
    }
    stop_postgresql_units();
    if !Path::new(RANSOMEYE_POSTGRES_UNIT_PATH).is_file() {
        install_ransomeye_postgres_systemd_unit();
    }
    if !Path::new(PG_BIN).is_file() {
        panic!("[FATAL] PostgreSQL binary missing at {}", PG_BIN);
    }
    if !Path::new(PG_DATA_DIR).is_dir() {
        panic!("[FATAL] PostgreSQL data directory missing: {}", PG_DATA_DIR);
    }
    if !Path::new(PG_CONFIG_FILE).is_file() {
        panic!(
            "[FATAL] RansomEye postgresql.conf missing: {}",
            PG_CONFIG_FILE
        );
    }
    restart_postgresql_units();
    println!("[INSTALLER] PostgreSQL is accepting connections");
}

/// libpq connection string: TLS 1.3 channel with `verify-full` (no sslmode downgrade).
fn psql_conninfo_verify_full(db: &str, user: &str) -> String {
    format!(
        "host=127.0.0.1 port=5432 dbname={} user={} sslmode=verify-full sslrootcert={} sslcert={}/client.crt sslkey={}/client.key",
        db, user, CANONICAL_CA_CHAIN, DB_CERT_PATH, DB_CERT_PATH
    )
}

pub fn setup_database() {
    let db_user = "ransomeye";
    let db_password = "ransomeye@12345";
    let db_name = "ransomeye";

    println!("[INSTALLER] Setting up PostgreSQL database and roles");

    // Create user (idempotent DO block)
    let create_user = format!(
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{}') THEN CREATE ROLE {} WITH LOGIN PASSWORD '{}'; END IF; END $$;",
        db_user, db_user, db_password
    );

    // CREATE DATABASE cannot run inside a DO/transaction block — use a standalone statement.
    let create_db = format!("CREATE DATABASE {} OWNER {}", db_name, db_user);

    let grant = format!(
        "GRANT ALL PRIVILEGES ON DATABASE {} TO {};",
        db_name, db_user
    );

    run_psql(&create_user);
    if !database_exists(db_name) {
        run_psql(&create_db);
    }
    run_psql(&grant);

    // Extensions require elevated session; installer phase only (PRD-17).
    run_psql_on_db(
        "CREATE EXTENSION IF NOT EXISTS pgcrypto; CREATE EXTENSION IF NOT EXISTS timescaledb;",
        db_name,
    );

    println!("[INSTALLER] PostgreSQL setup complete");
}

pub fn verify_connection() {
    let conninfo = psql_conninfo_verify_full("ransomeye", "ransomeye");
    let status = Command::new("psql")
        .arg("-d")
        .arg(&conninfo)
        .arg("-c")
        .arg("\\q")
        .env("PGPASSWORD", "ransomeye@12345")
        .status()
        .expect("psql failed");

    if !status.success() {
        panic!("[FATAL] DB TLS verification failed");
    }
    println!("[INSTALLER] DB TLS connectivity verified (verify-full, ransomeye → ransomeye)");
}

fn database_exists(name: &str) -> bool {
    let q = format!("SELECT 1 FROM pg_database WHERE datname = '{}'", name);
    let conninfo = psql_conninfo_verify_full("postgres", "postgres");
    let out = Command::new("psql")
        .arg("-d")
        .arg(&conninfo)
        .arg("-tAc")
        .arg(&q)
        .env("PGPASSWORD", pg_password())
        .output()
        .unwrap_or_else(|e| panic!("failed to execute psql: {}", e));
    if !out.status.success() {
        let _ = std::io::stderr().write_all(&out.stderr);
        panic!("[FATAL] PostgreSQL setup failed (database_exists query)");
    }
    String::from_utf8_lossy(&out.stdout).trim() == "1"
}

/// `psql` with `ON_ERROR_STOP=1`, `verify-full` libpq URL; returns stderr (or stdout) on failure.
fn run_psql_result(query: &str, database: &str, user: &str) -> Result<(), String> {
    let conninfo = psql_conninfo_verify_full(database, user);
    let output = Command::new("psql")
        .arg("-d")
        .arg(&conninfo)
        .arg("-v")
        .arg("ON_ERROR_STOP=1")
        .arg("-c")
        .arg(query)
        .env(
            "PGPASSWORD",
            std::env::var("POSTGRES_PASSWORD").expect("[FATAL] POSTGRES_PASSWORD required"),
        )
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        let mut msg = String::from_utf8_lossy(&output.stderr).to_string();
        if msg.trim().is_empty() {
            msg = String::from_utf8_lossy(&output.stdout).to_string();
        }
        return Err(msg);
    }
    Ok(())
}

fn run_psql(query: &str) {
    match run_psql_result(query, "postgres", "postgres") {
        Ok(()) => {}
        Err(e) => {
            eprintln!("{}", e);
            panic!("[FATAL] PostgreSQL setup failed");
        }
    }
}

fn run_psql_on_db(query: &str, database: &str) {
    match run_psql_result(query, database, "postgres") {
        Ok(()) => {}
        Err(e) => {
            eprintln!("{}", e);
            panic!("[FATAL] PostgreSQL setup failed");
        }
    }
}
