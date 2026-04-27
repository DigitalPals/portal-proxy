use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

mod web;

const DEFAULT_STATE_DIR: &str = "/var/lib/portal-hub";
const MAX_REPLAY_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_PRUNE_ENDED_OLDER_THAN_DAYS: i64 = 14;
const LIVE_LOG_COMPACT_INTERVAL: Duration = Duration::from_millis(500);
const API_VERSION: u16 = 1;
const METADATA_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Parser)]
#[command(name = "portal-hub")]
#[command(about = "Persistent SSH session hub for Portal")]
struct Cli {
    #[arg(long, env = "PORTAL_HUB_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,

    /// Maximum bytes to retain for live and ended session logs. Set 0 to disable truncation.
    #[arg(
        long,
        env = "PORTAL_HUB_MAX_LOG_BYTES",
        default_value_t = DEFAULT_MAX_LOG_BYTES
    )]
    max_log_bytes: u64,

    /// Session output logging mode. Use disabled to avoid storing terminal output.
    #[arg(
        long,
        env = "PORTAL_HUB_LOGGING_MODE",
        value_enum,
        default_value_t = LoggingMode::Full
    )]
    logging_mode: LoggingMode,

    /// Comma-separated allowlist for target hosts. Supports exact names, '*' wildcards, and IP CIDR ranges.
    #[arg(long, env = "PORTAL_HUB_ALLOWED_TARGETS", value_delimiter = ',')]
    allowed_targets: Vec<String>,

    #[command(subcommand)]
    command: Option<CommandKind>,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    /// Parse SSH_ORIGINAL_COMMAND and execute the requested Hub command.
    Serve {
        #[arg(long)]
        stdio: bool,
    },
    /// List known Hub sessions as JSON.
    List {
        #[arg(long)]
        active: bool,
        #[arg(long)]
        include_preview: bool,
        #[arg(long, default_value_t = 512 * 1024)]
        preview_bytes: u64,
        #[arg(long, value_enum, default_value_t = ListFormat::Legacy)]
        format: ListFormat,
    },
    /// Check dependencies, state directory permissions, and runtime assumptions.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Delete old ended sessions and trim old logs.
    Prune {
        #[arg(long, default_value_t = DEFAULT_PRUNE_ENDED_OLDER_THAN_DAYS)]
        ended_older_than_days: i64,
        #[arg(long)]
        max_log_bytes: Option<u64>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Print Portal Hub version and API compatibility information.
    Version {
        #[arg(long)]
        json: bool,
    },
    /// Attach to an existing session or create it when missing.
    Attach {
        #[arg(long)]
        session_id: Uuid,
        #[arg(long)]
        target_host: String,
        #[arg(long, default_value_t = 22)]
        target_port: u16,
        #[arg(long)]
        target_user: String,
        #[arg(long, default_value_t = 80)]
        cols: u16,
        #[arg(long, default_value_t = 24)]
        rows: u16,
        #[arg(long, hide = true)]
        identity_file: Option<PathBuf>,
        #[arg(long, hide = true)]
        interactive_auth: bool,
    },
    /// Synchronize Portal hosts, settings, snippets, and encrypted vault blobs.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    /// Run the Portal Hub HTTPS/web authentication and sync API server.
    Web {
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
        #[arg(long, env = "PORTAL_HUB_PUBLIC_URL")]
        public_url: Option<String>,
    },
    /// Internal recorder used inside detached dtach sessions.
    #[command(hide = true)]
    Record {
        #[arg(long)]
        log_path: PathBuf,
        #[arg(long)]
        max_log_bytes: u64,
        #[arg(long)]
        command: String,
    },
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    /// Read the current synchronized profile and vault state.
    Get {
        #[arg(long, value_enum, default_value_t = SyncFormat::V1)]
        format: SyncFormat,
    },
    /// Replace the synchronized profile and vault state if the revision matches.
    Put {
        #[arg(long)]
        expected_revision: String,
        #[arg(long, value_enum, default_value_t = SyncFormat::V1)]
        format: SyncFormat,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ListFormat {
    /// Backward-compatible JSON array.
    Legacy,
    /// Versioned response object.
    V1,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SyncFormat {
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LoggingMode {
    Full,
    Disabled,
}

#[derive(Debug, Serialize)]
struct VersionResponse {
    version: &'static str,
    api_version: u16,
    metadata_schema_version: u16,
    min_portal_api_version: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionMetadata {
    #[serde(default = "default_metadata_schema_version")]
    schema_version: u16,
    session_id: Uuid,
    #[serde(alias = "abduco_name")]
    session_name: String,
    target_host: String,
    target_port: u16,
    target_user: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
}

fn default_metadata_schema_version() -> u16 {
    METADATA_SCHEMA_VERSION
}

#[derive(Debug, Serialize)]
struct ListedSession {
    #[serde(flatten)]
    metadata: SessionMetadata,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_output_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview_base64: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    preview_truncated: bool,
}

#[derive(Debug, Serialize)]
struct ListResponse {
    api_version: u16,
    generated_at: DateTime<Utc>,
    sessions: Vec<ListedSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncState {
    revision: String,
    profile: Value,
    vault: Value,
    updated_at: DateTime<Utc>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            revision: "0".to_string(),
            profile: default_sync_profile(),
            vault: default_sync_vault(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SyncPutRequest {
    profile: Value,
    vault: Value,
}

#[derive(Debug, Serialize)]
struct SyncResponse {
    api_version: u16,
    generated_at: DateTime<Utc>,
    revision: String,
    profile: Value,
    vault: Value,
}

#[derive(Debug, Serialize)]
struct AuditEntry {
    timestamp: DateTime<Utc>,
    event: String,
    outcome: String,
    detail: Value,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    api_version: u16,
    generated_at: DateTime<Utc>,
    state_dir: PathBuf,
    ok: bool,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    ok: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct PruneReport {
    api_version: u16,
    generated_at: DateTime<Utc>,
    dry_run: bool,
    ended_older_than_days: i64,
    max_log_bytes: u64,
    deleted_sessions: Vec<Uuid>,
    truncated_logs: Vec<TruncatedLog>,
    reclaimed_bytes: u64,
}

#[derive(Debug, Serialize)]
struct TruncatedLog {
    session_id: Uuid,
    before_bytes: u64,
    after_bytes: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn main() -> Result<()> {
    let cli = parse_cli()?;
    let state = State::new(cli.state_dir);
    let max_log_bytes = cli.max_log_bytes;
    let logging_mode = cli.logging_mode;
    let allowed_targets = cli.allowed_targets;

    match cli.command.unwrap_or(CommandKind::Serve { stdio: true }) {
        CommandKind::Serve { stdio: _ } => run_forced_command(&state),
        CommandKind::List {
            active,
            include_preview,
            preview_bytes,
            format,
        } => list_sessions(&state, active, include_preview, preview_bytes, format),
        CommandKind::Doctor { json } => doctor(&state, json),
        CommandKind::Prune {
            ended_older_than_days,
            max_log_bytes: prune_max_log_bytes,
            dry_run,
        } => prune_sessions(
            &state,
            ended_older_than_days,
            prune_max_log_bytes.unwrap_or(max_log_bytes),
            dry_run,
        ),
        CommandKind::Version { json } => version(json),
        CommandKind::Attach {
            session_id,
            target_host,
            target_port,
            target_user,
            cols,
            rows,
            identity_file,
            interactive_auth,
        } => attach_session(
            &state,
            AttachRequest {
                session_id,
                target_host,
                target_port,
                target_user,
                cols,
                rows,
                max_log_bytes,
                logging_mode,
                allowed_targets,
                identity_file,
                batch_mode: !interactive_auth,
            },
        ),
        CommandKind::Sync { command } => sync_command(&state, command),
        CommandKind::Web { bind, public_url } => web::run(state.root, bind, public_url),
        CommandKind::Record {
            log_path,
            max_log_bytes,
            command,
        } => record_session(&log_path, max_log_bytes, &command),
    }
}

fn parse_cli() -> Result<Cli> {
    let mut args: Vec<OsString> = env::args_os().collect();
    if args.len() > 1 && args[1] == "portal-hub" {
        args.remove(1);
    }

    Ok(Cli::parse_from(args))
}

fn run_forced_command(state: &State) -> Result<()> {
    let original = env::var("SSH_ORIGINAL_COMMAND")
        .context("SSH_ORIGINAL_COMMAND is missing; no Portal Hub command was requested")?;
    let mut parts = shell_words(&original)?;

    if parts.first().is_some_and(|part| part == "portal-hub") {
        parts.remove(0);
    }

    let mut args = vec!["portal-hub".to_string()];
    args.push("--state-dir".to_string());
    args.push(state.root.to_string_lossy().to_string());
    args.extend(parts);

    let cli = Cli::try_parse_from(args)?;
    match cli.command {
        Some(CommandKind::List {
            active,
            include_preview,
            preview_bytes,
            format,
        }) => list_sessions(state, active, include_preview, preview_bytes, format),
        Some(CommandKind::Doctor { json }) => doctor(state, json),
        Some(CommandKind::Prune { .. }) => {
            bail!("prune is not available through forced-command mode")
        }
        Some(CommandKind::Version { json }) => version(json),
        Some(CommandKind::Attach {
            session_id,
            target_host,
            target_port,
            target_user,
            cols,
            rows,
            identity_file,
            interactive_auth,
        }) => attach_session(
            state,
            AttachRequest {
                session_id,
                target_host,
                target_port,
                target_user,
                cols,
                rows,
                max_log_bytes: configured_max_log_bytes(),
                logging_mode: configured_logging_mode(),
                allowed_targets: configured_allowed_targets(),
                identity_file,
                batch_mode: !interactive_auth,
            },
        ),
        Some(CommandKind::Sync { command }) => sync_command(state, command),
        Some(CommandKind::Web { .. }) => {
            bail!("web is not available through forced-command mode")
        }
        Some(CommandKind::Record { .. }) => {
            bail!("record is not available through forced-command mode")
        }
        Some(CommandKind::Serve { .. }) | None => bail!("nested serve command is not supported"),
    }
}

fn list_sessions(
    state: &State,
    active_only: bool,
    include_preview: bool,
    preview_bytes: u64,
    format: ListFormat,
) -> Result<()> {
    let preview_bytes = preview_bytes.min(MAX_REPLAY_BYTES);
    let sessions = listed_sessions(state, active_only, include_preview, preview_bytes)?;
    state.audit(
        "session_list",
        "success",
        json!({
            "active_only": active_only,
            "include_preview": include_preview,
            "session_count": sessions.len(),
        }),
    )?;

    match format {
        ListFormat::Legacy => println!("{}", serde_json::to_string_pretty(&sessions)?),
        ListFormat::V1 => println!(
            "{}",
            serde_json::to_string_pretty(&ListResponse {
                api_version: API_VERSION,
                generated_at: Utc::now(),
                sessions,
            })?
        ),
    }

    Ok(())
}

fn sync_command(state: &State, command: SyncCommand) -> Result<()> {
    match command {
        SyncCommand::Get { format: _ } => sync_get(state),
        SyncCommand::Put {
            expected_revision,
            format: _,
        } => sync_put(state, &expected_revision),
    }
}

fn sync_get(state: &State) -> Result<()> {
    let sync_state = state.load_sync_state()?;
    state.audit(
        "sync_get",
        "success",
        json!({
            "revision": sync_state.revision,
            "vault_key_count": vault_key_count(&sync_state.vault),
        }),
    )?;
    print_sync_response(sync_state)
}

fn sync_put(state: &State, expected_revision: &str) -> Result<()> {
    let current = state.load_sync_state()?;
    if current.revision != expected_revision {
        state.audit(
            "sync_put",
            "conflict",
            json!({
                "expected_revision": expected_revision,
                "current_revision": current.revision,
            }),
        )?;
        bail!(
            "sync revision conflict: expected {}, current {}",
            expected_revision,
            current.revision
        );
    }

    let request: SyncPutRequest =
        serde_json::from_reader(io::stdin()).context("failed to parse sync put request")?;
    let next = SyncState {
        revision: Uuid::new_v4().to_string(),
        profile: request.profile,
        vault: request.vault,
        updated_at: Utc::now(),
    };
    state.save_sync_state(&next)?;
    state.audit(
        "sync_put",
        "success",
        json!({
            "previous_revision": expected_revision,
            "revision": next.revision,
            "vault_key_count": vault_key_count(&next.vault),
        }),
    )?;
    print_sync_response(next)
}

fn print_sync_response(sync_state: SyncState) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&SyncResponse {
            api_version: API_VERSION,
            generated_at: Utc::now(),
            revision: sync_state.revision,
            profile: sync_state.profile,
            vault: sync_state.vault,
        })?
    );
    Ok(())
}

fn default_sync_profile() -> Value {
    json!({
        "hosts": {
            "hosts": [],
            "groups": [],
        },
        "settings": {},
        "snippets": {
            "snippets": [],
        },
    })
}

fn default_sync_vault() -> Value {
    json!({
        "keys": [],
    })
}

fn vault_key_count(vault: &Value) -> usize {
    vault
        .get("keys")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn listed_sessions(
    state: &State,
    active_only: bool,
    include_preview: bool,
    preview_bytes: u64,
) -> Result<Vec<ListedSession>> {
    let mut sessions = Vec::new();
    for metadata in state.load_sessions()? {
        let socket_path = state.session_socket_path(metadata.session_id);
        let active = metadata.ended_at.is_none() && socket_path.exists();
        if active_only && !active {
            continue;
        }

        let log_path = state.session_log_path(metadata.session_id);
        let last_output_at = file_modified_at(&log_path)?;
        let (preview_base64, preview_truncated) = if include_preview {
            match read_log_tail(&log_path, preview_bytes)? {
                Some((bytes, truncated)) => (Some(BASE64_STANDARD.encode(bytes)), truncated),
                None => (None, false),
            }
        } else {
            (None, false)
        };

        sessions.push(ListedSession {
            metadata,
            active,
            last_output_at,
            preview_base64,
            preview_truncated,
        });
    }

    Ok(sessions)
}

struct AttachRequest {
    session_id: Uuid,
    target_host: String,
    target_port: u16,
    target_user: String,
    cols: u16,
    rows: u16,
    max_log_bytes: u64,
    logging_mode: LoggingMode,
    allowed_targets: Vec<String>,
    identity_file: Option<PathBuf>,
    batch_mode: bool,
}

fn attach_session(state: &State, request: AttachRequest) -> Result<()> {
    let AttachRequest {
        session_id,
        target_host,
        target_port,
        target_user,
        cols,
        rows,
        max_log_bytes,
        logging_mode,
        allowed_targets,
        identity_file,
        batch_mode,
    } = request;

    validate_target(&target_host, target_port, &target_user)?;
    validate_target_allowed(&target_host, &allowed_targets)?;
    ensure_binary("dtach").context("install dtach on the Portal Hub host")?;
    ensure_binary("ssh").context("install OpenSSH client on the Portal Hub host")?;
    if logging_mode == LoggingMode::Full {
        ensure_binary("script").context("install util-linux on the Portal Hub host")?;
    }

    state.ensure_dirs()?;
    let session_name = format!("portal-{}", session_id);
    let socket_path = state.session_socket_path(session_id);
    let now = Utc::now();
    let existing = state.load_session(session_id)?;
    let should_replay = existing
        .as_ref()
        .is_some_and(|session| session.ended_at.is_none() && socket_path.exists());
    let metadata = existing
        .map(|mut existing| {
            existing.updated_at = now;
            existing.ended_at = None;
            existing
        })
        .unwrap_or(SessionMetadata {
            schema_version: METADATA_SCHEMA_VERSION,
            session_id,
            session_name,
            target_host: target_host.clone(),
            target_port,
            target_user: target_user.clone(),
            created_at: now,
            updated_at: now,
            ended_at: None,
        });
    state.save_session(&metadata)?;

    let log_path = state.session_log_path(session_id);
    if logging_mode == LoggingMode::Full && !should_replay {
        remove_file_if_exists(&log_path)?;
    }

    let ssh_command = target_ssh_command(
        rows,
        cols,
        &state.known_hosts_path(),
        target_port,
        &target_user,
        &target_host,
        identity_file.as_deref(),
        batch_mode,
    );

    let mut command = Command::new("dtach");
    command.arg("-A").arg(&socket_path).arg("-r").arg("winch");

    match logging_mode {
        LoggingMode::Full => {
            command.arg("sh").arg("-lc").arg(record_session_command(
                &log_path,
                max_log_bytes,
                &ssh_command,
            )?);
        }
        LoggingMode::Disabled => {
            command.arg("sh").arg("-lc").arg(ssh_command);
        }
    }

    let mut child = command
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env("COLUMNS", cols.to_string())
        .env("LINES", rows.to_string())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to start dtach")?;

    if logging_mode == LoggingMode::Full && should_replay {
        thread::sleep(Duration::from_millis(75));
        replay_log_tail(&log_path, MAX_REPLAY_BYTES)?;
    }

    let status = child.wait().context("failed to wait for dtach")?;

    let mut updated = metadata;
    updated.updated_at = Utc::now();
    updated.ended_at = if socket_path.exists() {
        None
    } else {
        Some(updated.updated_at)
    };
    if logging_mode == LoggingMode::Full && updated.ended_at.is_some() && max_log_bytes > 0 {
        truncate_log_to_tail(&log_path, max_log_bytes)?;
    }
    state.save_session(&updated)?;
    state.audit(
        "session_attach",
        if status.success() {
            "success"
        } else {
            "failure"
        },
        json!({
            "session_id": session_id,
            "target_host": target_host,
            "target_port": target_port,
            "target_user": target_user,
            "ended": updated.ended_at.is_some(),
        }),
    )?;

    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => std::process::exit(code),
        None => std::process::exit(128 + status.signal().unwrap_or(1)),
    }
}

fn record_session_command(
    log_path: &Path,
    max_log_bytes: u64,
    target_command: &str,
) -> Result<String> {
    let executable =
        env::current_exe().context("failed to resolve current portal-hub executable")?;
    Ok(shell_join([
        executable.to_string_lossy().to_string(),
        "record".to_string(),
        "--log-path".to_string(),
        log_path.to_string_lossy().to_string(),
        "--max-log-bytes".to_string(),
        max_log_bytes.to_string(),
        "--command".to_string(),
        target_command.to_string(),
    ]))
}

fn record_session(log_path: &Path, max_log_bytes: u64, target_command: &str) -> Result<()> {
    ensure_binary("script").context("install util-linux on the Portal Hub host")?;

    let mut child = Command::new("script")
        .arg("-q")
        .arg("-f")
        .arg("-a")
        .arg("-c")
        .arg(target_command)
        .arg(log_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to start script recorder")?;

    let compactor = LiveLogCompactor::start(log_path.to_path_buf(), max_log_bytes);
    let status = child.wait().context("failed to wait for script recorder")?;
    if let Some(compactor) = compactor {
        compactor.stop();
    }
    if max_log_bytes > 0 {
        truncate_log_to_tail(log_path, max_log_bytes)?;
    }

    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => std::process::exit(code),
        None => std::process::exit(128 + status.signal().unwrap_or(1)),
    }
}

fn configured_max_log_bytes() -> u64 {
    env::var("PORTAL_HUB_MAX_LOG_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_LOG_BYTES)
}

#[allow(clippy::too_many_arguments)]
fn target_ssh_command(
    rows: u16,
    cols: u16,
    known_hosts_path: &Path,
    target_port: u16,
    target_user: &str,
    target_host: &str,
    identity_file: Option<&Path>,
    batch_mode: bool,
) -> String {
    let mut args = vec![
        "ssh".to_string(),
        "-F".to_string(),
        "/dev/null".to_string(),
        "-tt".to_string(),
        "-o".to_string(),
        "ForwardAgent=yes".to_string(),
        "-o".to_string(),
        if identity_file.is_some() {
            "IdentitiesOnly=yes".to_string()
        } else {
            "IdentitiesOnly=no".to_string()
        },
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        format!("UserKnownHostsFile={}", known_hosts_path.display()),
        "-p".to_string(),
        target_port.to_string(),
        "-l".to_string(),
        target_user.to_string(),
    ];
    if batch_mode {
        args.push("-o".to_string());
        args.push("BatchMode=yes".to_string());
    }
    if let Some(identity_file) = identity_file {
        args.push("-i".to_string());
        args.push(identity_file.display().to_string());
    }
    args.push(target_host.to_string());

    let ssh_invocation = shell_join(args);

    format!(
        "stty rows {} cols {} 2>/dev/null || true; exec {}",
        rows, cols, ssh_invocation
    )
}

fn configured_logging_mode() -> LoggingMode {
    match env::var("PORTAL_HUB_LOGGING_MODE")
        .unwrap_or_else(|_| "full".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "disabled" | "off" | "none" => LoggingMode::Disabled,
        _ => LoggingMode::Full,
    }
}

fn configured_allowed_targets() -> Vec<String> {
    env::var("PORTAL_HUB_ALLOWED_TARGETS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn version(json: bool) -> Result<()> {
    let response = VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        api_version: API_VERSION,
        metadata_schema_version: METADATA_SCHEMA_VERSION,
        min_portal_api_version: 1,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("portal-hub {}", response.version);
        println!("API version: {}", response.api_version);
        println!(
            "Metadata schema version: {}",
            response.metadata_schema_version
        );
    }

    Ok(())
}

fn doctor(state: &State, json: bool) -> Result<()> {
    let checks = vec![
        binary_check("dtach", "required for detached session persistence"),
        binary_check("ssh", "required for outbound target connections"),
        binary_check("script", "required for replay logs and thumbnails"),
        binary_check(
            "tailscale",
            "recommended because Portal Hub is designed for Tailscale-only exposure",
        ),
        state_dir_check(state),
        non_root_check(),
    ];

    let ok = checks.iter().all(|check| check.ok);
    let report = DoctorReport {
        api_version: API_VERSION,
        generated_at: Utc::now(),
        state_dir: state.root.clone(),
        ok,
        checks,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Portal Hub doctor");
        println!("State dir: {}", report.state_dir.display());
        for check in &report.checks {
            let status = if check.ok { "ok" } else { "fail" };
            println!("[{}] {} - {}", status, check.name, check.message);
        }
    }

    if ok {
        Ok(())
    } else {
        bail!("doctor found failing checks")
    }
}

fn binary_check(name: &str, purpose: &str) -> DoctorCheck {
    match command_exists(name) {
        Ok(true) => DoctorCheck {
            name: format!("binary:{}", name),
            ok: true,
            message: purpose.to_string(),
        },
        Ok(false) => DoctorCheck {
            name: format!("binary:{}", name),
            ok: false,
            message: format!("{}; '{}' was not found in PATH", purpose, name),
        },
        Err(error) => DoctorCheck {
            name: format!("binary:{}", name),
            ok: false,
            message: format!("failed to check '{}': {}", name, error),
        },
    }
}

fn state_dir_check(state: &State) -> DoctorCheck {
    match state.ensure_dirs().and_then(|()| state.check_writable()) {
        Ok(()) => DoctorCheck {
            name: "state_dir".to_string(),
            ok: true,
            message: "state directory exists and is writable".to_string(),
        },
        Err(error) => DoctorCheck {
            name: "state_dir".to_string(),
            ok: false,
            message: error.to_string(),
        },
    }
}

fn non_root_check() -> DoctorCheck {
    let user = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    DoctorCheck {
        name: "user".to_string(),
        ok: user != "root",
        message: if user == "root" {
            "Portal Hub should run as a dedicated non-root user".to_string()
        } else {
            format!("running as {}", user)
        },
    }
}

fn prune_sessions(
    state: &State,
    ended_older_than_days: i64,
    max_log_bytes: u64,
    dry_run: bool,
) -> Result<()> {
    state.ensure_dirs()?;
    let cutoff = Utc::now() - ChronoDuration::days(ended_older_than_days.max(0));
    let mut deleted_sessions = Vec::new();
    let mut truncated_logs = Vec::new();
    let mut reclaimed_bytes = 0u64;

    for metadata in state.load_sessions()? {
        let socket_path = state.session_socket_path(metadata.session_id);
        let active = metadata.ended_at.is_none() && socket_path.exists();
        let effective_ended_at = metadata
            .ended_at
            .or_else(|| (!active).then_some(metadata.updated_at));
        let log_path = state.session_log_path(metadata.session_id);

        if !active && effective_ended_at.is_some_and(|ended_at| ended_at <= cutoff) {
            let before = file_size(state.session_path(metadata.session_id))?
                + file_size(&log_path)?
                + file_size(&socket_path)?;
            if !dry_run {
                remove_file_if_exists(state.session_path(metadata.session_id))?;
                remove_file_if_exists(&log_path)?;
                remove_file_if_exists(&socket_path)?;
            }
            deleted_sessions.push(metadata.session_id);
            reclaimed_bytes = reclaimed_bytes.saturating_add(before);
            continue;
        }

        if !active && max_log_bytes > 0 {
            let Some((before, after)) = log_truncation_sizes(&log_path, max_log_bytes)? else {
                continue;
            };
            if !dry_run {
                truncate_log_to_tail(&log_path, max_log_bytes)?;
            }
            truncated_logs.push(TruncatedLog {
                session_id: metadata.session_id,
                before_bytes: before,
                after_bytes: after,
            });
            reclaimed_bytes = reclaimed_bytes.saturating_add(before.saturating_sub(after));
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&PruneReport {
            api_version: API_VERSION,
            generated_at: Utc::now(),
            dry_run,
            ended_older_than_days,
            max_log_bytes,
            deleted_sessions,
            truncated_logs,
            reclaimed_bytes,
        })?
    );

    Ok(())
}

fn validate_target(host: &str, port: u16, user: &str) -> Result<()> {
    if host.trim().is_empty() || host.contains('\0') || host.starts_with('-') {
        bail!("invalid target host");
    }
    if user.trim().is_empty() || user.contains('\0') || user.starts_with('-') {
        bail!("invalid target user");
    }
    if port == 0 {
        bail!("invalid target port");
    }
    Ok(())
}

fn validate_target_allowed(host: &str, allowed_targets: &[String]) -> Result<()> {
    if allowed_targets.is_empty() {
        return Ok(());
    }

    if allowed_targets
        .iter()
        .any(|pattern| target_pattern_matches(pattern, host))
    {
        return Ok(());
    }

    bail!(
        "target host '{}' is not allowed by PORTAL_HUB_ALLOWED_TARGETS",
        host
    )
}

fn target_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if pattern == "*" || pattern.eq_ignore_ascii_case(host) {
        return true;
    }
    if let Some((network, prefix)) = pattern.split_once('/') {
        return cidr_matches(network, prefix, host);
    }
    wildcard_matches(pattern, host)
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }

    let mut remainder = value.as_str();
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(pos) = remainder.find(part) else {
            return false;
        };
        if idx == 0 && !pattern.starts_with('*') && pos != 0 {
            return false;
        }
        remainder = &remainder[pos + part.len()..];
    }

    pattern.ends_with('*')
        || parts
            .last()
            .is_some_and(|last| remainder.is_empty() || last.is_empty())
}

fn cidr_matches(network: &str, prefix: &str, host: &str) -> bool {
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    let Ok(network) = network.parse::<IpAddr>() else {
        return false;
    };
    let Ok(host) = host.parse::<IpAddr>() else {
        return false;
    };

    match (network, host) {
        (IpAddr::V4(network), IpAddr::V4(host)) => ipv4_cidr_matches(network, host, prefix),
        (IpAddr::V6(network), IpAddr::V6(host)) => ipv6_cidr_matches(network, host, prefix),
        _ => false,
    }
}

fn ipv4_cidr_matches(network: Ipv4Addr, host: Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(network) & mask) == (u32::from(host) & mask)
}

fn ipv6_cidr_matches(network: Ipv6Addr, host: Ipv6Addr, prefix: u8) -> bool {
    if prefix > 128 {
        return false;
    }
    let network = u128::from(network);
    let host = u128::from(host);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (network & mask) == (host & mask)
}

fn ensure_binary(name: &str) -> Result<()> {
    if command_exists(name)? {
        Ok(())
    } else {
        bail!("required binary not found in PATH: {}", name)
    }
}

fn command_exists(name: &str) -> Result<bool> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {}", name))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to check for {}", name))?;
    Ok(status.success())
}

fn replay_log_tail(path: &Path, max_bytes: u64) -> Result<()> {
    let Some((replay, truncated)) = read_log_tail(path, max_bytes)? else {
        return Ok(());
    };

    let mut stdout = io::stdout().lock();
    if truncated {
        stdout.write_all(b"\r\n[Portal Hub replay truncated]\r\n")?;
    }
    stdout.write_all(&replay)?;
    stdout.flush()?;
    Ok(())
}

fn read_log_tail(path: &Path, max_bytes: u64) -> Result<Option<(Vec<u8>, bool)>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to open {}", path.display()));
        }
    };

    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut replay = Vec::new();
    file.read_to_end(&mut replay)?;
    if start == 0 {
        strip_script_header(&mut replay);
    }

    Ok(Some((replay, start > 0)))
}

fn file_modified_at(path: &Path) -> Result<Option<DateTime<Utc>>> {
    let modified = match fs::metadata(path).and_then(|metadata| metadata.modified()) {
        Ok(modified) => modified,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };

    Ok(Some(DateTime::<Utc>::from(modified)))
}

fn file_size(path: impl AsRef<Path>) -> Result<u64> {
    match fs::metadata(path.as_ref()) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {}", path.as_ref().display()))
        }
    }
}

struct LiveLogCompactor {
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

impl LiveLogCompactor {
    fn start(path: PathBuf, max_bytes: u64) -> Option<Self> {
        if max_bytes == 0 {
            return None;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                thread::sleep(LIVE_LOG_COMPACT_INTERVAL);
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                let _ = compact_live_log_window(&path, max_bytes);
            }
        });

        Some(Self { stop, handle })
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

fn live_log_compaction_target(max_bytes: u64) -> u64 {
    if max_bytes <= 1 {
        max_bytes
    } else {
        (max_bytes / 2).max(1)
    }
}

fn compact_live_log_window(path: &Path, max_bytes: u64) -> Result<Option<(u64, u64)>> {
    if max_bytes == 0 || file_size(path)? <= max_bytes {
        return Ok(None);
    }

    truncate_log_to_tail_in_place(path, live_log_compaction_target(max_bytes))
}

fn log_truncation_sizes(path: &Path, max_bytes: u64) -> Result<Option<(u64, u64)>> {
    let before = file_size(path)?;
    if before <= max_bytes {
        return Ok(None);
    }

    Ok(Some((before, max_bytes)))
}

fn truncate_log_to_tail_in_place(path: &Path, max_bytes: u64) -> Result<Option<(u64, u64)>> {
    let Some((before, _after)) = log_truncation_sizes(path, max_bytes)? else {
        return Ok(None);
    };
    let Some((bytes, _truncated)) = read_log_tail(path, max_bytes)? else {
        return Ok(None);
    };
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to open {} for truncation", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("failed to rewrite {}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    Ok(Some((before, bytes.len() as u64)))
}

fn truncate_log_to_tail(path: &Path, max_bytes: u64) -> Result<Option<(u64, u64)>> {
    let Some((before, after)) = log_truncation_sizes(path, max_bytes)? else {
        return Ok(None);
    };
    let Some((bytes, _truncated)) = read_log_tail(path, max_bytes)? else {
        return Ok(None);
    };
    let temp = with_temp_extension(path);
    fs::write(&temp, bytes).with_context(|| format!("failed to write {}", temp.display()))?;
    fs::rename(&temp, path).with_context(|| format!("failed to move {}", path.display()))?;
    Ok(Some((before, after)))
}

fn remove_file_if_exists(path: impl AsRef<Path>) -> Result<()> {
    match fs::remove_file(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {}", path.as_ref().display()))
        }
    }
}

fn strip_script_header(bytes: &mut Vec<u8>) {
    if !bytes.starts_with(b"Script started on ") {
        return;
    }

    if let Some(line_end) = bytes.iter().position(|byte| *byte == b'\n') {
        bytes.drain(..=line_end);
    }
}

fn shell_join(args: impl IntoIterator<Item = String>) -> String {
    args.into_iter()
        .map(|arg| shell_quote(&arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b'@')
        })
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\\''"))
}

struct State {
    root: PathBuf,
}

impl State {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(self.sessions_dir()).context("failed to create sessions directory")?;
        fs::create_dir_all(self.ssh_dir()).context("failed to create ssh state directory")?;
        fs::create_dir_all(self.logs_dir()).context("failed to create logs directory")?;
        fs::create_dir_all(self.sockets_dir()).context("failed to create sockets directory")?;
        fs::create_dir_all(self.sync_dir()).context("failed to create sync directory")?;
        Ok(())
    }

    fn check_writable(&self) -> Result<()> {
        let path = self.root.join(format!(".doctor-{}", Uuid::new_v4()));
        fs::write(&path, b"ok").with_context(|| format!("failed to write {}", path.display()))?;
        remove_file_if_exists(&path)?;
        Ok(())
    }

    fn sessions_dir(&self) -> PathBuf {
        self.root.join("sessions")
    }

    fn ssh_dir(&self) -> PathBuf {
        self.root.join("ssh")
    }

    fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    fn sockets_dir(&self) -> PathBuf {
        self.root.join("sockets")
    }

    fn sync_dir(&self) -> PathBuf {
        self.root.join("sync")
    }

    fn sync_profile_path(&self) -> PathBuf {
        self.sync_dir().join("profile.json")
    }

    fn audit_log_path(&self) -> PathBuf {
        self.sync_dir().join("audit.log")
    }

    fn known_hosts_path(&self) -> PathBuf {
        self.ssh_dir().join("known_hosts")
    }

    fn session_path(&self, id: Uuid) -> PathBuf {
        self.sessions_dir().join(format!("{}.json", id))
    }

    fn session_log_path(&self, id: Uuid) -> PathBuf {
        self.logs_dir().join(format!("{}.typescript", id))
    }

    fn session_socket_path(&self, id: Uuid) -> PathBuf {
        self.sockets_dir().join(id.to_string())
    }

    fn load_session(&self, id: Uuid) -> Result<Option<SessionMetadata>> {
        let path = self.session_path(id);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(Some(serde_json::from_str(&content)?))
    }

    fn load_sessions(&self) -> Result<Vec<SessionMetadata>> {
        self.ensure_dirs()?;
        let mut sessions = Vec::new();
        for entry in fs::read_dir(self.sessions_dir())? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            sessions.push(serde_json::from_str(&content)?);
        }
        sessions.sort_by_key(|session: &SessionMetadata| session.updated_at);
        sessions.reverse();
        Ok(sessions)
    }

    fn save_session(&self, metadata: &SessionMetadata) -> Result<()> {
        self.ensure_dirs()?;
        let path = self.session_path(metadata.session_id);
        let temp = with_temp_extension(&path);
        fs::write(&temp, serde_json::to_vec_pretty(metadata)?)
            .with_context(|| format!("failed to write {}", temp.display()))?;
        fs::rename(&temp, &path).with_context(|| format!("failed to move {}", path.display()))?;
        Ok(())
    }

    fn load_sync_state(&self) -> Result<SyncState> {
        self.ensure_dirs()?;
        let path = self.sync_profile_path();
        if !path.exists() {
            return Ok(SyncState::default());
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))
    }

    fn save_sync_state(&self, sync_state: &SyncState) -> Result<()> {
        self.ensure_dirs()?;
        let path = self.sync_profile_path();
        let temp = with_temp_extension(&path);
        fs::write(&temp, serde_json::to_vec_pretty(sync_state)?)
            .with_context(|| format!("failed to write {}", temp.display()))?;
        fs::rename(&temp, &path).with_context(|| format!("failed to move {}", path.display()))?;
        Ok(())
    }

    fn audit(&self, event: &str, outcome: &str, detail: Value) -> Result<()> {
        self.ensure_dirs()?;
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            detail,
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.audit_log_path())
            .context("failed to open audit log")?;
        writeln!(file, "{}", serde_json::to_string(&entry)?).context("failed to write audit log")
    }
}

fn with_temp_extension(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map_or_else(|| "tmp".to_string(), |ext| format!("{}.tmp", ext));
    temp.set_extension(extension);
    temp
}

fn shell_words(input: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some('\''), c) => current.push(c),
            (Some('"'), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), c) => current.push(c),
            (None, '\'' | '"') => quote = Some(ch),
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            (None, c) => current.push(c),
        }
    }

    if quote.is_some() {
        return Err(anyhow!("unterminated quote in SSH_ORIGINAL_COMMAND"));
    }

    if !current.is_empty() {
        words.push(current);
    }

    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn temp_state() -> State {
        State::new(env::temp_dir().join(format!("portal-hub-test-{}", Uuid::new_v4())))
    }

    fn metadata(id: Uuid, ended_at: Option<DateTime<Utc>>) -> SessionMetadata {
        let now = Utc::now();
        SessionMetadata {
            schema_version: METADATA_SCHEMA_VERSION,
            session_id: id,
            session_name: format!("portal-{}", id),
            target_host: "example.com".to_string(),
            target_port: 22,
            target_user: "john".to_string(),
            created_at: now,
            updated_at: ended_at.unwrap_or(now),
            ended_at,
        }
    }

    #[test]
    fn parses_shell_words() {
        assert_eq!(
            shell_words("portal-hub attach --target-host 'example host'").unwrap(),
            vec!["portal-hub", "attach", "--target-host", "example host"]
        );
    }

    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(shell_quote("simple-value"), "simple-value");
        assert_eq!(shell_quote("two words"), "'two words'");
        assert_eq!(shell_quote("john's host"), "'john'\\''s host'");
    }

    #[test]
    fn target_ssh_command_sets_pty_size_before_ssh() {
        let command = target_ssh_command(
            30,
            100,
            Path::new("/tmp/portal known_hosts"),
            2222,
            "root",
            "10.10.0.6",
            None,
            true,
        );

        assert!(command.starts_with("stty rows 30 cols 100 2>/dev/null || true; exec ssh "));
        assert!(command.contains("BatchMode=yes"));
        assert!(command.contains("'UserKnownHostsFile=/tmp/portal known_hosts'"));
    }

    #[test]
    fn target_ssh_command_supports_web_identity_and_interactive_auth() {
        let command = target_ssh_command(
            24,
            80,
            Path::new("/tmp/known_hosts"),
            22,
            "deploy",
            "example.com",
            Some(Path::new("/tmp/portal hub/key")),
            false,
        );

        assert!(!command.contains("BatchMode=yes"));
        assert!(command.contains("IdentitiesOnly=yes"));
        assert!(command.contains("-i '/tmp/portal hub/key'"));
    }

    #[test]
    fn record_session_command_uses_bounded_recorder() {
        let command =
            record_session_command(Path::new("/tmp/portal log"), 16, "ssh example.com").unwrap();

        assert!(command.contains(" record "));
        assert!(command.contains("--log-path"));
        assert!(command.contains("--max-log-bytes 16"));
        assert!(command.contains("'ssh example.com'"));
        assert!(!command.contains("output-limit"));
    }

    #[test]
    fn strips_script_header_from_replay() {
        let mut bytes = b"Script started on today\nactual output\n".to_vec();
        strip_script_header(&mut bytes);
        assert_eq!(bytes, b"actual output\n");
    }

    #[test]
    fn log_tail_reports_truncation() {
        let path = env::temp_dir().join(format!("portal-hub-test-{}.log", Uuid::new_v4()));
        fs::write(&path, b"abcdef").unwrap();

        let (bytes, truncated) = read_log_tail(&path, 3).unwrap().unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(bytes, b"def");
        assert!(truncated);
    }

    #[test]
    fn truncate_log_keeps_tail() {
        let path = env::temp_dir().join(format!("portal-hub-test-{}.log", Uuid::new_v4()));
        fs::write(&path, b"abcdef").unwrap();

        let result = truncate_log_to_tail(&path, 3).unwrap().unwrap();
        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(result, (6, 3));
        assert_eq!(bytes, b"def");
    }

    #[test]
    fn active_log_compaction_keeps_tail_without_replacing_file() {
        let path = env::temp_dir().join(format!("portal-hub-test-{}.log", Uuid::new_v4()));
        fs::write(&path, b"abcdef").unwrap();
        let inode = fs::metadata(&path).unwrap().ino();

        let result = truncate_log_to_tail_in_place(&path, 3).unwrap().unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(result, (6, 3));
        assert_eq!(metadata.ino(), inode);
        assert_eq!(bytes, b"def");
    }

    #[test]
    fn live_log_compaction_uses_moving_window() {
        let path = env::temp_dir().join(format!("portal-hub-test-{}.log", Uuid::new_v4()));
        fs::write(&path, b"abcdefghijkl").unwrap();

        let result = compact_live_log_window(&path, 8).unwrap().unwrap();
        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(result, (12, 4));
        assert_eq!(bytes, b"ijkl");
    }

    #[test]
    fn listed_sessions_filters_active_and_includes_preview() {
        let state = temp_state();
        state.ensure_dirs().unwrap();
        let active_id = Uuid::new_v4();
        let ended_id = Uuid::new_v4();
        state.save_session(&metadata(active_id, None)).unwrap();
        state
            .save_session(&metadata(ended_id, Some(Utc::now())))
            .unwrap();
        fs::write(state.session_socket_path(active_id), b"").unwrap();
        fs::write(state.session_log_path(active_id), b"hello").unwrap();

        let sessions = listed_sessions(&state, true, true, 1024).unwrap();
        let _ = fs::remove_dir_all(&state.root);

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].metadata.session_id, active_id);
        assert_eq!(
            sessions[0].preview_base64,
            Some(BASE64_STANDARD.encode(b"hello"))
        );
    }

    #[test]
    fn sync_state_defaults_to_empty_profile_and_vault() {
        let state = temp_state();
        let sync_state = state.load_sync_state().unwrap();
        let _ = fs::remove_dir_all(&state.root);

        assert_eq!(sync_state.revision, "0");
        assert_eq!(vault_key_count(&sync_state.vault), 0);
        assert!(sync_state.profile.get("hosts").is_some());
        assert!(sync_state.profile.get("settings").is_some());
        assert!(sync_state.profile.get("snippets").is_some());
    }

    #[test]
    fn sync_state_roundtrips_with_new_revision() {
        let state = temp_state();
        let sync_state = SyncState {
            revision: "rev-1".to_string(),
            profile: json!({
                "hosts": { "hosts": [{ "name": "db" }], "groups": [] },
                "settings": { "theme": "portal_default" },
                "snippets": { "snippets": [] },
            }),
            vault: json!({
                "keys": [{
                    "id": Uuid::new_v4(),
                    "name": "default",
                    "ciphertext_base64": "secret"
                }],
            }),
            updated_at: Utc::now(),
        };

        state.save_sync_state(&sync_state).unwrap();
        let loaded = state.load_sync_state().unwrap();
        let _ = fs::remove_dir_all(&state.root);

        assert_eq!(loaded.revision, "rev-1");
        assert_eq!(vault_key_count(&loaded.vault), 1);
        assert_eq!(loaded.profile["settings"]["theme"], "portal_default");
    }

    #[test]
    fn audit_writes_jsonl_without_vault_payload() {
        let state = temp_state();
        state
            .audit("sync_put", "success", json!({ "vault_key_count": 2 }))
            .unwrap();

        let audit = fs::read_to_string(state.audit_log_path()).unwrap();
        let _ = fs::remove_dir_all(&state.root);

        assert!(audit.contains("\"event\":\"sync_put\""));
        assert!(audit.contains("\"vault_key_count\":2"));
        assert!(!audit.contains("ciphertext"));
    }

    #[test]
    fn prune_deletes_old_ended_sessions() {
        let state = temp_state();
        state.ensure_dirs().unwrap();
        let id = Uuid::new_v4();
        state
            .save_session(&metadata(id, Some(Utc::now() - ChronoDuration::days(2))))
            .unwrap();
        fs::write(state.session_log_path(id), b"secret output").unwrap();

        prune_sessions(&state, 1, DEFAULT_MAX_LOG_BYTES, false).unwrap();
        let session_exists = state.session_path(id).exists();
        let log_exists = state.session_log_path(id).exists();
        let _ = fs::remove_dir_all(&state.root);

        assert!(!session_exists);
        assert!(!log_exists);
    }

    #[test]
    fn prune_truncates_recent_ended_logs() {
        let state = temp_state();
        state.ensure_dirs().unwrap();
        let id = Uuid::new_v4();
        state.save_session(&metadata(id, Some(Utc::now()))).unwrap();
        fs::write(state.session_log_path(id), b"abcdef").unwrap();

        prune_sessions(&state, 14, 3, false).unwrap();
        let bytes = fs::read(state.session_log_path(id)).unwrap();
        let _ = fs::remove_dir_all(&state.root);

        assert_eq!(bytes, b"def");
    }

    #[test]
    fn rejects_empty_target() {
        assert!(validate_target("", 22, "john").is_err());
        assert!(validate_target("example.com", 0, "john").is_err());
        assert!(validate_target("example.com", 22, "").is_err());
    }

    #[test]
    fn target_allowlist_supports_exact_wildcard_and_cidr() {
        assert!(target_pattern_matches("example.com", "example.com"));
        assert!(target_pattern_matches("*.internal", "db.internal"));
        assert!(target_pattern_matches("10.10.0.0/16", "10.10.0.206"));
        assert!(!target_pattern_matches("10.10.0.0/24", "10.10.1.2"));
    }

    #[test]
    fn target_allowlist_rejects_unmatched_hosts() {
        assert!(validate_target_allowed("db.internal", &["*.internal".to_string()]).is_ok());
        assert!(validate_target_allowed("evil.example", &["*.internal".to_string()]).is_err());
    }
}
