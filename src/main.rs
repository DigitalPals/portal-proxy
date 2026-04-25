use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const DEFAULT_STATE_DIR: &str = "/var/lib/portal-proxy";
const MAX_REPLAY_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "portal-proxy")]
#[command(about = "Persistent SSH session proxy for Portal")]
struct Cli {
    #[arg(long, env = "PORTAL_PROXY_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,

    #[command(subcommand)]
    command: Option<CommandKind>,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    /// Parse SSH_ORIGINAL_COMMAND and execute the requested proxy command.
    Serve {
        #[arg(long)]
        stdio: bool,
    },
    /// List known proxy sessions as JSON.
    List,
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
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionMetadata {
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

fn main() -> Result<()> {
    let cli = parse_cli()?;
    let state = State::new(cli.state_dir);

    match cli.command.unwrap_or(CommandKind::Serve { stdio: true }) {
        CommandKind::Serve { stdio: _ } => run_forced_command(&state),
        CommandKind::List => list_sessions(&state),
        CommandKind::Attach {
            session_id,
            target_host,
            target_port,
            target_user,
            cols,
            rows,
        } => attach_session(
            &state,
            session_id,
            target_host,
            target_port,
            target_user,
            cols,
            rows,
        ),
    }
}

fn parse_cli() -> Result<Cli> {
    let mut args: Vec<OsString> = env::args_os().collect();
    if args.len() > 1 && args[1] == "portal-proxy" {
        args.remove(1);
    }

    Ok(Cli::parse_from(args))
}

fn run_forced_command(state: &State) -> Result<()> {
    let original = env::var("SSH_ORIGINAL_COMMAND")
        .context("SSH_ORIGINAL_COMMAND is missing; no Portal Proxy command was requested")?;
    let mut parts = shell_words(&original)?;

    if parts.first().is_some_and(|part| part == "portal-proxy") {
        parts.remove(0);
    }

    let mut args = vec!["portal-proxy".to_string()];
    args.push("--state-dir".to_string());
    args.push(state.root.to_string_lossy().to_string());
    args.extend(parts);

    let cli = Cli::try_parse_from(args)?;
    match cli.command {
        Some(CommandKind::List) => list_sessions(state),
        Some(CommandKind::Attach {
            session_id,
            target_host,
            target_port,
            target_user,
            cols,
            rows,
        }) => attach_session(
            state,
            session_id,
            target_host,
            target_port,
            target_user,
            cols,
            rows,
        ),
        Some(CommandKind::Serve { .. }) | None => bail!("nested serve command is not supported"),
    }
}

fn list_sessions(state: &State) -> Result<()> {
    let sessions = state.load_sessions()?;
    println!("{}", serde_json::to_string_pretty(&sessions)?);
    Ok(())
}

fn attach_session(
    state: &State,
    session_id: Uuid,
    target_host: String,
    target_port: u16,
    target_user: String,
    cols: u16,
    rows: u16,
) -> Result<()> {
    validate_target(&target_host, target_port, &target_user)?;
    ensure_binary("dtach")?;
    ensure_binary("ssh")?;
    ensure_binary("script")?;

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
            session_id,
            session_name: session_name.clone(),
            target_host: target_host.clone(),
            target_port,
            target_user: target_user.clone(),
            created_at: now,
            updated_at: now,
            ended_at: None,
        });
    state.save_session(&metadata)?;

    let log_path = state.session_log_path(session_id);
    if !should_replay {
        let _ = fs::remove_file(&log_path);
    }

    let ssh_command = shell_join([
        "ssh".to_string(),
        "-F".to_string(),
        "/dev/null".to_string(),
        "-tt".to_string(),
        "-o".to_string(),
        "ForwardAgent=yes".to_string(),
        "-o".to_string(),
        "IdentitiesOnly=no".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        format!("UserKnownHostsFile={}", state.known_hosts_path().display()),
        "-p".to_string(),
        target_port.to_string(),
        "-l".to_string(),
        target_user.clone(),
        target_host.clone(),
    ]);

    let mut child = Command::new("dtach")
        .arg("-A")
        .arg(&socket_path)
        .arg("-r")
        .arg("none")
        .arg("script")
        .arg("-q")
        .arg("-f")
        .arg("-a")
        .arg("-c")
        .arg(ssh_command)
        .arg(&log_path)
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env("COLUMNS", cols.to_string())
        .env("LINES", rows.to_string())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to start dtach")?;

    if should_replay {
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
    let _ = state.save_session(&updated);

    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => std::process::exit(code),
        None => std::process::exit(128 + status.signal().unwrap_or(1)),
    }
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

fn ensure_binary(name: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {}", name))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to check for {}", name))?;
    if !status.success() {
        bail!("required binary not found in PATH: {}", name);
    }
    Ok(())
}

fn replay_log_tail(path: &Path, max_bytes: u64) -> Result<()> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
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

    let mut stdout = io::stdout().lock();
    if start > 0 {
        stdout.write_all(b"\r\n[Portal Proxy replay truncated]\r\n")?;
    }
    stdout.write_all(&replay)?;
    stdout.flush()?;
    Ok(())
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
}

fn with_temp_extension(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_extension("json.tmp");
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

    #[test]
    fn parses_shell_words() {
        assert_eq!(
            shell_words("portal-proxy attach --target-host 'example host'").unwrap(),
            vec!["portal-proxy", "attach", "--target-host", "example host"]
        );
    }

    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(shell_quote("simple-value"), "simple-value");
        assert_eq!(shell_quote("two words"), "'two words'");
        assert_eq!(shell_quote("john's host"), "'john'\\''s host'");
    }

    #[test]
    fn strips_script_header_from_replay() {
        let mut bytes = b"Script started on today\nactual output\n".to_vec();
        strip_script_header(&mut bytes);
        assert_eq!(bytes, b"actual output\n");
    }

    #[test]
    fn rejects_empty_target() {
        assert!(validate_target("", 22, "john").is_err());
        assert!(validate_target("example.com", 0, "john").is_err());
        assert!(validate_target("example.com", 22, "").is_err());
    }
}
