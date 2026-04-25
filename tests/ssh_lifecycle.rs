use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn portal_proxy() -> &'static str {
    env!("CARGO_BIN_EXE_portal-proxy")
}

#[test]
fn attach_detach_reconnect_replay_and_exit() {
    if missing_any(&["sshd", "ssh", "ssh-keygen", "dtach", "script"]) {
        eprintln!("skipping SSH lifecycle test; required system dependencies are missing");
        return;
    }

    let fixture = SshFixture::start().expect("start local sshd fixture");
    let state_dir = TempDir::new("portal-proxy-state");
    let home_dir = TempDir::new("portal-proxy-home");
    let home_ssh = home_dir.path.join(".ssh");
    fs::create_dir_all(&home_ssh).unwrap();
    fs::copy(&fixture.client_key, home_ssh.join("id_ed25519")).unwrap();
    set_private_key_permissions(&home_ssh.join("id_ed25519"));

    let session_id = uuid::Uuid::new_v4().to_string();
    let mut first = spawn_attach(&fixture, &state_dir.path, &home_dir.path, &session_id);
    first.stdin.write_all(b"echo PROXY_FIRST\n").unwrap();
    first
        .reader
        .wait_for(b"PROXY_FIRST", Duration::from_secs(10));
    first.child.kill().ok();
    first.child.wait().ok();

    let active = list_active_sessions(&state_dir.path);
    assert_eq!(active, 1);

    let mut second = spawn_attach(&fixture, &state_dir.path, &home_dir.path, &session_id);
    second
        .reader
        .wait_for(b"PROXY_FIRST", Duration::from_secs(10));
    second
        .stdin
        .write_all(b"echo PROXY_SECOND\nexit\n")
        .unwrap();
    second
        .reader
        .wait_for(b"PROXY_SECOND", Duration::from_secs(10));
    wait_for_child_exit(&mut second.child, Duration::from_secs(10));

    let active = list_active_sessions(&state_dir.path);
    assert_eq!(active, 0);
}

struct AttachProcess {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: OutputReader,
}

fn spawn_attach(
    fixture: &SshFixture,
    state_dir: &Path,
    home_dir: &Path,
    session_id: &str,
) -> AttachProcess {
    let argv = vec![
        portal_proxy().to_string(),
        "--state-dir".to_string(),
        state_dir.display().to_string(),
        "--max-log-bytes".to_string(),
        "1048576".to_string(),
        "attach".to_string(),
        "--session-id".to_string(),
        session_id.to_string(),
        "--target-host".to_string(),
        "127.0.0.1".to_string(),
        "--target-port".to_string(),
        fixture.port.to_string(),
        "--target-user".to_string(),
        fixture.user.clone(),
        "--cols".to_string(),
        "80".to_string(),
        "--rows".to_string(),
        "24".to_string(),
    ];
    let command = argv
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");

    let mut child = Command::new(command_path("script"))
        .env("HOME", home_dir)
        .arg("-q")
        .arg("-e")
        .arg("-f")
        .arg("-c")
        .arg(command)
        .arg("/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn portal-proxy attach");

    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let reader = OutputReader::new(stdout);
    AttachProcess {
        child,
        stdin,
        reader,
    }
}

fn list_active_sessions(state_dir: &Path) -> usize {
    let output = Command::new(portal_proxy())
        .arg("--state-dir")
        .arg(state_dir)
        .arg("list")
        .arg("--active")
        .arg("--format")
        .arg("v1")
        .output()
        .expect("list sessions");
    assert!(
        output.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    json["sessions"].as_array().unwrap().len()
}

struct OutputReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
}

impl OutputReader {
    fn new(mut stdout: std::process::ChildStdout) -> Self {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stdout.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            rx,
            buffer: Vec::new(),
        }
    }

    fn wait_for(&mut self, needle: &[u8], timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if contains_bytes(&self.buffer, needle) {
                return;
            }
            if let Ok(bytes) = self.rx.recv_timeout(Duration::from_millis(100)) {
                self.buffer.extend(bytes);
            }
        }
        panic!(
            "timed out waiting for {:?}; output was:\n{}",
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&self.buffer)
        );
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    child.kill().ok();
    panic!("child did not exit within {:?}", timeout);
}

struct SshFixture {
    root: TempDir,
    child: Child,
    user: String,
    port: u16,
    client_key: PathBuf,
    sshd_log: PathBuf,
}

impl SshFixture {
    fn start() -> std::io::Result<Self> {
        let root = TempDir::new("portal-proxy-sshd");
        let host_key = root.path.join("host_ed25519");
        let client_key = root.path.join("client_ed25519");
        let authorized_keys = root.path.join("authorized_keys");
        run_success(
            Command::new(command_path("ssh-keygen"))
                .arg("-t")
                .arg("ed25519")
                .arg("-q")
                .arg("-N")
                .arg("")
                .arg("-f")
                .arg(&host_key),
        );
        run_success(
            Command::new(command_path("ssh-keygen"))
                .arg("-t")
                .arg("ed25519")
                .arg("-q")
                .arg("-N")
                .arg("")
                .arg("-f")
                .arg(&client_key),
        );
        fs::copy(client_key.with_extension("pub"), &authorized_keys)?;

        let port = free_port();
        let user = std::env::var("USER").unwrap_or_else(|_| "runner".to_string());
        let config = root.path.join("sshd_config");
        fs::write(
            &config,
            format!(
                r#"
Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {pid}
AuthorizedKeysFile {authorized_keys}
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PubkeyAuthentication yes
StrictModes no
AllowUsers {user}
LogLevel ERROR
"#,
                port = port,
                host_key = host_key.display(),
                pid = root.path.join("sshd.pid").display(),
                authorized_keys = authorized_keys.display(),
                user = user
            ),
        )?;

        let sshd_log = root.path.join("sshd.log");
        let child = Command::new(command_path("sshd"))
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&sshd_log)?)
            .spawn()?;

        let fixture = Self {
            root,
            child,
            user,
            port,
            client_key,
            sshd_log,
        };
        fixture.wait_until_ready();
        Ok(fixture)
    }

    fn wait_until_ready(&self) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            let status = Command::new(command_path("ssh"))
                .arg("-i")
                .arg(&self.client_key)
                .arg("-p")
                .arg(self.port.to_string())
                .arg("-o")
                .arg("BatchMode=yes")
                .arg("-o")
                .arg("StrictHostKeyChecking=no")
                .arg("-o")
                .arg("UserKnownHostsFile=/dev/null")
                .arg(format!("{}@127.0.0.1", self.user))
                .arg("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if status.is_ok_and(|status| status.success()) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let sshd_status = if self.child.id() == 0 {
            "unknown".to_string()
        } else {
            format!("pid {}", self.child.id())
        };
        panic!(
            "sshd fixture did not become ready on port {} ({}); root: {}; sshd log:\n{}",
            self.port,
            sshd_status,
            self.root.path.display(),
            fs::read_to_string(&self.sshd_log)
                .unwrap_or_else(|error| format!("failed to read sshd log: {}", error))
        );
    }
}

impl Drop for SshFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_success(command: &mut Command) {
    let status = command.status().expect("run command");
    assert!(status.success(), "command failed: {:?}", command);
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn missing_any(names: &[&str]) -> bool {
    names.iter().any(|name| {
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {}", name))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_or(true, |status| !status.success())
    })
}

fn command_path(name: &str) -> PathBuf {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {}", name))
        .output()
        .unwrap_or_else(|error| panic!("failed to resolve {}: {}", name, error));
    assert!(
        output.status.success(),
        "failed to resolve {}: {}",
        name,
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', r#"'\''"#))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_private_key_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn set_private_key_permissions(_path: &Path) {}
