use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

fn portal_proxy() -> &'static str {
    env!("CARGO_BIN_EXE_portal-proxy")
}

#[test]
fn attach_detach_reconnect_replay_and_exit() {
    if missing_any(&[
        "sshd",
        "ssh",
        "ssh-add",
        "ssh-agent",
        "ssh-keygen",
        "dtach",
        "script",
    ]) {
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
    first
        .stdin
        .write_all(b"echo PROXY_FIRST; sleep 30\n")
        .unwrap();
    first
        .reader
        .wait_for_occurrences(b"PROXY_FIRST", 2, Duration::from_secs(10));
    first.stdin.write_all(&[0x1c]).unwrap();
    wait_for_attach_exit(first, Duration::from_secs(10));

    let active = list_active_sessions(&state_dir.path);
    assert_eq!(active, 1);

    let mut second = spawn_attach(&fixture, &state_dir.path, &home_dir.path, &session_id);
    second
        .reader
        .wait_for(b"PROXY_FIRST", Duration::from_secs(10));
    second.stdin.write_all(&[0x03]).unwrap();
    second
        .stdin
        .write_all(b"echo PROXY_SECOND\nexit\n")
        .unwrap();
    second
        .reader
        .wait_for(b"PROXY_SECOND", Duration::from_secs(10));
    wait_for_attach_exit(second, Duration::from_secs(10));

    let active = list_active_sessions(&state_dir.path);
    assert_eq!(active, 0);
}

struct AttachProcess {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    child_killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
    stdin: Box<dyn Write + Send>,
    reader: OutputReader,
}

fn spawn_attach(
    fixture: &SshFixture,
    state_dir: &Path,
    home_dir: &Path,
    session_id: &str,
) -> AttachProcess {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open attach pty");
    let argv = vec![
        portal_proxy().into(),
        "--state-dir".into(),
        state_dir.as_os_str().to_os_string(),
        "--max-log-bytes".into(),
        "1048576".into(),
        "attach".into(),
        "--session-id".into(),
        session_id.into(),
        "--target-host".into(),
        "127.0.0.1".into(),
        "--target-port".into(),
        fixture.port.to_string().into(),
        "--target-user".into(),
        fixture.user.clone().into(),
        "--cols".into(),
        "80".into(),
        "--rows".into(),
        "24".into(),
    ];
    let mut command = CommandBuilder::from_argv(argv);
    command.env("HOME", home_dir);
    command.env("SSH_AUTH_SOCK", &fixture.agent_sock);
    command.env("TERM", "xterm-256color");

    let child = pair
        .slave
        .spawn_command(command)
        .expect("spawn portal-proxy attach");
    let child_killer = child.clone_killer();
    let stdout = pair.master.try_clone_reader().expect("clone pty reader");
    let stdin = pair.master.take_writer().expect("take pty writer");
    let reader = OutputReader::new(stdout);
    AttachProcess {
        child,
        child_killer,
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
    fn new(mut stdout: Box<dyn Read + Send>) -> Self {
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
        self.wait_for_occurrences(needle, 1, timeout);
    }

    fn wait_for_occurrences(&mut self, needle: &[u8], count: usize, timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if count_occurrences(&self.buffer, needle) >= count {
                return;
            }
            if let Ok(bytes) = self.rx.recv_timeout(Duration::from_millis(100)) {
                self.buffer.extend(bytes);
            }
        }
        panic!(
            "timed out waiting for {} occurrences of {:?}; output was:\n{}",
            count,
            String::from_utf8_lossy(needle),
            String::from_utf8_lossy(&self.buffer)
        );
    }
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn wait_for_attach_exit(mut attach: AttachProcess, timeout: Duration) {
    drop(attach.stdin);
    let mut child_killer = attach.child_killer;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(attach.child.wait());
    });

    if rx.recv_timeout(timeout).is_ok() {
        return;
    }

    let _ = child_killer.kill();
    panic!("child did not exit within {:?}", timeout);
}

struct SshFixture {
    root: TempDir,
    child: Child,
    user: String,
    port: u16,
    client_key: PathBuf,
    sshd_log: PathBuf,
    agent_sock: PathBuf,
    agent_pid: u32,
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
        let agent_sock = root.path.join("ssh-agent.sock");
        let agent_pid = start_agent(&agent_sock);
        run_success(
            Command::new(command_path("ssh-add"))
                .env("SSH_AUTH_SOCK", &agent_sock)
                .arg(&client_key),
        );

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
            agent_sock,
            agent_pid,
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
        let _ = Command::new("kill")
            .arg(self.agent_pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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

fn start_agent(socket_path: &Path) -> u32 {
    let output = Command::new(command_path("ssh-agent"))
        .arg("-a")
        .arg(socket_path)
        .arg("-s")
        .output()
        .expect("start ssh-agent");
    assert!(
        output.status.success(),
        "ssh-agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse_agent_pid(&String::from_utf8_lossy(&output.stdout))
}

fn parse_agent_pid(output: &str) -> u32 {
    output
        .split(';')
        .find_map(|part| {
            part.trim()
                .strip_prefix("SSH_AGENT_PID=")
                .and_then(|pid| pid.parse().ok())
        })
        .expect("ssh-agent did not print SSH_AGENT_PID")
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
