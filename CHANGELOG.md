# Changelog

## 0.5.0-beta.12 - 2026-04-28

- Store and signal the `dtach` process id for session deletion without moving
  direct SSH attachments into a background process group.

## 0.5.0-beta.11 - 2026-04-28

- Added the authenticated `DELETE /api/sessions/{id}` endpoint so Portal and
  Portal Android can kill active Portal Hub sessions.
- Store process-group metadata for new `dtach` sessions so Hub can signal the
  underlying session before removing it from active lists.

## 0.5.0-beta.9 - 2026-04-27

- Hide `script` recorder headers from web session previews so thumbnails start
  at the terminal output instead of capture metadata.

## 0.5.0-beta.8 - 2026-04-27

- Restart the web service during installer updates so it does not keep running
  a deleted binary after reinstalling.
- Resolve Portal Hub child process spawns through the installed binary when the
  current executable path points at a replaced inode.

## 0.5.0-beta.7 - 2026-04-27

- Added Tailscale Serve public URL support for installer-managed web services.
- Added a Portal web-terminal PTY spawn fallback for containerized systemd
  environments where assigning the child controlling TTY fails.

## 0.5.0-beta.6 - 2026-04-27

- Fixed GitHub release packaging after the project rename so the installer can
  download `portal-hub-linux-x86_64.tar.gz`.

## 0.5.0-beta.5 - 2026-04-26

- Replaced live log output-limit termination with a bounded moving replay log
  window so heavy-output sessions keep running.
- Lowered the default replay log retention cap from 64 MiB to 16 MiB.
- Added an internal recorder path that keeps live log compaction active inside
  detached `dtach` sessions.

## 0.5.0-beta.4 - 2026-04-26

- Forward terminal resize notifications through `dtach` attachments so Portal
  Proxy sessions update the remote shell size after the Portal window changes.

## 0.5.0-beta.1 - 2026-04-25

- Added versioned `list --format v1` API.
- Added `version --json` compatibility endpoint.
- Added metadata `schema_version`.
- Added `doctor` health checks.
- Added `prune` for old sessions and ended-session logs.
- Added live log output limit using `script --output-limit`.
- Added optional logging disable mode.
- Added optional target allowlist with exact, wildcard, and IP CIDR patterns.
- Added CLI and SSH lifecycle integration tests.
- Added deployment docs, security policy, examples, release workflow, and CI.
- Added Debian/Ubuntu LXC installer script for release installs and updates.

## 0.2.0

- Prepared the project for public alpha distribution.
- Added initial versioned API, operational commands, retention docs, and CI.

## 0.1.0

- Initial Portal Hub prototype using OpenSSH, `dtach`, and `script`.
- Supported persistent SSH terminal sessions, reconnect replay, active session
  listing, and thumbnails.
