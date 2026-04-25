# Portal Proxy

Portal Proxy keeps Portal SSH sessions alive when the Portal app or the local
machine disconnects. It is intended to run on a small Linux host or LXC that is
reachable only over Tailscale.

Status: beta. The core workflow works, the JSON API is versioned, lifecycle
integration coverage exists, and operational safeguards are in place. The
project is still pre-1.0, so compatibility is maintained deliberately but major
changes may still happen before 1.0.

## How It Works

Portal connects to the proxy over SSH. The proxy starts the target SSH session
inside `dtach`, records terminal output with `script`, and reconnects Portal to
the same `dtach` session when Portal opens the session again.

Target authentication is non-interactive. Portal should forward a local
`ssh-agent`; the proxy does not need target private keys installed on disk.

Typing `exit` in the remote shell ends the real target session. Closing Portal
or losing network connectivity only detaches Portal from the session.

## Security Model

Portal Proxy is designed for Tailscale-only access.

- Do not expose the proxy SSH port to the public internet.
- Use Tailscale ACLs to restrict who can reach the proxy host.
- Run the proxy as a dedicated non-root user.
- Use OpenSSH `authorized_keys` forced-command options.
- Keep `/var/lib/portal-proxy` private to the proxy user.

Portal Proxy uses SSH agent forwarding from Portal to connect onward to target
hosts. Only enable it for environments where that trust model is acceptable.

## Session Logs

Portal Proxy stores terminal output in `/var/lib/portal-proxy/logs` so Portal
can replay and thumbnail session state after reconnecting.

Those logs can contain secrets shown in terminals, including tokens, passwords,
command output, and environment values. Treat the state directory as sensitive
data. Use `portal-proxy prune` regularly.

By default, live session logs have a hard 64 MiB output limit. This protects the
proxy host from unbounded disk growth. When the limit is reached, `script(1)`
terminates the session. Set `PORTAL_PROXY_MAX_LOG_BYTES=0` only if you have a
separate disk quota or retention strategy.

## Requirements

- Linux
- OpenSSH server and client
- Tailscale
- `dtach`
- `script` from util-linux

## Install On Debian / Ubuntu LXC

One-line installer:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-proxy/main/scripts/install-debian.sh | bash
```

The installer checks for Debian/Ubuntu, installs required packages, creates the
dedicated `portal-proxy` user, installs or updates the release binary, adds
an OpenSSH port config so SSH listens on the existing port plus `2222` by
default, enables a daily prune timer, and runs `portal-proxy doctor`. Run it
from a root shell or from a user with `sudo`; the script detects the current
user and escalates through `sudo` when needed.

Install a specific release:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-proxy/main/scripts/install-debian.sh | PORTAL_PROXY_VERSION=v0.5.0-beta.3 bash
```

The default installer uses GitHub's `latest` release URL. For beta prereleases,
set `PORTAL_PROXY_VERSION` explicitly if GitHub has not promoted that release as
latest.

Use a custom proxy SSH port:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-proxy/main/scripts/install-debian.sh | PORTAL_PROXY_SSH_PORT=2022 bash
```

## Build

```sh
cargo build --release
```

Install the binary:

```sh
sudo install -m 0755 target/release/portal-proxy /usr/local/bin/portal-proxy
```

## Basic Setup

Create a dedicated user and state directory:

```sh
sudo useradd --system --create-home --shell /bin/sh portal-proxy
sudo install -d -o portal-proxy -g portal-proxy -m 0700 /var/lib/portal-proxy
sudo install -d -o portal-proxy -g portal-proxy -m 0700 /home/portal-proxy/.ssh
```

Add your Portal client public key to
`/home/portal-proxy/.ssh/authorized_keys` with a forced command:

```text
restrict,pty,agent-forwarding,command="/usr/local/bin/portal-proxy serve --stdio" ssh-ed25519 AAAA...
```

Run the health check as the proxy user:

```sh
sudo -u portal-proxy portal-proxy doctor
```

List active sessions:

```sh
sudo -u portal-proxy portal-proxy list --active
```

Prune old ended sessions and trim ended-session logs:

```sh
sudo -u portal-proxy portal-proxy prune --ended-older-than-days 14 --max-log-bytes 67108864
```

## Portal Configuration

In Portal settings, enable Portal Proxy and configure:

- Host: the proxy Tailscale DNS name or Tailscale IP
- Port: `2222` unless you installed with a custom `PORTAL_PROXY_SSH_PORT`
- Username: `portal-proxy`
- Identity file: the private key matching the forced-command public key

Then enable Portal Proxy per SSH host.

## JSON API

The legacy list output is a JSON array:

```sh
portal-proxy list --active --include-preview
```

New clients should request the versioned format:

```sh
portal-proxy list --active --include-preview --format v1
```

The versioned response contains `api_version`, `generated_at`, and `sessions`.

## Operations

Useful commands:

```sh
portal-proxy doctor
portal-proxy doctor --json
portal-proxy version --json
portal-proxy list --active --include-preview --format v1
portal-proxy prune --dry-run
portal-proxy prune --ended-older-than-days 14 --max-log-bytes 67108864
```

Environment variables:

```text
PORTAL_PROXY_STATE_DIR=/var/lib/portal-proxy
PORTAL_PROXY_MAX_LOG_BYTES=67108864
PORTAL_PROXY_LOGGING_MODE=full
PORTAL_PROXY_ALLOWED_TARGETS=*.internal,10.10.0.0/16
```

Logging modes:

- `full`: store terminal output for replay and thumbnails.
- `disabled`: do not store terminal output. Reconnect persistence still works,
  but replay and thumbnails are unavailable.

`PORTAL_PROXY_ALLOWED_TARGETS` is optional. When set, attach requests are
restricted to exact hostnames, `*` wildcard patterns, or IP CIDR ranges.

## Known Limitations

- SSH terminal sessions only.
- Target host authentication currently depends on SSH agent forwarding.
- If the live log output limit is reached, the target session is terminated to
  prevent unbounded disk usage.
- The project is still pre-1.0; compatibility is maintained deliberately, but
  breaking changes may happen before 1.0.

See [docs/deployment.md](docs/deployment.md) for a fuller LXC deployment guide
and [docs/api.md](docs/api.md) for the JSON API contract.
