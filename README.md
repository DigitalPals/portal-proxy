# Portal Hub

Portal Hub keeps Portal SSH sessions alive when the Portal app or the local
machine disconnects. It is intended to run on a small Linux host or LXC that is
reachable only over Tailscale.

Status: beta. The core workflow works, the JSON API is versioned, lifecycle
integration coverage exists, and operational safeguards are in place. The
project is still pre-1.0, and breaking changes may still happen before 1.0.

## How It Works

Portal signs in to the Hub web service with OAuth + PKCE and opens persistent
terminal streams over an authenticated WebSocket. The Hub starts the target SSH
session inside `dtach`, records terminal output with `script`, and reconnects
Portal to the same `dtach` session when Portal opens the session again. The
legacy SSH forced-command mode remains available for manual operation and older
clients.

Target authentication is non-interactive. Portal should forward a local
`ssh-agent`; the proxy does not need target private keys installed on disk.

Typing `exit` in the remote shell ends the real target session. Closing Portal
or losing network connectivity only detaches Portal from the session.

## Security Model

Portal Hub is designed for Tailscale-only access.

- Do not expose the proxy SSH port to the public internet.
- Use Tailscale ACLs to restrict who can reach the proxy host.
- Run the proxy as a dedicated non-root user.
- Use the OAuth web API over Tailscale or behind an HTTPS reverse proxy.
- Keep the legacy OpenSSH forced-command entry restricted if you enable it.
- Keep `/var/lib/portal-hub` private to the proxy user.

Portal Hub uses SSH agent forwarding from Portal to connect onward to target
hosts. Only enable it for environments where that trust model is acceptable.

Portal Hub can also store Portal hosts, settings, snippets, and encrypted vault
items for desktop sync. Hosts, settings, and snippets are readable in the Hub
state directory. Private keys are stored only as Portal-encrypted blobs; Hub
does not receive the vault passphrase or decrypted keys.

For Portal desktop sign-in, sync, session listing, and WebSocket terminal
transport, run the web server:

```sh
portal-hub web --bind 0.0.0.0:8080 --public-url https://hub.example.test
```

With Tailscale Serve, bind the Hub web service to loopback and advertise the
Serve URL:

```sh
portal-hub web --bind 127.0.0.1:8080 --public-url https://portal-hub.example.ts.net
tailscale serve --bg http://127.0.0.1:8080
```

On first visit, `/admin` creates the owner account with a password. Portal
desktop signs in through the system browser with OAuth authorization code +
PKCE, then stores Hub tokens in the OS keychain. Portal Hub stores only an
Argon2 password hash.

## Session Logs

Portal Hub stores terminal output in `/var/lib/portal-hub/logs` so Portal
can replay and thumbnail session state after reconnecting.

Those logs can contain secrets shown in terminals, including tokens, passwords,
command output, and environment values. Treat the state directory as sensitive
data. Use `portal-hub prune` regularly.

By default, live session logs use a 16 MiB moving window. This protects the
proxy host from unbounded disk growth without terminating long-running target
sessions that produce heavy output. Set `PORTAL_HUB_MAX_LOG_BYTES=0` only if
you have a separate disk quota or retention strategy.

## Requirements

- Linux
- OpenSSH server and client
- Tailscale
- `dtach`
- `script` from util-linux

## Install On Debian / Ubuntu LXC

One-line installer:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh | bash
```

The installer checks for Debian/Ubuntu, installs required packages, creates the
dedicated `portal-hub` user, installs or updates the release binary, adds
an OpenSSH port config so SSH listens on the existing port plus `2222` by
default, enables a daily prune timer, and runs `portal-hub doctor`. Run it
from a root shell or from a user with `sudo`; the script detects the current
user and escalates through `sudo` when needed.

Install a specific release:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh | PORTAL_HUB_VERSION=v0.5.0-beta.6 bash
```

The default installer uses GitHub's `latest` release URL. For beta prereleases,
set `PORTAL_HUB_VERSION` explicitly if GitHub has not promoted that release as
latest.

Use a custom proxy SSH port:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh | PORTAL_HUB_SSH_PORT=2022 bash
```

## Build

```sh
cargo build --release
```

Install the binary:

```sh
sudo install -m 0755 target/release/portal-hub /usr/local/bin/portal-hub
```

## Basic Setup

Create a dedicated user and state directory:

```sh
sudo useradd --system --create-home --shell /bin/sh portal-hub
sudo install -d -o portal-hub -g portal-hub -m 0700 /var/lib/portal-hub
sudo install -d -o portal-hub -g portal-hub -m 0700 /home/portal-hub/.ssh
```

Add your Portal client public key to
`/home/portal-hub/.ssh/authorized_keys` with a forced command:

```text
restrict,pty,agent-forwarding,command="/usr/local/bin/portal-hub serve --stdio" ssh-ed25519 AAAA...
```

Run the health check as the proxy user:

```sh
sudo -u portal-hub portal-hub doctor
```

List active sessions:

```sh
sudo -u portal-hub portal-hub list --active
```

Prune old ended sessions and trim ended-session logs:

```sh
sudo -u portal-hub portal-hub prune --ended-older-than-days 14 --max-log-bytes 16777216
```

## Portal Configuration

In Portal settings, start the Portal Hub onboarding wizard and configure:

- Host: the Portal Hub DNS name, IP, or full Tailscale Serve URL, for example
  `https://portal-hub.example.ts.net`
- Web port: `8080` unless you installed the web service on another port. Portal
  does not append this port when the Host or Web URL field contains a full URL.

Portal opens the Hub OAuth page in your browser. After sign-in, choose which
services to enable: hosts sync, settings sync, snippets sync, key vault, and
persistent sessions / proxy.

Desktop sync, session listing, and persistent proxy sessions use the OAuth web
API. Portal sends local private-key material only for the lifetime of a WebSocket
terminal request when a host is configured for public-key auth; Hub stores it in
a temporary `0600` identity file and removes it when the terminal stream ends.

## JSON API

The legacy list output is a JSON array:

```sh
portal-hub list --active --include-preview
```

New clients should request the versioned format:

```sh
portal-hub list --active --include-preview --format v1
```

The versioned response contains `api_version`, `generated_at`, and `sessions`.

## Operations

Useful commands:

```sh
portal-hub doctor
portal-hub doctor --json
portal-hub version --json
portal-hub web --bind 0.0.0.0:8080
systemctl status portal-hub-web
portal-hub list --active --include-preview --format v1
portal-hub sync get --format v1
portal-hub prune --dry-run
portal-hub prune --ended-older-than-days 14 --max-log-bytes 16777216
```

Environment variables:

```text
PORTAL_HUB_STATE_DIR=/var/lib/portal-hub
PORTAL_HUB_MAX_LOG_BYTES=16777216
PORTAL_HUB_LOGGING_MODE=full
PORTAL_HUB_ALLOWED_TARGETS=*.internal,10.10.0.0/16
```

Logging modes:

- `full`: store terminal output for replay and thumbnails.
- `disabled`: do not store terminal output. Reconnect persistence still works,
  but replay and thumbnails are unavailable.

`PORTAL_HUB_ALLOWED_TARGETS` is optional. When set, attach requests are
restricted to exact hostnames, `*` wildcard patterns, or IP CIDR ranges.

Sync operations are revisioned. `portal-hub sync put` requires
`--expected-revision` and rejects stale writes instead of merging or silently
overwriting another device's changes.

## Known Limitations

- SSH terminal sessions only.
- Target host authentication currently depends on SSH agent forwarding.
- Browser/PWA SSH is not part of this release.
- Live replay logs are retained as a bounded moving window, so older terminal
  output may be discarded while the target session continues running.
- The project is still pre-1.0, and breaking changes may happen before 1.0.

See [docs/deployment.md](docs/deployment.md) for a fuller LXC deployment guide
and [docs/api.md](docs/api.md) for the JSON API contract.
