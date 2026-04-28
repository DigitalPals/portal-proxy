# Portal Hub

Portal Hub is the always-on companion service for Portal. Run it on a small
Linux host or LXC in your tailnet, then let Portal use it for persistent SSH
sessions, browser sign-in, device sync, session previews, and encrypted key
vault sync.

It is built for the practical homelab and ops workflow: start a terminal from
Portal, close your laptop, switch networks, come back later, and reconnect to
the same shell.

Status: beta. The core flows are working and versioned, but the project is
still pre-1.0 and API or storage details may change before a stable release.

## What It Does

| Feature | What you get |
| --- | --- |
| Persistent SSH sessions | Remote shells keep running on the Hub after Portal disconnects. |
| Session resume | Reopen active sessions from Portal, including sessions detached from another device. |
| Terminal thumbnails | Portal can show session previews from Hub replay logs. |
| Web terminal transport | Portal connects through an OAuth-authenticated WebSocket instead of relying only on SSH forced-command mode. |
| Browser sign-in | Portal signs in with OAuth authorization code + PKCE and stores tokens in the OS keychain. |
| Profile sync | Hosts, settings, snippets, and vault metadata sync between Portal devices. |
| Encrypted key vault sync | Private keys are stored as Portal-encrypted blobs; Hub never receives the vault passphrase or decrypted keys. |
| Tailscale Serve support | Use a clean HTTPS `.ts.net` URL while the Hub service binds safely to loopback. |
| Operational tooling | `doctor`, `version --json`, `list`, `prune`, target allowlists, bounded logs, and systemd units. |

## How It Works

Portal signs in to the Hub web service with OAuth + PKCE. For persistent
terminal sessions, Portal opens an authenticated WebSocket and asks Hub to start
or attach to a target SSH session. Hub runs that target session inside `dtach`,
records a bounded replay log with `script`, and reconnects Portal to the same
session later.

Typing `exit` in the remote shell ends the real target session. Closing Portal,
losing Wi-Fi, or moving to another machine only detaches the Portal client.

Portal Hub also keeps a revisioned sync store for Portal data:

- Hosts, settings, and snippets are stored as readable JSON in the Hub state
  directory.
- Vault entries are stored as encrypted blobs produced by Portal.
- Sync v2 tracks each service independently and exposes an SSE event stream so
  other Portal clients can refresh quickly after a change.

The legacy OpenSSH forced-command mode is still available for manual operation
and older clients.

## Recommended Setup

Portal Hub is intended to live on a private host reachable through Tailscale.
The common setup is:

```text
Portal app  ->  Tailscale / Tailscale Serve  ->  portal-hub-web.service
Portal app  ->  Portal Hub SSH port 2222     ->  legacy forced-command fallback
Portal Hub  ->  target SSH hosts
```

Recommended minimum LXC size for personal use:

```text
1 vCPU
512 MB to 1 GB RAM
10 GB disk
512 MB swap
```

Disk is the main resource to watch because replay logs power reconnect previews
and thumbnails.

## Install

On a Debian or Ubuntu LXC, run the installer as root or a sudo-capable user:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh | bash
```

The installer:

- installs `openssh-server`, `openssh-client`, `dtach`, `util-linux`, `curl`,
  and `tar`;
- installs Tailscale when it is available from the configured apt repositories;
- creates the dedicated `portal-hub` user;
- creates `/var/lib/portal-hub` with private permissions;
- installs or updates the release binary in `/usr/local/bin`;
- configures OpenSSH to keep the existing SSH port and add `2222` by default;
- installs and restarts `portal-hub-web.service`;
- enables a daily prune timer;
- runs `portal-hub doctor`.

Update later by running the same installer again.

### Install With Tailscale Serve

For a polished HTTPS tailnet URL, bind Hub to loopback and publish it with
Tailscale Serve:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh \
  | PORTAL_HUB_WEB_BIND=127.0.0.1:8080 \
    PORTAL_HUB_PUBLIC_URL=https://portal-hub.example.ts.net \
    bash

tailscale serve --bg http://127.0.0.1:8080
```

Use your real Serve URL in `PORTAL_HUB_PUBLIC_URL`, for example
`https://portal-hub.your-tailnet.ts.net`.

### Useful Installer Options

```sh
# Pin a release
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh \
  | PORTAL_HUB_VERSION=v0.5.0-beta.9 bash

# Use a custom Portal Hub SSH port
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh \
  | PORTAL_HUB_SSH_PORT=2022 bash

# Bind the web service to a private address or loopback
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh \
  | PORTAL_HUB_WEB_BIND=127.0.0.1:8080 bash
```

## First Run

After installation, open the Hub admin page through the same URL Portal will
use:

```text
https://portal-hub.example.ts.net/admin
```

The first visit creates the owner account. Portal then signs in through the
browser and stores Hub tokens locally in the OS keychain. Hub stores only an
Argon2 password hash, OAuth tokens, sync state, session metadata, and replay
logs in `/var/lib/portal-hub`.

Check the service:

```sh
sudo systemctl status portal-hub-web
sudo -u portal-hub portal-hub doctor
```

## Portal Setup

In Portal, open Settings and start the Portal Hub setup flow.

Use:

- Host: the Tailscale name, IP, or full Tailscale Serve URL.
- Web URL: the HTTPS URL that reaches `portal-hub-web.service`.
- Web port: `8080`, unless you changed the web bind port. Portal does not append
  this port when Host or Web URL already contains a full URL.
- Sign in through the browser.
- Enable the services you want: hosts, settings, snippets, key vault, and
  persistent sessions.
- Enable Portal Hub on individual SSH hosts that should use persistent sessions.

When an SSH host uses public-key auth through the web terminal transport, Portal
sends the private key material only for the lifetime of that terminal request.
Hub writes it to a temporary `0600` identity file and removes it when the
terminal stream ends.

## Security Model

Portal Hub is designed for Tailscale-only access.

- Do not expose the Hub SSH port or web service to the public internet.
- Use Tailscale ACLs to restrict who can reach the Hub host.
- Run Hub as the dedicated non-root `portal-hub` user.
- Keep `/var/lib/portal-hub` private to the Hub user.
- Treat terminal replay logs as sensitive; they can contain command output,
  tokens, passwords, environment values, and pasted secrets.
- Use `PORTAL_HUB_ALLOWED_TARGETS` on shared Hub hosts to restrict where Hub can
  connect.
- Keep the legacy SSH forced-command entry restricted if you enable it.

Portal Hub can sync encrypted vault blobs, but it must never receive the vault
passphrase, derived key, or decrypted private keys. Android vault enrollment
keeps that model: Hub stores an Android device public key and an encrypted
unlock-key envelope produced by Portal desktop, but not the plaintext unlock
key.

## Session Logs And Retention

Hub stores terminal output in:

```text
/var/lib/portal-hub/logs
```

By default, live logs use a 16 MiB moving window. Older replay output may be
discarded, but the target session keeps running.

Useful commands:

```sh
sudo -u portal-hub portal-hub list --active --include-preview --format v1
sudo -u portal-hub portal-hub prune --dry-run
sudo -u portal-hub portal-hub prune --ended-older-than-days 14 --max-log-bytes 16777216
```

Disable replay logging if you do not want terminal output stored:

```text
PORTAL_HUB_LOGGING_MODE=disabled
```

Sessions still persist across disconnects, but replay and thumbnails are not
available.

## Operations

Common commands:

```sh
portal-hub doctor
portal-hub doctor --json
portal-hub version --json
portal-hub web --bind 127.0.0.1:8080 --public-url https://portal-hub.example.ts.net
portal-hub list --active --include-preview --format v1
portal-hub sync get --format v1
portal-hub prune --dry-run
```

Common environment variables:

```text
PORTAL_HUB_STATE_DIR=/var/lib/portal-hub
PORTAL_HUB_PUBLIC_URL=https://portal-hub.example.ts.net
PORTAL_HUB_MAX_LOG_BYTES=16777216
PORTAL_HUB_LOGGING_MODE=full
PORTAL_HUB_ALLOWED_TARGETS=*.internal,10.10.0.0/16
```

`PORTAL_HUB_ALLOWED_TARGETS` supports exact hostnames, `*` wildcard patterns,
and IP CIDR ranges.

## Legacy Forced-Command Mode

The web transport is the primary Portal workflow, but the SSH forced-command
mode remains available.

Add the Portal client public key to:

```text
/home/portal-hub/.ssh/authorized_keys
```

Use this restricted prefix:

```text
restrict,pty,agent-forwarding,command="/usr/local/bin/portal-hub serve --stdio" ssh-ed25519 AAAA...
```

Smoke test from the Portal machine:

```sh
ssh -A -tt -p 2222 portal-hub@TAILSCALE_NAME -- portal-hub doctor
```

Target authentication in forced-command mode is non-interactive and depends on
SSH agent forwarding from the Portal client.

## Build From Source

```sh
cargo build --release
sudo install -m 0755 target/release/portal-hub /usr/local/bin/portal-hub
```

Run the web service manually:

```sh
PORTAL_HUB_STATE_DIR=/var/lib/portal-hub \
  portal-hub web --bind 127.0.0.1:8080 --public-url https://portal-hub.example.ts.net
```

## API And Integrations

Portal Hub exposes versioned CLI JSON and OAuth-authenticated web APIs:

- `GET /api/info`
- `GET /api/me`
- `GET /api/sync`
- `PUT /api/sync`
- `GET /api/sync/v2`
- `PUT /api/sync/v2`
- `GET /api/sync/v2/events`
- `GET /api/sessions`
- `GET /api/sessions/terminal`

See [docs/api.md](docs/api.md) for request and response details.

## Current Limitations

- SSH terminal sessions are supported; browser/PWA SSH is not part of this
  release.
- Legacy forced-command target authentication depends on SSH agent forwarding.
- Replay logs are bounded, so older terminal output can be trimmed while the
  target session continues running.
- The project is pre-1.0 and may still make breaking changes.

## More Docs

- [Deployment guide](docs/deployment.md)
- [API contract](docs/api.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
