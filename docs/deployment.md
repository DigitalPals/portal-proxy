# Portal Hub Deployment

This guide targets a Debian or Ubuntu LXC reachable through Tailscale.

## Suggested LXC Size

For personal use:

```text
1 vCPU
512 MB to 1 GB RAM
10 GB disk
512 MB swap
```

Disk is the main resource to watch because Portal Hub records terminal output
for reconnect replay and thumbnails.

## Packages

Use the installer for a standard Debian/Ubuntu LXC:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh | bash
```

For beta prereleases, pin the version:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh | PORTAL_HUB_VERSION=v0.5.0-beta.6 bash
```

Use a custom proxy SSH port:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh | PORTAL_HUB_SSH_PORT=2022 bash
```

The installer can be rerun to update Portal Hub. It installs requirements,
creates the `portal-hub` user and state directory, installs the release binary,
configures OpenSSH to listen on the existing SSH port plus `2222` by default,
installs `portal-hub-web.service` on `0.0.0.0:8080`, enables daily pruning
through systemd, and runs `portal-hub doctor`. Run it from a root shell or from
a user with `sudo`; the script detects the current user and escalates through
`sudo` when needed.

If you want the web service to bind somewhere else, such as loopback for a
reverse proxy:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-hub/main/scripts/install-debian.sh | PORTAL_HUB_WEB_BIND=127.0.0.1:8080 bash
```

The default bind is intended for hosts that are reachable only over Tailscale or
another private network. For HTTPS, bind the service on loopback and publish it
with Tailscale Serve or another reverse proxy.

Manual package installation:

```sh
sudo apt update
sudo apt install -y openssh-server openssh-client dtach tailscale util-linux
```

`script(1)` is provided by util-linux.

## Tailscale

Enable Tailscale inside the LXC:

```sh
sudo tailscale up
```

If Tailscale cannot access `/dev/net/tun`, either allow the device in the LXC
configuration or run Tailscale in userspace networking mode.

Restrict access with Tailscale ACLs. Portal Hub assumes the SSH service is not
reachable from the public internet.

## User And State

```sh
sudo useradd --system --create-home --shell /bin/sh portal-hub
sudo install -d -o portal-hub -g portal-hub -m 0700 /var/lib/portal-hub
sudo install -d -o portal-hub -g portal-hub -m 0700 /home/portal-hub/.ssh
```

Install the built binary:

```sh
sudo install -m 0755 target/release/portal-hub /usr/local/bin/portal-hub
```

Run:

```sh
sudo -u portal-hub portal-hub doctor
```

The doctor command checks dependencies, state directory permissions, and whether
the process is running as a non-root user.

## Web Service

Portal desktop uses the web service for OAuth sign-in, sync, session listing,
and persistent terminal WebSocket streams. With the installer, check it with:

```sh
sudo systemctl status portal-hub-web
```

Manual service installation can use
`examples/systemd/portal-hub-web.service`. The service listens on HTTP; expose
it through Tailscale Serve or another HTTPS reverse proxy when using a public
URL.

For Tailscale Serve, set `PORTAL_HUB_PUBLIC_URL` to the Serve origin and bind
the Hub web service to loopback:

```sh
PORTAL_HUB_PUBLIC_URL=https://portal-hub.example.ts.net \
  portal-hub web --bind 127.0.0.1:8080
tailscale serve --bg http://127.0.0.1:8080
```

## Legacy SSH Forced Command

Add the Portal client public key to:

```text
/home/portal-hub/.ssh/authorized_keys
```

Recommended key entry:

```text
restrict,pty,agent-forwarding,command="/usr/local/bin/portal-hub serve --stdio" ssh-ed25519 AAAA...
```

Make sure permissions are strict:

```sh
sudo chown -R portal-hub:portal-hub /home/portal-hub/.ssh
sudo chmod 0700 /home/portal-hub/.ssh
sudo chmod 0600 /home/portal-hub/.ssh/authorized_keys
```

Recommended `sshd_config` port config:

```text
Port 22
Port 2222
```

Reload SSH:

```sh
sudo systemctl reload ssh
```

## Smoke Test

Open the Hub admin page through the same URL Portal will use and create the
owner account:

```text
https://hub.example.test/admin
```

Then use Portal's settings to authenticate through the browser.

The legacy forced-command path can still be smoke-tested from the Portal
machine:

From the Portal machine:

```sh
ssh -A -tt -p 2222 portal-hub@TAILSCALE_NAME -- portal-hub doctor
```

Then test a target attach:

```sh
ssh -A -tt -p 2222 portal-hub@TAILSCALE_NAME -- portal-hub attach \
  --session-id 00000000-0000-0000-0000-000000000001 \
  --target-host TARGET_HOST \
  --target-user TARGET_USER
```

Close the SSH client without typing `exit`, reconnect with the same session ID,
and confirm the shell is still alive. Typing `exit` in the target shell should
end the `dtach` session.

Target SSH authentication in legacy forced-command mode is non-interactive.
Portal desktop's current web transport sends a temporary identity file for
public-key hosts and uses interactive SSH auth inside the Hub terminal PTY when
needed.

## Log Retention

Portal Hub stores terminal output in:

```text
/var/lib/portal-hub/logs
```

Use pruning regularly:

```sh
sudo -u portal-hub portal-hub prune --dry-run
sudo -u portal-hub portal-hub prune --ended-older-than-days 14 --max-log-bytes 16777216
```

Live session logs are retained as a moving window capped by
`PORTAL_HUB_MAX_LOG_BYTES` by default. Older replay output is discarded when
needed, but the target session keeps running.

Install the example systemd timer from `examples/systemd` to run pruning daily.

## Optional Target Allowlist

For shared proxy hosts, restrict which target hosts Portal Hub may connect to:

```text
PORTAL_HUB_ALLOWED_TARGETS=*.internal,10.10.0.0/16
```

Patterns support exact hostnames, `*` wildcards, and IP CIDR ranges.

## Optional Logging Disable Mode

To avoid storing terminal output:

```text
PORTAL_HUB_LOGGING_MODE=disabled
```

Sessions still persist across disconnects, but replay and thumbnails are not
available.

## Portal Settings

In Portal:

- Enable Portal Hub globally.
- Set host to the proxy Tailscale name, IP, or full Tailscale Serve URL.
- Set web port to `8080`, unless you changed `PORTAL_HUB_WEB_BIND`.
- Set Web URL to the HTTPS reverse-proxy or Tailscale Serve URL. If the web
  service is bound directly to a Tailscale-only/private address, set the matching
  `http://host:port` URL.
- Sign in through the browser.
- Enable Portal Hub on individual SSH hosts.

Portal Hub currently supports SSH terminal sessions only.
