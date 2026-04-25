# Portal Proxy Deployment

This guide targets a Debian or Ubuntu LXC reachable through Tailscale.

## Suggested LXC Size

For personal use:

```text
1 vCPU
512 MB to 1 GB RAM
10 GB disk
512 MB swap
```

Disk is the main resource to watch because Portal Proxy records terminal output
for reconnect replay and thumbnails.

## Packages

Use the installer for a standard Debian/Ubuntu LXC:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-proxy/main/scripts/install-debian.sh | bash
```

For beta prereleases, pin the version:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-proxy/main/scripts/install-debian.sh | PORTAL_PROXY_VERSION=v0.5.0-beta.3 bash
```

Use a custom proxy SSH port:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalPals/portal-proxy/main/scripts/install-debian.sh | PORTAL_PROXY_SSH_PORT=2022 bash
```

The installer can be rerun to update Portal Proxy. It installs requirements,
creates the `portal-proxy` user and state directory, installs the release
binary, configures OpenSSH to listen on the existing SSH port plus `2222` by
default, enables daily pruning through systemd, and runs `portal-proxy doctor`.
Run it from a root shell or from a user with `sudo`; the script detects the
current user and escalates through `sudo` when needed.

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

Restrict access with Tailscale ACLs. Portal Proxy assumes the SSH service is not
reachable from the public internet.

## User And State

```sh
sudo useradd --system --create-home --shell /bin/sh portal-proxy
sudo install -d -o portal-proxy -g portal-proxy -m 0700 /var/lib/portal-proxy
sudo install -d -o portal-proxy -g portal-proxy -m 0700 /home/portal-proxy/.ssh
```

Install the built binary:

```sh
sudo install -m 0755 target/release/portal-proxy /usr/local/bin/portal-proxy
```

Run:

```sh
sudo -u portal-proxy portal-proxy doctor
```

The doctor command checks dependencies, state directory permissions, and whether
the process is running as a non-root user.

## SSH Forced Command

Add the Portal client public key to:

```text
/home/portal-proxy/.ssh/authorized_keys
```

Recommended key entry:

```text
restrict,pty,agent-forwarding,command="/usr/local/bin/portal-proxy serve --stdio" ssh-ed25519 AAAA...
```

Make sure permissions are strict:

```sh
sudo chown -R portal-proxy:portal-proxy /home/portal-proxy/.ssh
sudo chmod 0700 /home/portal-proxy/.ssh
sudo chmod 0600 /home/portal-proxy/.ssh/authorized_keys
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

From the Portal machine:

```sh
ssh -A -tt -p 2222 portal-proxy@TAILSCALE_NAME -- portal-proxy doctor
```

Then test a target attach:

```sh
ssh -A -tt -p 2222 portal-proxy@TAILSCALE_NAME -- portal-proxy attach \
  --session-id 00000000-0000-0000-0000-000000000001 \
  --target-host TARGET_HOST \
  --target-user TARGET_USER
```

Close the SSH client without typing `exit`, reconnect with the same session ID,
and confirm the shell is still alive. Typing `exit` in the target shell should
end the `dtach` session.

Target SSH authentication is non-interactive. Portal forwards your local
`ssh-agent` through the proxy connection; target private keys do not need to be
installed on the proxy host.

## Log Retention

Portal Proxy stores terminal output in:

```text
/var/lib/portal-proxy/logs
```

Use pruning regularly:

```sh
sudo -u portal-proxy portal-proxy prune --dry-run
sudo -u portal-proxy portal-proxy prune --ended-older-than-days 14 --max-log-bytes 67108864
```

Live session logs are capped by `PORTAL_PROXY_MAX_LOG_BYTES` by default. If a
session exceeds that output limit, `script(1)` terminates the session to protect
the proxy host from unbounded disk usage.

Install the example systemd timer from `examples/systemd` to run pruning daily.

## Optional Target Allowlist

For shared proxy hosts, restrict which target hosts Portal Proxy may connect to:

```text
PORTAL_PROXY_ALLOWED_TARGETS=*.internal,10.10.0.0/16
```

Patterns support exact hostnames, `*` wildcards, and IP CIDR ranges.

## Optional Logging Disable Mode

To avoid storing terminal output:

```text
PORTAL_PROXY_LOGGING_MODE=disabled
```

Sessions still persist across disconnects, but replay and thumbnails are not
available.

## Portal Settings

In Portal:

- Enable Portal Proxy globally.
- Set host to the proxy Tailscale name or IP.
- Set port to `2222`.
- Set username to `portal-proxy`.
- Set the SSH key used in `authorized_keys`.
- Enable Portal Proxy on individual SSH hosts.

Portal Proxy currently supports SSH terminal sessions only.
