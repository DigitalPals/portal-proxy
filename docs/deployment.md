# Portal Proxy Deployment

Prototype target: Debian or Ubuntu LXC reachable through Tailscale.

## Packages

```sh
sudo apt update
sudo apt install -y openssh-server dtach tailscale util-linux
```

`portal-proxy` also requires `script(1)` from util-linux so reconnects can replay
recent terminal output into the new Portal terminal.

## User

```sh
sudo useradd --system --create-home --shell /usr/sbin/nologin portal-proxy
sudo mkdir -p /var/lib/portal-proxy
sudo chown -R portal-proxy:portal-proxy /var/lib/portal-proxy
```

Install the built binary:

```sh
sudo install -m 0755 target/release/portal-proxy /usr/local/bin/portal-proxy
```

## SSH

Add the Portal client public key to:

```text
/home/portal-proxy/.ssh/authorized_keys
```

Recommended key options:

```text
restrict,pty,agent-forwarding,command="/usr/local/bin/portal-proxy serve --stdio" ssh-ed25519 ...
```

Bind or firewall SSH so it is reachable only on the Tailscale interface. Keep
password login disabled.

## Smoke Test

From the Portal machine:

```sh
ssh -A -tt portal-proxy@TAILSCALE_NAME -- portal-proxy attach \
  --session-id 00000000-0000-0000-0000-000000000001 \
  --target-host TARGET_HOST \
  --target-user TARGET_USER
```

Disconnect the SSH client, reconnect with the same session ID, and confirm the
remote shell is still alive. Typing `exit` in the target shell should end the
dtach session.
