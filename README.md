# Portal Proxy

Portal Proxy is a small prototype companion service for Portal. It runs behind
OpenSSH on a Tailscale-only LXC and uses `dtach` to keep remote SSH terminal
sessions alive when Portal disconnects.

V1 is terminal-only. Target host authentication is done with SSH agent
forwarding from Portal to the proxy.

See [docs/deployment.md](docs/deployment.md) for setup notes.
