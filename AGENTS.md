# Agent Notes

## Development Environment

- Run commands from the repository root.
- `direnv` is expected. If the environment is not active, run `nix develop`.
- Do not install missing build tools globally; add project-specific tools and libraries to `flake.nix`.
- Common commands: `cargo test`, `cargo build`, `cargo clippy`.
