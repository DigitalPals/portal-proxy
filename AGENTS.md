# Agent Notes

## Development Environment

- Run commands from the repository root.
- `direnv` is expected. If the environment is not active, run `nix develop`.
- Do not install missing build tools globally; add project-specific tools and libraries to `flake.nix`.
- Common commands: `cargo test`, `cargo build`, `cargo clippy`.

## Human Testing Before Release

- The default Portal Hub human-testing target is the LXC at `root@10.10.0.13`.
- Before creating a new GitHub release for changes that affect Portal Hub behavior,
  Android pairing, authorization, vault access, SSH proxying, sync, or cross-client
  compatibility, test the feature on this LXC after automated checks pass.
- Use SSH to access the LXC. Treat it as the staging Portal Hub environment for
  release validation, not as a place for untracked source changes.
