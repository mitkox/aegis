# Contributing

Thanks for helping improve Aegis. This project is security-sensitive: changes must preserve the production security boundary and the deterministic policy model.

## Development

Run these before opening a pull request:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Security Rules

- Do not add `sudo`.
- Do not add shell-mediated command execution.
- Do not run install, upgrade, pull, or extension-install commands in `--plan` mode.
- Do not execute model-generated commands.
- Keep deterministic policy authoritative over AI review.
- Add deny-path tests before happy-path tests for new adapters or policy rules.

## Scope

Aegis supports read-only planning, review, deterministic policy, signed execution plans, and constrained production execution through `aegisctl` and `aegisd`. Do not add production apply support in the same change as a new package ecosystem adapter.
