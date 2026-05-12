# Contributing

Thanks for helping improve Aegis. This project is security-sensitive: changes should preserve the plan-only MVP boundary and the deterministic policy model.

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

The current MVP is for visibility, planning, review, and deterministic policy. Do not add `--apply` execution in the same change as a new package ecosystem adapter.
