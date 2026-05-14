# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.5] - 2026-05-14

### Added

- **Signed execution plans**: Ed25519 signing with canonical JSON via `aegisctl sign`, verification via `aegisctl verify`.
- **Constrained root executor** (`aegisd`): accepts only signed, policy-approved plans over Unix socket with systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`).
- **Unprivileged AI reviewer daemon** (`aegis-reviewd`): local model review over Unix socket.
- **Production operator CLI** (`aegisctl`): `sign`, `verify`, `apply`, `keygen`, `audit-path` commands.
- **Tamper-evident audit logging**: SHA-256 hash-chained NDJSON events with `new_audit_event` / `append_audit_event`.
- **`ExecutionPlan`**, **`SignatureEnvelope`**, **`Approval`**, **`AuditEvent`**, **`AuditEventKind`** types in `aegis-core`.
- **`policy_version`**, **`evaluator_hash`**, **`evidence_fresh_until`** fields on `PolicyResult`.
- **Policy config resolution**: `AEGIS_POLICY_CONFIG` env → `$XDG_CONFIG_HOME/aegis/policy.toml` → `/etc/aegis/policy.toml` → fallback.
- **`aegis-executor`** crate with deterministic argv allowlisting (APT-only in production).
- **`aegis-signing`** crate with Ed25519 key generation, plan signing, and verification.
- **systemd service units** for `aegisd`, `aegis-reviewd`, `aegis-monitor` with comprehensive hardening.
- **Native install/verify scripts** (`packaging/install-native.sh`, `packaging/verify-native.sh`).
- **Package wrapper script** to intercept direct package manager invocations.
- **CI improvements**: `Cargo.lock` freshness check, release build step.
- **CHANGELOG.md** following Keep a Changelog format.

### Changed

- Workspace `Cargo.toml` now includes `repository` URL.
- Policy evaluator uses versioned `POLICY_VERSION` and `EVALUATOR_HASH` constants.

### Fixed

- Policy config path no longer hardcoded to a relative path — works from any directory.

## [0.1.0] - 2026-05-14

### Added

- **Core pipeline**: deterministic planning → local AI review → deterministic policy → signed execution plan → constrained executor → tamper-evident audit log.
- **8 ecosystem adapters**: APT, npm, pip, Docker/Podman containers, NuGet, VS Code extensions, Go modules, Cargo crates.
- **Ed25519 execution-plan signing** with canonical JSON and deterministic verification.
- **Constrained root executor** (`aegisd`) accepting only signed plans over Unix socket with systemd hardening.
- **Unprivileged AI reviewer daemon** (`aegis-reviewd`) with configurable local model endpoint.
- **Deterministic policy engine** with deny/require-human/allow-with-snapshot/allow tiers.
- **Production operator CLI** (`aegisctl`) for signing, verifying, and applying execution plans.
- **Tamper-evident audit logging** with SHA-256 hash chain (NDJSON format).
- **Package name validation** before any subprocess invocation across all ecosystems.
- **`aegis doctor`** command for environment health checks.
- **systemd service units** with `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, and other hardening.
- **Package wrapper script** to intercept direct package manager invocations.
- **JSON schemas** for operation plans, AI reviews, policy results, execution plans, and audit events.
- **GitHub Actions CI** with format, clippy, and test checks.

### Security

- All crates use `#![forbid(unsafe_code)]`.
- No `shell=True` or shell-mediated command execution anywhere.
- All subprocess argv are validated against deterministic allowlists.
- AI model is reviewer-only — never executes, approves, or generates commands.
- Production apply is APT-only with exact argv matching.

### Limitations (MVP)

- `--apply` through CLI is stubbed; apply requires `aegisctl sign` + `aegisctl apply` through `aegisd`.
- Ecosystem adapters collect metadata only — no direct package installation.
- Single-threaded daemon handlers (adequate for local use).

[Unreleased]: https://github.com/mitkox/aegis/compare/v0.2.5...HEAD
[0.2.5]: https://github.com/mitkox/aegis/compare/v0.1.0...v0.2.5
[0.1.0]: https://github.com/mitkox/aegis/releases/tag/v0.1.0
