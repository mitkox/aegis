# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `aegis-brew` crate: deterministic Homebrew planning adapter for macOS.
  `aegis brew install <formula> --plan` produces signable
  `OperationPlan`s from `brew info --json=v2`, `brew deps
  --include-build --json=v1`, and `brew install --dry-run`. Apply path
  is intentionally deferred to v0.4 per AGENTS.md adapter rule 6.
- `Tool::Brew` variant on `aegis_core::Tool`.
- Test fixtures under `tests/fixtures/brew/` for poppler, yq, ripgrep,
  and gh.

## [0.2.7] - 2026-05-14

### Added

- Policy results are bound to the exact operation plan with `plan_hash`.
- Signed execution plans now embed the operation plan, policy result, optional AI review hash, and required-control proofs.
- `aegis policy --review <review.json>` consumes AI review output as a one-way restrictive signal.
- Real Ed25519 human approval signatures with separate approval keys.
- Executor preflight checks for embedded plan/policy hash consistency, policy freshness, required snapshot proofs, and trusted approval signatures.
- `AEGIS_AUDIT_LOG_DIR` and `aegisctl audit-verify` for audit-chain verification.

### Changed

- `aegisctl sign` re-runs deterministic policy and rejects supplied policy files that do not match the exact plan and optional review.
- Non-APT production apply is denied by default when artifacts are mutable or lack pinned/verified evidence; APT remains the primary production path.

### Fixed

- Placeholder human approval signatures are no longer accepted.

## [0.2.6] - 2026-05-14

### Added

- Production signed apply argv generation and executor allowlists for npm, pip, Docker/Podman, NuGet, VS Code extensions, Go, and Cargo.
- Managed non-APT apply roots under `/var/lib/aegis` for package-manager state, caches, and developer-tool installs where the ecosystem supports it.
- Concurrent `aegisd` client handling.
- Executor preflight target-drift checks that require signed argv targets to match execution-plan `exact_targets`.
- Deny-path coverage for failed metadata commands, unavailable metadata, malformed container digests, stale policy results, malformed Go version pins, and signed argv target drift.

### Changed

- Documentation now describes the full signed apply boundary for all supported ecosystems.
- Policy allow reasons now describe package and artifact risk outcomes directly.
- `aegisctl sign` now refuses stale policy-result versions or evaluator hashes.
- Failed metadata commands are deterministic denies, while unavailable metadata requires human approval.

### Fixed

- Container image digest pins must use full `sha256:<64-hex>` references.
- Production Go execution requires a well-formed single explicit version pin.

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
- **`aegis-executor`** crate with deterministic argv allowlisting.
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
- Production apply uses exact argv matching.

[Unreleased]: https://github.com/mitkox/aegis/compare/v0.2.7...HEAD
[0.2.7]: https://github.com/mitkox/aegis/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/mitkox/aegis/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/mitkox/aegis/compare/v0.1.0...v0.2.5
[0.1.0]: https://github.com/mitkox/aegis/releases/tag/v0.1.0
