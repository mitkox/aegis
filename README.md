# Aegis

Aegis is a local zero-trust package operation broker. It replaces direct package changes such as `sudo apt upgrade` or `npm install lodash` with deterministic planning, local AI review, deterministic policy, and auditable signed execution plans.

> Status: **0.2.6**. Planning, AI review, deterministic policy, Ed25519-signed execution plans, constrained executor (`aegisd`), production apply for the supported package and artifact managers, and tamper-evident audit logging are implemented.

Command flow:

```text
User intent
-> deterministic analyzer
-> local model review
-> deterministic policy decision
-> signed execution plan
-> constrained executor (aegisd)
-> tamper-evident audit log
```

## Threat Model

Aegis assumes package managers, package metadata, maintainer scripts, dependency trees, and model output may all be risky inputs. The goal is to prevent accidental direct mutation, block obvious dangerous package operations, and keep privileged execution behind deterministic controls.

The local model is only a reviewer. It never receives root privileges, never executes commands, never approves execution, and never generates shell commands that Aegis executes. Deterministic Rust code parses package manager evidence, computes risk signals, and enforces policy.

## Local Model Endpoint

Aegis expects an OpenAI-compatible local endpoint:

```text
Base URL: http://localhost:8000/v1
Model: deepseek-v4-flash
Temperature: 0
```

Defaults can be overridden for local deployments:

```bash
export AEGIS_AI_BASE_URL=http://localhost:8000/v1
export AEGIS_AI_MODEL=deepseek-v4-flash
```

Slow local models can tune review timing without changing policy behavior:

```bash
export AEGIS_AI_PREFILL_TOKENS_PER_SEC=330
export AEGIS_AI_DECODE_TOKENS_PER_SEC=17
export AEGIS_AI_MODEL_STARTUP_ALLOWANCE_SECS=120
export AEGIS_AI_REVIEW_TIMEOUT_SECS=600
```

If `AEGIS_AI_REVIEW_TIMEOUT_SECS` is unset, Aegis estimates the review timeout
from prompt size, the configured token rates, and a startup allowance. Review
responses are capped with `AEGIS_AI_MAX_OUTPUT_TOKENS` (default `4096`) to leave
room for local reasoning-token overhead while keeping reviews bounded.
OpenAI-compatible JSON response formatting is used by default; set
`AEGIS_AI_RESPONSE_FORMAT_JSON=0` if your local endpoint rejects that option.

One common setup is a vLLM-compatible server exposing the model name above:

```bash
vllm serve <local-or-hf-model-path> \
  --host 127.0.0.1 \
  --port 8000 \
  --served-model-name deepseek-v4-flash
```

Use the model path and vLLM flags appropriate for your local installation and hardware. Aegis checks `GET http://localhost:8000/v1/models` in `aegis doctor`.

## Commands

### Planning (read-only)

```bash
aegis doctor
aegis apt update --plan
aegis apt upgrade --plan
aegis apt install nginx --plan
aegis npm install lodash --plan
aegis pip install requests --plan
aegis docker pull ubuntu:latest --plan
aegis container pull ghcr.io/org/image@sha256:<digest> --plan
aegis nuget install Newtonsoft.Json --plan
aegis vscode install ms-python.python --plan
aegis go get github.com/gin-gonic/gin@v1.10.0 --plan
aegis cargo install ripgrep --plan
```

### AI Review and Policy

```bash
aegis review ~/.local/share/aegis/plans/<plan-id>.json
aegis policy ~/.local/share/aegis/plans/<plan-id>.json
```

### Signed Execution Plans

```bash
aegisctl keygen
aegisctl sign --plan <plan.json> --policy <policy.json> --key-id <id> --signer <identity>
aegisctl verify --execution-plan <exec-plan.json> --public-key-hex <hex>
aegisctl apply --execution-plan <exec-plan.json> --public-key-hex <hex>
aegisctl audit-path
```

### Production Daemons

```bash
# Root execution gate (runs as root with systemd hardening)
aegisd --public-key-hex <hex>

# Unprivileged AI reviewer
aegis-reviewd
```

## Development

Prerequisites:

- Rust stable (MSRV 1.85), with `rustfmt` and `clippy`
- Ubuntu-compatible package tools for the ecosystems you want to inspect
- Optional local OpenAI-compatible model endpoint for `aegis review`

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

## What Planning May Run

Aegis uses explicit argv with `std::process::Command`; it does not use a shell.

## Supported Ecosystems And Safety Model

| Ecosystem | Planning behavior | Signed apply argv |
| --- | --- |
| apt | dry-run with `apt-get -s`; `apt update --plan` describes intended metadata refresh without mutating | `apt-get update`, `apt-get upgrade -y -o Dpkg::Options::=--force-confold`, `apt-get install -y <validated-package>` |
| npm | metadata with `npm view <package> --json` | `npm install --global --prefix /var/lib/aegis/npm-global --ignore-scripts --no-audit --no-fund <validated-package>` |
| pip | metadata/environment with `python3 -m pip index versions` | `python3 -m pip install --disable-pip-version-check --no-input --target /var/lib/aegis/pip-packages <validated-package>` |
| Docker/Podman | manifest inspect | `docker pull <validated-image>` or `podman --root /var/lib/aegis/podman/storage --runroot /run/aegis/podman pull <validated-image>` |
| NuGet | metadata/search with `dotnet nuget search` | `nuget install <validated-package> -OutputDirectory /var/lib/aegis/nuget/packages -NonInteractive` |
| VS Code | extension id validation and installed-extension list | `code --install-extension <validated-extension> --user-data-dir /var/lib/aegis/vscode/user-data --extensions-dir /var/lib/aegis/vscode/extensions` |
| Go | module metadata in a temp cache directory | `go install <validated-module>@<version>` with managed `GOPATH`, `GOBIN`, and `GOCACHE` |
| Cargo | search with `cargo search` | `cargo install --locked --root /var/lib/aegis/cargo <validated-crate>` |

Allowed planning subprocesses:

- `apt-get -s upgrade`
- `apt-get -s install <validated-package>`
- `npm view <validated-package> --json`
- `python3 -m pip index versions <validated-package>`
- `python3 -m pip inspect`
- `docker manifest inspect <validated-image>`
- `podman manifest inspect <validated-image>`
- `dotnet nuget search <validated-package>`
- `code --list-extensions --show-versions`
- `go env GOSUMDB GOPROXY GOPRIVATE GONOSUMDB`
- `go list -m -json <validated-module>` from a temp directory under `~/.cache/aegis/tmp`
- `cargo search <validated-crate> --limit 5`
- read-only availability checks for `doctor`

Forbidden during planning:

- `sudo`
- `apt-get upgrade` without `-s`
- `apt-get install` without `-s`
- `npm install`
- `pip install`
- `docker pull`
- `podman pull`
- `dotnet add package`
- `nuget install`
- `code --install-extension`
- `go get`
- `cargo install`
- npm lifecycle scripts
- `curl | bash`
- model-generated commands

Production apply is available only through signed execution plans:

```bash
aegis <ecosystem> <operation> --plan
aegis review <plan.json>
aegis policy <plan.json>
aegisctl sign --plan <plan.json> --policy <policy.json> --key-id <id> --signer <identity>
aegisctl verify --execution-plan <exec-plan.json> --public-key-hex <hex>
aegisctl apply --execution-plan <exec-plan.json> --public-key-hex <hex>
```

`aegisctl sign` derives execution argv from the deterministic operation plan. The model never supplies argv, and `aegisd` validates the signed argv against the same production allowlist before execution.
Signing refuses stale policy-result versions, failed metadata collection is denied by deterministic policy, and unavailable package or artifact metadata requires human approval. The executor also verifies that the signed argv target matches the execution plan's exact target list before running an allowlisted command.

## Audit Files

Generated plans are written to:

```text
~/.local/share/aegis/plans/<plan_id>.json
```

AI reviews are written to:

```text
~/.local/share/aegis/reviews/<plan_id>.review.json
```

Policy results are written to:

```text
~/.local/share/aegis/policy/<plan_id>.policy.json
```

Tamper-evident audit events are appended to:

```text
~/.local/share/aegis/audit/audit.ndjson
```

Each audit event contains a SHA-256 hash chain linking it to the previous event.

## Open Source

Aegis is licensed under the MIT License. See [LICENSE](LICENSE).

Security reports should follow [SECURITY.md](SECURITY.md). Contributions should preserve the security invariant and follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Next Steps

- Add richer package and artifact metadata parsers.
- Add repository trust and snapshot integration.
- Add rollback plan execution.
- Add multi-platform CI matrix.
