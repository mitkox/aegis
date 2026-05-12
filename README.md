# Aegis

Aegis is a local zero-trust package operation broker for Ubuntu package operations. It replaces direct package changes such as `sudo apt upgrade` or `npm install lodash` with deterministic planning, local AI review, deterministic policy, and auditable plan files.

> Status: MVP. Aegis is useful for read-only planning, risk visibility, AI review, and deterministic policy checks. It is not yet a production root executor.

MVP command flow:

```text
User intent
-> deterministic analyzer
-> local model review
-> deterministic policy decision
-> signed execution plan
-> constrained executor
-> audit log
```

The MVP implements planning, review, policy evaluation, and audit file output. It does not implement privileged execution.

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

Development (from repo root):

```bash
cargo run -- doctor
cargo run -- apt update --plan
cargo run -- apt upgrade --plan
cargo run -- apt install nginx --plan
cargo run -- npm install lodash --plan
cargo run -- pip install requests --plan
cargo run -- docker pull ubuntu:latest --plan
cargo run -- container pull ghcr.io/org/image@sha256:<digest> --plan
cargo run -- nuget install Newtonsoft.Json --plan
cargo run -- vscode install ms-python.python --plan
cargo run -- go get github.com/gin-gonic/gin@v1.10.0 --plan
cargo run -- cargo install ripgrep --plan
cargo run -- review ~/.local/share/aegis/plans/<plan-id>.json
cargo run -- policy ~/.local/share/aegis/plans/<plan-id>.json
```

After `cargo install --path crates/aegis-cli`:

```bash
aegis doctor
aegis apt upgrade --plan
aegis npm install lodash --plan
aegis review ~/.local/share/aegis/plans/<plan-id>.json
aegis policy ~/.local/share/aegis/plans/<plan-id>.json
```

## Policy Configuration

The policy engine loads configuration from (in priority order):

1. `$AEGIS_POLICY_FILE` environment variable
2. `$XDG_CONFIG_HOME/aegis/policy.toml`
3. `$HOME/.config/aegis/policy.toml`
4. `policies/default-policy.toml` (from the working directory)

See `policies/default-policy.toml` for the available options.

## Development

Prerequisites:

- Rust stable, with `rustfmt` and `clippy`
- Ubuntu-compatible package tools for the ecosystems you want to inspect
- Optional local OpenAI-compatible model endpoint for `aegis review`

Check the repo:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

`--apply` exists but is intentionally disabled:

```text
apply is not implemented in MVP; only signed plan generation is supported
```

## What Planning May Run

Aegis uses explicit argv with `std::process::Command`; it does not use a shell.

## Supported Ecosystems And MVP Safety Model

| Ecosystem | MVP planning behavior |
| --- | --- |
| apt | dry-run with `apt-get -s`; `apt update --plan` describes intended metadata refresh without mutating |
| npm | metadata only with `npm view <package> --json`; no install |
| pip | metadata/environment only with `python3 -m pip index versions`; no install |
| Docker/Podman | manifest inspect only; no pull |
| NuGet | metadata/search only with `dotnet nuget search`; no install |
| VS Code | extension id validation and installed-extension list only; no install |
| Go | module metadata in a temp cache directory; no project mutation |
| Cargo | search only with `cargo search`; no install |

Allowed MVP subprocesses:

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

Forbidden in MVP:

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

## MVP Limitations

- No production daemon.
- No privileged root executor.
- No signed execution plan implementation yet.
- No `--apply` implementation.
- Apt parsing is best-effort over dry-run output.
- Npm planning inspects registry metadata only and never installs.
- New ecosystem adapters collect shallow metadata only; they do not implement full supply-chain intelligence.
- AI review requires a reachable local OpenAI-compatible endpoint.

## Open Source

Aegis is licensed under the MIT License. See [LICENSE](LICENSE).

Security reports should follow [SECURITY.md](SECURITY.md). Contributions should preserve the security invariant and follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Next Steps

- Add signed execution plans.
- Add a constrained root executor that accepts only signed, policy-approved argv.
- Add richer package and artifact metadata parsers.
- Add repository trust and snapshot integration.
- Add a full audit log chain with tamper-evident hashes.
