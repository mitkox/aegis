# Aegis Agent Rules

Aegis is a local zero-trust package operation broker. Future agent work must preserve the security invariant:

User intent -> deterministic analyzer -> local model review -> deterministic policy decision -> signed execution plan -> constrained executor -> audit log

## Hard Rules

- Never give an LLM root privileges.
- Never execute model-generated commands.
- Never use `shell=True` or equivalent shell-mediated command execution.
- Keep `--plan` read-only. Planning may run only approved dry-run or metadata commands.
- Never run `sudo`, real `apt-get install`, real `apt-get upgrade`, `npm install`, `pip install`, `docker pull`, `podman pull`, `nuget install`, `dotnet add package`, `code --install-extension`, `go get`, `cargo install`, lifecycle scripts, or `curl | bash` in MVP planning code.
- Prefer deterministic policy over AI judgement.
- Validate all package names before using them in subprocess argv.
- Do not weaken security tests to pass.
- Add tests for deny paths whenever policy behavior changes.
- Keep command previews as argv arrays, not shell strings.

## Allowed MVP Subprocesses

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
- `go list -m -json <validated-module>` only from a temp directory under `~/.cache/aegis/tmp`
- `cargo search <validated-crate> --limit 5`
- read-only availability checks such as `--version`

## Adding Ecosystem Support

When adding new ecosystem support:

1. Implement validation first.
2. Implement read-only metadata collection second.
3. Implement risk signals third.
4. Implement deterministic policy fourth.
5. Add deny-path tests before happy-path tests.
6. Never add apply support in the same change as a new adapter.
7. Never call package-manager install or pull commands in `--plan` mode.

## AI Boundary

The model is a reviewer only. It may classify risk and suggest controls, but it must not approve execution, generate execution argv, or decide policy.

## Executor Boundary

The root executor is intentionally not implemented in MVP. Future executor work must require signed execution plans and must constrain argv to deterministic, policy-approved operations.
