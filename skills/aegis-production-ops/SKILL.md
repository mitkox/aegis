---
name: aegis-production-ops
description: Use when operating Aegis on Linux servers, planning package changes, interpreting policy/provenance failures, or applying signed execution plans through aegisd. Enforces that agents never run direct package-manager mutation and never treat AI review as approval.
---

# Aegis Production Ops

## Invariant

Preserve this chain:

`intent -> deterministic analyzer -> local model review -> deterministic policy -> signed execution plan -> constrained executor -> audit log`

The local model is a reviewer only. It must not approve execution, generate argv, or run commands.

## Agent Rules

- Never run direct mutation: `sudo`, `apt-get install`, `apt-get upgrade`, `npm install`, `pip install`, `docker pull`, `podman pull`, `go get`, `cargo install`, lifecycle scripts, or `curl | bash`.
- Use Aegis planning commands first, such as `aegis apt install <pkg> --plan` or `aegis apt upgrade --plan`.
- Run `aegis review <plan.json>` only for advisory risk classification.
- Run `aegis policy <plan.json>` for the deterministic decision.
- Use `aegisctl sign` only when the policy result is not `deny` and required approvals/snapshots are satisfied.
- Use `aegisctl apply --execution-plan <file> --public-key-hex <key>` to submit to `aegisd`; do not bypass the daemon on production hosts.
- Treat provenance gaps, unsigned repositories, mutable container tags, direct artifact paths, critical vulnerabilities, package removals, downgrades, kernel changes, and suspicious scripts as blockers unless policy explicitly allows a signed approval path.

## Workflow

1. Create a read-only plan.
2. Inspect package deltas, repository evidence, provenance evidence, vulnerability evidence, rollback requirements, and risk signals.
3. Request AI review if useful; record it as advisory only.
4. Evaluate deterministic policy.
5. If policy requires controls, verify snapshots and collect a signed local approval reason.
6. Sign an execution plan with `aegisctl sign`.
7. Verify and submit through `aegisctl apply`.
8. Check `/var/log/aegis/audit.jsonl` or `aegisctl audit-path` for the tamper-evident event chain.

## Service Readiness Checks

Use these read-only checks before planning production work:

- `packaging/verify-native.sh`
- `systemctl status aegis-reviewd.service aegisd.service aegis-monitor.service aegis-monitor.timer --no-pager`
- `aegis doctor`

Expected production service state:

- `aegis-reviewd.service` is active and listening on `/run/aegis/aegis-reviewd.sock`.
- `aegisd.service` is active and listening on `/run/aegis/aegisd.sock`.
- `aegis-monitor.timer` is active.
- `aegis-monitor.service` is inactive after a successful oneshot run, not failed.

If unit paths point at `/usr/bin/aegis` or `/usr/libexec/aegis`, the host has
stale units. The human operator must run `packaging/install-native.sh` from a
root shell where `id -u` prints `0`; PolicyKit prompts for `systemctl` are not
enough to replace unit files.

## AI Agent Test Prompt

Use this prompt shape to test Aegis through an AI agent without mutation:

```text
Use Aegis production-ops rules. Do not run sudo or direct package-manager
mutation. Verify native service health with packaging/verify-native.sh, then
create a read-only plan for `aegis apt install nginx --plan`. Inspect the plan,
run `aegis review <plan>` and `aegis policy <plan>`, and summarize the risk,
policy decision, required controls, and generated file paths. Do not sign or
apply anything unless I explicitly approve a specific plan.
```

## Deny Interpretation

- `untrusted or weakly pinned package repository`: require an explicit trusted `Signed-By` keyring and approved source.
- `target source or evidence is denied`: do not work around direct URL, local path, replacement, unsigned repo, downgrade, or missing provenance blocks.
- `command preview contains shell metacharacters`: reject the request; command previews must be argv arrays.
- `critical vulnerability evidence`: install only an approved fixed version or deny the operation.
