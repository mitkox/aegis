# Security Policy

Aegis is security-sensitive production foundation tooling for package operation planning, policy review, signed execution plans, and constrained local execution.

## Supported Versions

Only the current `main` branch is supported until the project starts publishing releases.

## Reporting Vulnerabilities

Please open a private security advisory if the repository host supports it. If not, contact the maintainers privately before publishing details.

Useful reports include:

- a minimal reproduction;
- the exact Aegis command used;
- the generated plan, with secrets removed;
- expected versus actual policy behavior;
- whether a real mutation could occur.

## Security Boundaries

The intended invariant is:

```text
User intent
-> deterministic analyzer
-> local model review
-> deterministic policy decision
-> signed execution plan
-> constrained executor
-> audit log
```

The current production boundary implements planning, review, plan-bound deterministic policy, signed execution plans, a constrained `aegisd` executor, required-control preflight, and verifiable tamper-evident audit logging. Production apply is limited to policy-approved argv forms documented in `README.md`; APT is the primary production path, while non-APT apply is denied by default for mutable or unverified artifacts. Signing rejects stale or mismatched policy results by re-running deterministic policy for the exact plan and optional AI review. The executor verifies embedded plan/policy hashes, signed argv targets, expiry/freshness, snapshot proofs, and trusted human approval signatures before running allowlisted commands.

The model is a reviewer only. It must not execute commands, approve execution, or generate commands that Aegis runs.
