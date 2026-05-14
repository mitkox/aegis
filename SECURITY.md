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

The current production boundary implements planning, review, deterministic policy, signed execution plans, a constrained `aegisd` executor, and tamper-evident audit logging. Production apply is currently APT-only and limited to policy-approved argv forms documented in `README.md`.

The model is a reviewer only. It must not execute commands, approve execution, or generate commands that Aegis runs.
