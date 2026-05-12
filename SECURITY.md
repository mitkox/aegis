# Security Policy

Aegis is pre-1.0 security tooling. Treat it as an MVP for package operation planning and review, not as a production root executor.

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

The current MVP implements planning, review, policy, and audit file output. It does not implement signed execution plans or a constrained root executor.

The model is a reviewer only. It must not execute commands, approve execution, or generate commands that Aegis runs.
