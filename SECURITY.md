# Security Policy

## Intended use

`cyberpowerfull` is a penetration-testing agent. It is built for authorized engagements only:
systems you own, or systems for which you hold written authorization from the asset owner.

The agent is designed to make unauthorized use hard, not to make it look acceptable:

- It refuses to start without a `scope.json` declaring `"authorized": true` and explicit targets
  (exit code `3`).
- Every tool call is re-validated against that scope inside the worker layer; out-of-scope
  targets are blocked and recorded (exit code `4`).
- The scope is injected into the system prompt by the system, together with a SHA-256
  fingerprint recorded in every trace, so a run can be attributed to a declared engagement.
- Out-of-band interaction is disabled (`nuclei -no-interactsh`), cloud inference endpoints are
  rejected, and tool subprocesses run with cloud credentials removed from the environment.
- Exploitation is proof-only: no persistence, no lateral movement, no data extraction, no
  denial-of-service behaviour.

Do not remove these controls in a fork and redistribute the result as this project.

## Reporting a vulnerability in this software

If you find a security defect in `cyberpowerfull` itself (for example: a scope-bypass in the
worker layer, command injection through a tool argument, an unsafe deserialization path, or an
escape from the loopback-only inference policy):

1. Do **not** open a public issue.
2. Use GitHub's private vulnerability reporting on this repository
   (Security → Advisories → "Report a vulnerability"), or contact the maintainers through the
   address listed in `pyproject.toml`/repository profile.
3. Include: affected version or commit, a minimal reproduction, impact, and any suggested fix.

Expect an acknowledgement within 7 days and a remediation plan within 30 days. Please allow a
coordinated disclosure window before publishing details.

## Scope of this policy

In scope:

- the Python package in `src/cyberpowerfull/`
- the CLI contract and its exit codes
- the scope-enforcement and memory-integrity guarantees

Out of scope:

- vulnerabilities in third-party tools invoked by this project (nmap, nuclei, sqlmap, …) —
  report those upstream
- findings produced by the agent against your own targets
- issues that require weakening a documented safety control (for example: editing
  `scope.json` to add targets you do not own, or exporting an environment variable that points
  inference at a cloud host)

## Handling of engagement data

- Traces, reports, and memory stay on the local filesystem under `traces/` and `artifacts/`.
- No telemetry is collected, and no data leaves the machine except the requests the operator's
  authorized tools make against authorized targets.
- Treat `artifacts/` and `traces/` as engagement-confidential and delete them when the
  engagement ends.
