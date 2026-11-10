# Readiness and research notes

Review date: 2026-11-10. This document describes the current checkout, not a claim of a
production-certified release. The repository metadata is 2.0.0; no v1.5 requirements or release
were present to verify. The work focuses on making the existing local workflow reproducible and
surfacing failures rather than adding unverified integrations.


> **Status note (v3.0.0).** This audit was written against the 2.0.0 checkout. Everything it
> records still applies; 3.0 adds tools, playbooks, and external-agent adapters on top of the same
> guardrails. Two points moved since: `ffuf`/`nuclei` also accept files from the local wordlist and
> nuclei-template libraries (not arbitrary host paths), and the playbook path reports steps it
> could not run in the trace (`skipped`) and in the report. Re-verify before relying on any claim
> here for a specific engagement.
>
> **Status note (v5.0.0).** The inference backend changed: the Ollama client is removed, the
> default backend is the built-in auto agent (no model, no server), and a local model is used
> only via `--llm llamacpp:model` against `llama-server`. The loopback-only transport, the
> no-redirect/no-proxy guards, and the decision-retry behavior the audit verified still hold;
> only the "Local inference" row above and reference [1] describe a backend that no longer
> ships. See `CHANGELOG.md` for the 5.0.0 entry.

## Research and changes

| Area | What the upstream material and audit showed | What changed here |
|---|---|---|
| Local inference | Ollama's chat endpoint supports JSON mode and model tags; structured output is still subject to model/runtime behavior. [1] | The CLI checks the exact installed Ollama model, retries invalid decisions, uses short Qwen3 decisions, and does not follow model-server redirects or HTTP proxies. |
| Nuclei | Upstream documents rate limits, disabling redirects, update checks, and Interactsh. [2] Template matchers can still require false-positive assessment. [3] | Those flags are passed; only explicitly allowlisted template files can be requested. A match is recorded as unverified, not proof of impact. |
| HTTP probing | ProjectDiscovery httpx distinguishes unrestricted redirects from same-host redirects and supports a request-rate flag. [4] | The wrapper uses same-host redirects when requested, disables update checks, and passes the scope rate hint. |
| Fuzzing | ffuf defaults to no redirects, accepts a request-rate cap, and its CLI returns a non-zero error code on invalid input. [5] | FUZZ is restricted to path/query, redirects are explicitly disabled, wordlists require operator approval, and exit code 1 is not treated as success. |
| SQL injection | sqlmap documents delay between HTTP requests. [6] Its maintainers note that an "appears injectable" message can later be rejected as a false positive. [7] | A single-worker delay is applied, redirects are disabled, and a preliminary heuristic remains unverified rather than becoming a confirmed high-severity finding. |
| Nikto | Nikto can return code 1 for findings **or** errors. [8] Its documented pause option provides a per-test delay. [9] | An ambiguous exit is accepted only with a zero-error completion summary; otherwise it is reported as a failed/incomplete call. |
| Dalfox | Dalfox v3 documents distinct clean, findings, and error exits; its rate behavior and CLI have changed between versions. [10] | Exit 1 requires parseable findings; rate/delay options are conservative hints. Compatibility with a particular installed Dalfox release must be checked separately. |
| Engagement data | Code review found that previous SQLite reads were not filtered by run and that failures could still return exit 0. | Reads and aggregates are run-isolated; failure exit codes are surfaced after saving reports; new artifacts use owner-only POSIX file permissions; repeated finding IDs are deduplicated. |
| Address handling | Host parsing accepted numeric-only aliases that the standard library interprets as IPv4, and mapped IPv6 CIDRs did not exclude their IPv4 equivalents. | Numeric-only host names are rejected; mapped-CIDR membership is checked in scope validation, native TCP and the external-scanner DNS preflight. |
| Rate formatting | SQLMap/Nikto delays were formatted to three decimals, which could round a 3 request/second limit down to 0.333 s. | Delays round upward to whole milliseconds, non-finite or non-positive rates are refused, and the per-process flags remain best-effort hints. |
| Environment budgets | A malformed environment value aborted argument parsing, breaking `--help` and valid CLI overrides. | Environment values are resolved after parsing; only the value actually used is validated, and errors name the variable. |
| Scanner exits | A live SQLMap run showed that a connection failure can still exit 0, with the fatal message on stdout. | A zero exit is accepted only for a completed clean or confirmed SQLMap result; other zero-exit output becomes an error. |

## What was verified

- Automated tests cover exact/wildcard scope semantics, malformed target rejection, explicit
  file/source opt-ins, DNS exclusion checks, scanner argv construction and error handling,
  reporting, run-isolated memory, time/token checkpoints, and pure JSON stdout.
- A real local TCP listener is probed twice using the same SQLite file; both independent runs
  retain their own evidence. A fake Ollama-compatible HTTP server exercises the real transport,
  model decision parsing, the native TCP probe, trace writing, and report creation.
- The documented lab uses a local `http.server` and the checked-in decision stream. It does not
  need an LLM or external scanner binary after Python dependencies have been installed.
- Fixtures and mocked subprocesses cover the third-party wrappers. In addition, SQLMap
  (`1.10.11.8#dev`, commit `397a3bd`, fetched 2026-11-10) was run against an ephemeral loopback
  HTTP/SQLite fixture: a clean endpoint produced no findings, a deliberately injectable endpoint
  produced one candidate, and a closed port was surfaced as an error. This is one scanner version
  on one platform, not a compatibility guarantee. No actual Ollama model or other scanner version
  has been certified by these tests. The live test is opt-in
  (`CYBERPOWERFULL_RUN_SQLMAP_TEST=1`) and is not part of the default test run.
- An interrupted model response, malformed traces, and invalid environment settings are covered
  by regression tests and are reported rather than crashing.

## Remaining limitations and operational controls

1. **No network sandbox.** Scope matching validates requested primary hosts and filters reported
   findings. The native TCP probe checks DNS answers against excluded networks and connects to a
   checked address. Other scanners can resolve again, follow behavior inside templates, contact
   configured services, or spawn children. DNS checks are subject to time-of-check/time-of-use
   races. Use isolated DNS and an allowlisted egress firewall; audit all templates and binaries.
2. **No global rate guarantee.** Native TCP connections are paced. Scanner rate/delay options
   are best-effort, version-dependent hints; nmap's `--max-rate` is a packet-rate option, not an
   HTTP request budget. httpx, Nuclei, ffuf and subfinder accept only whole requests/second, so a
   sub-one limit is refused rather than rounded up. Multiple processes, DNS, retries, and scanner
   internals can exceed the declared rate. Enforce a network-level rate limit where necessary.
3. **Local inference is not offline scanning.** Local model endpoints are checked on loopback,
   but scope and tool behavior are separate from network isolation. Passive subdomain enumeration, DNS, dependency
   installation, scanner behavior, and optional templates may contact outside services. Passive
   sources require an explicit scope opt-in, but external network policies remain necessary.
4. **Evidence is not proof.** Scanner output can be stale, incomplete, malformed, misleading, or
   prompt-injected. A `verified` flag means a wrapper observed a tool's confirmation signal,
   not independent human verification. Severity and impact must be reviewed manually.
5. **Budgets are checkpoints, not hard isolation.** Prompt/decision tokens are estimates; DNS,
   socket behavior, and subprocess descendants may outlive a requested deadline. Large process
   output is spooled to temporary files and only bounded excerpts are parsed, but the temporary
   files can grow until the process exits. Use an external supervisor, disk limits, and process
   isolation for strict resource controls.
6. **Secrets remain sensitive.** The code strips common credential and proxy environment
   variables from scanner processes and creates new artifacts as owner-only files on POSIX.
   Scanners can still read local configuration/files, and traces/reports/SQLite contain plaintext
   engagement data. Existing directories keep their permissions; use disk encryption and access
   controls as appropriate.

## Primary references

1. [Ollama API: chat and JSON output](https://github.com/ollama/ollama/blob/main/docs/api.md).
2. [ProjectDiscovery Nuclei CLI flags](https://github.com/projectdiscovery/nuclei/blob/main/README.md).
3. [Nuclei discussion of confidence and potential false positives](https://github.com/projectdiscovery/nuclei/pull/7506).
4. [ProjectDiscovery httpx CLI flags](https://github.com/projectdiscovery/httpx/blob/main/README.md).
5. [ffuf CLI flags](https://github.com/ffuf/ffuf/blob/master/README.md) and [ffuf exit handling](https://github.com/ffuf/ffuf/blob/master/main.go).
6. [sqlmap usage: delay between HTTP requests](https://github.com/sqlmapproject/sqlmap/wiki/Usage).
7. [sqlmap maintainer on preliminary "appears injectable" output](https://github.com/sqlmapproject/sqlmap/issues/4452).
8. [Nikto exit code ambiguity](https://github.com/sullo/nikto/issues/837).
9. [Nikto source and pause option](https://github.com/sullo/nikto/blob/main/program/plugins/nikto_core.plugin).
10. [Dalfox release notes](https://github.com/hahwul/dalfox/releases) and [scan outcome source](https://github.com/hahwul/dalfox/blob/main/src/cmd/scan/mod.rs).
