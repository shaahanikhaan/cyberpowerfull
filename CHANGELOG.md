# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] — Offline CVE intelligence and proof-only payloads

Everything in this release runs locally: no cloud key, no scanner binary, no network call made
by the agent itself. Feeds are files the operator fetched; payloads are proof vectors, not
weapons; candidates stay unverified until evidence confirms them.

### Added

- **Offline advisory corpus** (`intel/`): SQLite store with merge-on-import semantics
  (severity maximum, CVSS maximum, KEV flag OR, references unioned, no detail loss), a
  dependency-free version tokeniser/ranger (`2.4.49`, `9.6p1`, `2.0-beta9`), and a curated
  bundled snapshot of 12 verifiable advisories with fixed intervals.
- **Feed importers** for NVD 2.0 JSON, NVD 1.1 JSON, CISA KEV JSON, and a native format, with
  format auto-detection, CPE parsing, and per-row error accounting. Importer errors never abort
  a feed.
- **Deterministic CVE correlation**: component → advisory matching with product aliases, range
  membership, confidence scoring, severity capping for unversioned components, and
  `verified=False` candidate findings that include the matched range, CVSS, KEV status, and
  remediation. Newly published 2025–2026 CVEs are covered as soon as the operator imports a
  current feed; the agent never invents an advisory.
- **Native HTTP probe tool** (`http_probe`): one bounded, scope-checked request with header and
  body allowlisting, CRLF rejection, same-host redirect following only, marker reflection,
  redirect-target analysis, DB error signature detection, and `Allow` enumeration.
- **Proof-only payload engine** (`payloads/`, `payload` tool): 55 catalogue entries across 14
  skills, JWT builders (`alg=none`, empty signature), request rendering for query/path/header/body
  contexts, and a safety audit that refuses destructive templates before a request is built.
- **`cve_correlate` tool**: the reasoning agent can now correlate its own observations against
  the local corpus (no network access), returning typed findings plus corpus statistics.
- **Native scan helpers** (`native_scan.py`): `resolve`, `ports` (TCP connect), `http` facts, and
  `inventory` (nmap XML + HTTP banners → components), each gated by `--scope`.
- **Bash toolkit** (`tools/bash/`): `cve_hunt.sh`, `payload_run.sh`, `scan_cycle.sh`, and
  `lib/common.sh`. Every script refuses to run without `scope.json`, re-checks targets through the
  Python scope engine, and writes timestamped JSON artifacts plus a Markdown summary.
- **CLI surface**: `--intel-status`, `--import-feed`, `--feed-format`, `--intel-store`,
  `--correlate`, `--min-cvss`, `--payload`, `--payload-param`, `--payload-ids`, `--http-probe`,
  `--probe-method`, `--probe-body`, `--probe-marker`.
- **Skill packs** now route the new tools: `exploit_availability` gains `cve_correlate`, the
  injection/access-control packs gain `payload` and `http_probe`.

### Changed

- 29 typed tools (was 26); tool count, README badge, and repository layout updated.
- `advisory` identifiers are validated by family (`CVE`, `GHSA`, `RHSA`, `USN`, `DSA`, `MSRC`,
  `ZDI`, `CNVD`, `BDU`) with a strict numeric pattern for CVEs, so malformed feed rows are
  rejected instead of stored.

### Tests

- 5 new test modules: intel (versioning, store, import, correlation), payloads (catalogue,
  rendering, safety guard), native tools (live loopback HTTP server, port scan, nmap XML),
  CLI intel surface, and the bash toolkit (subprocess, scope refusal, artifacts).
## [3.1.0] — Frictionless first run

Nothing about the safety model changed; this release removes the setup friction that made a first
run take ten minutes instead of thirty seconds.

### Added

- **`--lab`**: starts a real `http.server` listener on loopback, runs a real playbook against it,
  writes the usual trace/report, and stops the service. No model, no scanner binaries, no fixture
  data. Port selection is verified free first, and a busy port fails loudly instead of scanning
  nothing.
- **`--init-scope`**: writes a validated `scope.json` from flags
  (`--engagement`, `--targets`, `--capabilities`, `--expires`, `--contact`, `--max-rps`,
  `--allow-passive-sources`). It refuses to write `authorized: true` without
  `--authorization-ref`, refuses to overwrite an existing file without `--force`, and prints the
  exact next command.
- `make` targets: `setup`, `lab`, `doctor`, `toolchain`, `tools`, `test`, `lint`, `fmt`, `clean`.
- `scripts/install.sh`: Python 3.10 check, venv creation, editable install, optional
  `--with-tools` apt install of the scanner set, and a readiness summary at the end.
- `cpf` console script as a short alias.
- `cyberpowerfull.scope.bootstrap_scope` / `write_scope` (validated scope creation, no silent
  overwrite).

### Changed

- `--lab` requires the target to be in scope, like every other path; a scope that does not cover
  `127.0.0.1` exits `4`.
- CI smoke job runs `--lab` and asserts the served port is evidenced in the trace.
- Version 3.1.0; docs gain an "Easy start" section and a task-to-command table.

### Fixed

- `run_local_lab()` no longer passes an empty step budget to the runner (it now defaults to the
  CLI value of 80), which made the lab fail with a validation error.
- Lab runs carry their `run_id` into the trace, so the trace, report, findings JSON and memory
  file all agree on one identifier.


## [3.0.0] — Depth, automation, and live host awareness

This release makes the agent substantially more capable without weakening the authorization
model. Every addition runs through the same worker guardrails: scope re-check, phase check,
capability gate, negative cache, argv-only execution. It also carries the readiness and
safety hardening recorded below that landed on `main` while this release was in progress.

### Added

- **26 typed tools** (was 9). New wrappers: `masscan`, `naabu`, `amass`, `dnsrecon`, `katana`,
  `whatweb`, `wpscan`, `gobuster`, `feroxbuster`, `arjun`, `wafw00f`, `testssl`, `searchsploit`,
  `hydra`, plus external-agent adapters `strix`, `pentagi`, and `sn1per`.
- **Capability model** (`Capability`: `aggressive`, `credential_testing`, `external_agents`,
  `destructive`). Tools declare the capability they need; the worker blocks them before execution
  unless `scope.json` grants it. Capabilities are part of the scope fingerprint and the prompt.
- **Deterministic playbook engine** (`playbook.py`): six playbooks (`recon`, `web`, `network`,
  `stealth`, `api`, `full`), 34 ordered steps, parallel groups, and fact-driven adaptivity —
  discovered ports become the next scan's port list, live URLs and technology select testssl,
  wpscan, arjun, and Exploit-DB lookups. Runs with no model at all.
- **Live host inventory** (`inventory.py`): probes 68 catalogued binaries (including Kali renames
  `httpx-toolkit`, `testssl.sh`, `nxc`), reads version banners, discovers wordlists with kind and
  compression flags, counts nuclei templates and NSE scripts, detects Docker and external agents.
  The inventory is injected into the system prompt; nothing is simulated.
- **Offline knowledge base** (`knowledge.py` + CLI): `--search-exploits` (local Exploit-DB),
  `--templates` (nuclei), `--nse` (Nmap scripts), `--wordlists`. Missing sources exit `6` instead
  of returning an indistinguishable empty result.
- **External autonomous systems**: Strix (headless CLI with budget and turn caps), PentAGI
  (GraphQL `createFlow` + polling, REST fallback, report retrieval), Sn1per (real CLI + real loot
  workspace parsing). All three require `external_agents` and receive a scope statement.
- **13 new skill packs** (29 total), including `network_services`, `tls_hardening`, `api_security`,
  `graphql`, `cms_wordpress`, `active_directory`, `container_kubernetes`, `credential_testing`,
  `exploit_availability`, and `external_validation`.
- **Per-step skill selection**: at most eight packs (tree hypotheses first, then phase-appropriate
  packs), so the prompt fits a small local model's context window.
- **CLI**: `--playbook`, `--parallel`, `--max-steps`, `--list-playbooks`, `--agents`,
  `--toolchain [--json]`, `--doctor`, `--search-exploits`, `--templates`, `--nse`, `--wordlists`.
- **New exit code `8`** for an unknown playbook name.
- **Docs**: `docs/KALI.md` (host layout, packages, readiness) and `docs/INTEGRATIONS.md`
  (Strix, PentAGI, Sn1per setup and limits).

### Changed

- Worker allowlists are derived from the registry and the tool phase, with explicit cross-phase
  extras, plus a new `external` worker that can only run external-agent tools.
- The reasoning loop now consults the negative cache before executing a delegated tool, so an
  identical failing invocation is not retried within a run.
- Reports list the attack-tree node per step and state plainly when a run used no model.
- Binary resolution honours alternate executable names and rewrites `argv[0]` only.
- Default scope grants `aggressive` for the loopback lab; `scope.example.json` documents all four
  capabilities.
- Version, badges, and documented counts updated; CI adds a playbook smoke run and a live
  inventory check.

### Fixed

- Degraded gracefully when a probed directory is unreadable (`/root/nuclei-templates` under a
  non-root user raised `PermissionError`).
- Masscan JSON parsing tolerates the progress banners it prints before the JSON body.
- PentAGI reports that are JSON are parsed as records instead of being scraped as prose.

## [2.1.0] — Readiness and Safety Hardening

### Fixed

- Isolated all SQLite memory reads, aggregates and negative-cache lookups by run; preserve
  independent findings when the same database is reused.
- Return non-zero exit codes for failed inference, blocked policy actions and failed/incomplete
  tool calls while saving traces and reports when possible. Keep `--json` stdout parseable and
  retain the original target URL and port in the objective.
- Harden scope parsing (exact targets, explicit wildcard semantics, strict authorization boolean,
  IPv4-mapped IPv6 exclusions), re-check expiry, suppress out-of-scope findings, and check DNS
  exclusions before native and third-party calls where possible.
- Pace native TCP connections and pass per-tool rate hints, limit scanner redirects and update
  checks, require operator-approved ffuf wordlists and Nuclei template files, and require opt-in
  for passive third-party sources. These are guardrails, not an egress or rate-limit sandbox.
- Prevent inference redirects and environment-proxy use, honor custom local endpoints and exact
  Ollama tags, retry malformed model responses, and check time/token budgets before tool execution.
- Report truncated output and ambiguous scanner failures instead of silently claiming success;
  treat Nuclei matches and SQL heuristics conservatively and do not identify a service by port alone.
- Write new traces, reports and memory with owner-only POSIX permissions; validate replay IDs and
  schemas before constructing output filenames; escape untrusted Markdown report content and fix
  duplicate findings and attack-tree expansion at depth limits.
- Start the engagement scope template unauthorized until the operator explicitly enables it;
  update wheel license metadata for modern Python packaging.
- Reject numeric-only host aliases (such as hexadecimal IPv4) and apply IPv4-mapped IPv6 CIDR
  exclusions consistently to their IPv4 equivalents.
- Treat an interrupted model response as a reported inference failure rather than a crash; keep
  the original URL in `--render-prompt` and deduplicate repeated finding IDs within a trace batch.
- Round scanner request delays upward to whole milliseconds, refuse unrepresentable rates, expand
  `~` in permitted ffuf wordlists, and stop inventing a CVSS score for Dalfox findings.
- Treat a zero-exit SQLMap run as success only when it completes with a clean or confirmed result;
  connection failures and unrecognised output are now surfaced as errors.
- Let `--help`, `--version` and explicit budget flags work even when an environment budget value
  is malformed; invalid environment values are reported only when they would actually be used.

### Added

- A copy/paste loopback lab using recorded decisions and the native TCP probe, with no model or
  scanner binary required after dependency installation.
- Regression tests using real loopback TCP and mock-model HTTP services, plus a documented
  [readiness audit](docs/readiness-audit.md) with upstream references and remaining limitations.
- An opt-in live SQLMap integration test (`CYBERPOWERFULL_RUN_SQLMAP_TEST=1`) that starts an
  ephemeral loopback fixture and checks clean, positive and connection-failure outcomes.

## [2.0.0 baseline] — Pentest-Only Hard Fork

This release replaces the previous general-purpose automation framework with a focused,
autonomous, penetration-testing-only agent. Nothing from the old rule-based "brain" survives.

### Added

- **Three-layer brain** with enforced separation of concerns:
  - Layer 1 — model-backed reasoning loop (`brain/llm.py`, `brain/orchestrator.py`,
    `brain/system_prompt.jinja`), emitting one validated JSON decision per step
    (`{"step", "tool", "args", "reason"}`).
  - Layer 2 — typed tool layer (`tools/`) with Pydantic argument models, argv construction
    without a shell, deterministic output parsers, and scope re-checks per call.
  - Layer 3 — append-only SQLite memory (`memory/store.py`) for findings, attempts (negative
    cache), and steps, protected by UPDATE/DELETE triggers, exposed to the model only through a
    read-only `MemoryView`.
- **Task Difficulty Assessment** (`brain/tda.py`): horizon, evidence confidence, context load,
  and historical success, combined into a difficulty level, expansion threshold, and maximum
  attack-tree depth.
- **Evidence-Guided Attack Tree Search** (`brain/attack_tree.py`): scored hypotheses, TDA-gated
  selection, model-proposed expansion, pruning of low-value branches, and depth enforcement.
- **Strix-style Jinja2 system prompt** (`brain/system_prompt.jinja`) with `root_agent_directive`,
  `core_capabilities`, `communication_rules`, `execution_guidelines`, system-verified scope,
  TDA/EGATS state, tool catalogue, skill packs, stop conditions, and safety rules; rendered with
  `StrictUndefined` so missing context fails loudly.
- **Root/Worker role separation enforced in code**: `RootAgent.ALLOWED_ACTIONS = {delegate,
  terminate}` with no executor; workers (`recon`, `scan`, `validate`) own the tools and apply a
  deterministic per-worker allowlist.
- **16 skill packs** (Markdown/Jinja) covering `authentication_jwt`, `idor`, `sql_injection`,
  `xss`, `ssrf`, `csrf`, `xxe`, `rce`, `business_logic`, `race_conditions`, `path_traversal`,
  `open_redirect`, `mass_assignment`, `file_uploads`, `information_disclosure`, and
  `subdomain_takeover`.
- **9 typed tool wrappers**: `nmap`, `httpx`, `subfinder`, `nuclei`, `nikto`, `ffuf`, `sqlmap`,
  `dalfox`, plus native `tcp_probe` for environments without scanner binaries.
- **Local-only inference transport** (`brain/llm.py`): Ollama, llama.cpp, and deterministic
  replay clients; non-loopback endpoints rejected; API-key-free by construction.
- **Structured traces and replay** (`trace.py`, `reporting.py`): JSON trace with steps, tool
  calls, TDA snapshots, findings, attack-tree stats, and stop reason; Markdown report and
  findings JSON; `--replay` renders a recorded run without a model or a tool.
- **Scope enforcement** (`scope.py`): `scope.json` required at startup, CIDR/wildcard/domain
  matching, exclusions, expiry, phase allowlist, and a SHA-256 scope fingerprint in every trace.
- **CLI** (`cli.py`) with a pentest-only contract: run, `--replay`, `--check`, `--dry-run`,
  `--render-prompt`, `--list-tools`, `--list-skills`, `--json`, documented exit codes 0–7.
- **Test suite** (321 tests, 92% line coverage) with mocked `subprocess` calls per tool, scope
  and policy tests, prompt-rendering and tone tests, memory append-only tests, and a real
  end-to-end run against a local mock TCP service.
- **CI** (`.github/workflows/ci.yml`): ruff, black, `pytest --cov` (gate at 70%) on Python
  3.10–3.12, plus an end-to-end smoke job that asserts a structured trace with findings, the
  scope-refusal exit code, and successful replay.
- **Pre-commit** configuration: ruff, black, trailing-whitespace, end-of-file-fixer,
  check-yaml/json, detect-private-key.
- `LICENSE` (MIT), `SECURITY.md`, `scope.json` (loopback lab), `scope.example.json`,
  `examples/decisions.json`, `examples/trace-example.json`.

### Changed

- **README rewritten** to state what the project is, what it does, and what makes it different in
  the first ten lines; adds badges, an architecture diagram of the three layers and the
  TDA/EGATS loop, three-command Quick Start, a Supported Tools table with input schema, output
  format and test status, a Skills table for all 16 packs, and Safety & Scope at the top.
- Packaging moved to `src/` layout with `pyproject.toml` (PEP 621), console entry point
  `cyberpowerfull`, `pytest`/`coverage` configuration including `--cov-fail-under=70`.
- Tool execution hardened: `shell=False`, argv lists only, sanitised environment (cloud
  credentials stripped), per-tool timeouts, output truncation, and contained parser failures.
- Findings are now typed objects with severity, confidence, verification state, CWE/CVE, CVSS,
  remediation, and evidence; duplicates are suppressed and every finding is persisted to
  append-only memory before it appears in a report.
- `nuclei` runs with `-no-interactsh` to disable Interactsh; this flag alone does not prevent
  all outbound traffic.

### Removed

- `automation/brain/hummwin_brain_agent.py` and `hummwin_brain_agent_100x.py` — rule-based
  if/else "brain" with hardcoded randomness and simulated training.
- All general-purpose and unrelated automation modules: `automation/recon/*`,
  `automation/scanner/*`, `modules/executor.py`, `modules/parser.py`, `modules/reporter.py`,
  `scripts/run_full_scan.py`, `scripts/modify_tools.py`, `scripts/install_tools.sh`,
  `tests/test_recon.py`.
- The chat/language-selection interface and all "general assistant" behaviour.
- Every unverifiable claim in the README and code ("self-trained", "beyond Hacker AI / OpenAI
  Cyber", "1000009* POWERFULL", "100+ tools", "24/7 research"), and the aspirational
  `requirements.txt` entries for packages that do not exist.
- Committed `reports/` artifacts from previous runs (regenerate with the current CLI).
- The fictional "Gap 6–12" integration claims (ARTEMIS, RL simulator, hybrid accountability
  bridge, fictional compliance SDKs) that had no implementation behind them.
