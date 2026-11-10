# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Readiness and Safety Hardening

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
