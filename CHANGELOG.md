# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] — Depth, automation, and live host awareness

This release makes the agent substantially more capable without weakening the authorization
model. Every addition runs through the same worker guardrails: scope re-check, phase check,
capability gate, negative cache, argv-only execution.

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

## [Unreleased] — Pentest-Only Hard Fork

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
- `nuclei` runs with `-no-interactsh` so no target data leaves the machine.

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
