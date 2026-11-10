# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
