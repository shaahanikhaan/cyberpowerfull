# cyberpowerfull

**What is it?** A local-only autonomous penetration-testing agent: a model-backed reasoning loop
that calls typed tools and records evidence against an authorized target. It is not a chatbot.

**What does it do?** Recon, scanning, validation, and reporting against an authorized target —
port discovery, HTTP probing, content discovery, template validation, injection confirmation.

**What makes it different?** Difficulty-aware planning, a typed tool layer, append-only memory,
no cloud API key, no Docker, and no chat surface.

[![version](https://img.shields.io/badge/version-2.0.0-blue.svg)](CHANGELOG.md)
[![CI](https://github.com/shaahanikhaan/cyberpowerfull/actions/workflows/ci.yml/badge.svg)](https://github.com/shaahanikhaan/cyberpowerfull/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

| Property | Value |
|---|---|
| Inference | local open-weight model (Qwen3-4B / equivalent) via Ollama or llama.cpp |
| Typed tools | 9 (nmap, httpx, subfinder, nuclei, nikto, ffuf, sqlmap, dalfox, tcp_probe) |
| Skill packs | 16 markdown/Jinja behavioural packages |
| Tests | 321 tests, 92% line coverage, `pytest --cov-fail-under=70` enforced in CI |
| Cloud dependencies | none (loopback-only inference, no telemetry, no SaaS callbacks) |

> **This repository was hard-forked to be pentest-only.** The previous general-purpose
> "assistant" surface, the rule-based pseudo-brain, and the unverifiable marketing claims were
> removed. What remains is a reasoning loop, a typed tool layer, and deterministic memory.
> See [CHANGELOG.md](CHANGELOG.md).

---

## Safety & Scope (read first)

The agent **refuses to run without `scope.json`**. There is no override flag, no
"`--force`", and no interactive confirmation prompt that a user could click through.

- `scope.json` must contain `{"authorized": true}` and a non-empty target list. Anything else
  exits with code `3` before a single tool is invoked.
- Every tool call is re-validated against the scope by the worker layer. A target outside the
  scope is blocked, recorded as a blocked attempt, and never executed (exit code `4` for the
  requested `--target`).
- Scope is injected into the system prompt by the system, not by the model, together with a
  SHA-256 fingerprint that is embedded in every trace.
- Out-of-band interaction is disabled (`nuclei -no-interactsh`), cloud inference endpoints are
  rejected at the transport layer, and tool subprocesses run with cloud credentials stripped
  from the environment.
- Exploitation is proof-only: no persistence, no lateral movement, no data extraction, no
  denial of service, no webshells.

Test only assets you are contractually authorized to test. Unauthorized access to computer
systems is a criminal offence in most jurisdictions. See [SECURITY.md](SECURITY.md).

---

## Architecture

Three layers, strict separation, deterministic control plane around an LLM:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1 — REASONING (local model, e.g. Qwen3-4B via Ollama / llama.cpp)      │
│   system_prompt.jinja  →  TDA  →  EGATS node  →  one JSON decision per step  │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  {"step": 3, "tool": "delegate", "args": {…}, "reason": "…"}
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ ROOT AGENT — orchestration only. Permitted actions: delegate | terminate.    │
│   no executor · no shell · no subprocess handle · no memory write access     │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  DelegationRequest (Pydantic, extra keys rejected)
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ LAYER 2 — TOOL & SKILL LAYER (deterministic)                                 │
│   workers: recon | scan | validate                                           │
│   typed tools: nmap httpx subfinder nuclei nikto ffuf sqlmap dalfox tcp_probe│
│   Pydantic args → argv list (shell=False) → subprocess → parser → Findings   │
│   16 skill packs (Markdown/Jinja) rendered into the system prompt            │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  ToolResult(status, findings, observations)
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ LAYER 3 — MEMORY (deterministic, append-only SQLite)                         │
│   findings · attempts (negative cache) · steps · evidence                    │
│   UPDATE/DELETE rejected by triggers · model sees a read-only MemoryView     │
└──────────────────────────────────────────────────────────────────────────────┘
```

The per-step loop (TDA + EGATS):

```
        ┌──────────────────────────── TDA ─────────────────────────────┐
        │ horizon · evidence confidence · context load · historical win │
        └───────────────────────────────┬──────────────────────────────┘
                                        ▼
        memory digest ────────► difficulty score, level, threshold, max depth
                                        │
                                        ▼
                     EGATS: pick the highest expected-value node
                            (no over-commitment when difficulty is high)
                                        │
                                        ▼
        system prompt = scope + TDA state + attack tree + memory + tools + skills
                                        │
                                        ▼
                     local model → exactly one validated JSON decision
                                        │
                                        ▼
        delegate → worker → scope re-check → typed tool → parsed findings
                                        │
                                        ▼
        append findings/attempts to memory · update tree · write trace record
```

**Task Difficulty Assessment** (`brain/tda.py`) scores four measurable dimensions and maps
them to a difficulty level, an expansion threshold, and a maximum tree depth:

| Dimension | Meaning | Weight |
|---|---|---|
| Horizon | fraction of the step budget consumed | 0.35 |
| Evidence confidence | strength of the evidence collected so far | 0.30 (inverted) |
| Context load | fraction of the context window consumed | 0.20 |
| Historical success | success rate over recorded attempts | 0.15 (inverted) |

**Evidence-Guided Attack Tree Search** (`brain/attack_tree.py`) scores each hypothesis as
`prior × (1 + evidence) − 0.15 × failures`. When difficulty is `high` or `critical`, nodes that
cannot clear the raised threshold are pruned instead of explored, and the allowed depth shrinks.
The model can expand the tree by proposing child hypotheses; only the orchestrator mutates it.

### Repository layout

```
src/cyberpowerfull/
├── cli.py                  # pentest-only CLI, exit-code contract
├── scope.py                # scope.json loading, matching, fingerprint
├── models.py               # Phase, Severity, Finding, Decision, BudgetState
├── config.py               # RunConfig, ModelConfig, ToolPolicy (env sanitation)
├── trace.py                # Trace / StepRecord / replay
├── reporting.py            # Markdown report + findings JSON
├── brain/
│   ├── system_prompt.jinja # the behavioural operating system
│   ├── prompt.py           # Jinja2 renderer (StrictUndefined)
│   ├── llm.py              # loopback-only Ollama / llama.cpp / replay clients
│   ├── tda.py              # Task Difficulty Assessment
│   ├── attack_tree.py      # EGATS state machine
│   └── orchestrator.py     # RootAgent, WorkerAgent, Orchestrator
├── tools/                  # 9 typed wrappers + registry
├── skills/packs/           # 16 Markdown/Jinja skill packages
└── memory/store.py         # append-only SQLite memory
```

---

## Quick Start

Three commands, no API key, no Docker:

```bash
pip install -e .
python -m cyberpowerfull.cli --scope scope.json --target example.com
python -m cyberpowerfull.cli --replay traces/latest.json
```

Before the second command, one of:

```bash
ollama serve & ollama pull qwen3:4b              # Ollama backend (default)
llama-server -m qwen3-4b-instruct.gguf -c 32768  # llama.cpp backend, then --llm llamacpp:qwen3
```

`scope.json` in the repository root is a loopback-only lab scope. Copy `scope.example.json` and
replace the targets, authorization reference, and expiry with your engagement values. The agent
will not start otherwise.

### Common invocations

```bash
# Validate scope, tool availability, and the local model endpoint without running anything
python -m cyberpowerfull.cli --check --scope scope.json --target 127.0.0.1

# Rehearse the loop with command lines built but nothing executed
python -m cyberpowerfull.cli --scope scope.json --target 127.0.0.1 --dry-run

# Inspect what the model is told (regenerate the system prompt)
python -m cyberpowerfull.cli --render-prompt --scope scope.json --target 127.0.0.1

# Catalogue
python -m cyberpowerfull.cli --list-tools
python -m cyberpowerfull.cli --list-skills
```

Artifacts: `traces/latest.json` (structured run trace), `artifacts/report-<run_id>.md`
(human review), `artifacts/findings-<run_id>.json` (machine review),
`artifacts/memory.sqlite3` (append-only memory).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | run completed (any stop condition: tree exhausted, budget, terminate, critical finding) |
| 2 | usage error |
| 3 | `scope.json` missing, invalid, unauthorized, or expired |
| 4 | target outside the authorized scope |
| 5 | local inference unavailable |
| 6 | tool argument or execution error surfaced to the operator |
| 7 | policy violation by the reasoning model (e.g. the root agent tried to run a scanner) |

---

## Supported Tools

Every wrapper validates arguments with Pydantic (`extra="forbid"`), builds an argv list with
`shell=False`, executes through `subprocess`, and parses output into typed findings. Cloud
credentials are stripped from the subprocess environment.

| Tool | Input schema (key fields) | Output format | Status |
|---|---|---|---|
| `nmap` | `target`, `ports` (`top-N` or list), `service_detection`, `timing`, `scripts` (allowlist) | XML on stdout (`-oX -`) → ports, service banners | tested (unit, mocked subprocess) |
| `httpx` | `target` (URL), `ports`, `tech_detect`, `follow_redirects`, `threads` | JSONL (`-json`) → status, title, tech, server | tested (unit) |
| `subfinder` | `target` (domain), `all_sources`, `recursive`, `max_findings` | one hostname per line | tested (unit) |
| `nuclei` | `target`, `severity`, `tags`, `templates`, `rate_limit`, `concurrency` | JSONL → template, severity, CVE/CWE, matcher | tested (unit) |
| `nikto` | `target`, `port`, `ssl`, `tuning` | plain text `+` items → severity mapping | tested (unit) |
| `ffuf` | `target` (must contain `FUZZ`), `wordlist`, `method`, `extensions`, `match_codes` | JSON file (`-of json`) → discovered paths | tested (unit) |
| `sqlmap` | `target` (URL), `data`, `parameter`, `level`, `risk`, `technique`, `dbms` | stdout → confirmed injection point | tested (unit) |
| `dalfox` | `target` (URL), `method`, `data`, `cookie`, `workers` | JSON file (`--format json`) → XSS payloads | tested (unit) |
| `tcp_probe` | `target`, `ports` (≤64), `timeout_s` | native JSON (`{"open": [...], "errors": {...}}`) | tested (unit + end-to-end) |

`tcp_probe` is a native pure-Python TCP connect probe. It exists so that a run produces real
evidence on machines without scanner binaries (CI, minimal lab images) — no payloads, no
fingerprinting.

Status legend: *unit* means argv construction, output parsing, error paths, and
`subprocess` interactions are covered by tests with mocked subprocess calls. These wrappers have
not been validated against live third-party targets in CI; treat the parsers as version-sensitive.

---

## Skills

Skill packs are Markdown/Jinja packages rendered into the system prompt. Each pack states the
signals that justify it, the probe order, the validation criteria, the evidence required to
report a finding, and its stop criteria. A skill is a behavioural contract, not executable code.

| Skill pack | Covers | Primary tools |
|---|---|---|
| `authentication_jwt` | token handling, `alg` confusion, claim tampering, session lifecycle | httpx, ffuf |
| `idor` | horizontal and vertical object access with two identities | httpx, ffuf |
| `sql_injection` | boolean differentials, error signatures, confirmation-only sqlmap | sqlmap, ffuf |
| `xss` | reflection context mapping, payload confirmation | dalfox, ffuf |
| `ssrf` | server-initiated requests to in-scope collaborators only | httpx, nuclei |
| `csrf` | token presence, SameSite behaviour, Origin validation | httpx |
| `xxe` | DOCTYPE/entity handling in XML, SVG, SOAP, documents | httpx, nuclei |
| `rce` | proof-only evaluation of interpreters and template engines | nuclei, httpx |
| `business_logic` | client-controlled value, entitlement, and workflow state | httpx, ffuf |
| `race_conditions` | check-then-act limits with small parallel bursts | httpx |
| `path_traversal` | encoded traversal sequences against file parameters | ffuf, httpx |
| `open_redirect` | Location-header control through redirect parameters | httpx, nuclei |
| `mass_assignment` | privileged fields accepted from client bodies | httpx |
| `file_uploads` | type, extension, and serving behaviour of uploaded content | httpx, ffuf |
| `information_disclosure` | banners, debug endpoints, backups, leaked metadata | nmap, httpx, nikto, nuclei, ffuf, tcp_probe |
| `subdomain_takeover` | dangling DNS records pointing at unclaimed resources | subfinder, httpx |

```bash
python -m cyberpowerfull.cli --list-skills
```

---

## How the agent behaves

The system prompt (`src/cyberpowerfull/brain/system_prompt.jinja`) is the behavioural operating
system. It is rendered with `StrictUndefined` — a missing context key is a hard failure, never a
silently partial contract — and contains, in order:

1. `root_agent_directive` — orchestration and delegation only; the forbidden actions are listed
   explicitly and enforced in code (`RootAgent.ALLOWED_ACTIONS`).
2. `core_capabilities` — identity as an authorized pentest validation agent, and the
   capabilities it explicitly does not have (general conversation, unrelated assistance).
3. `communication_rules` — exactly one JSON object per step, the decision schema, inter-agent
   messaging rules, and tool-call requirements.
4. `execution_guidelines` — authorization, recon → scanning → validation order, evidence rules,
   proof-only exploitation.
5. `authorized_scope` — the system-verified scope block and fingerprint.
6. `task_difficulty_assessment` — the four dimensions, the composite score, and the directive.
7. `evidence_guided_attack_tree_search` — the selection rule and current tree state.
8. `memory` — read-only digest of findings, severities, failures, and success rate.
9. `tool_catalogue` — every tool with phase, install state, description, and argument schema.
10. `skill_packs` — all 16 rendered packages.
11. `current_objective`, 12. `stop_conditions`, 13. `safety`.

Stop conditions: attack tree exhausted, budget exhausted (iterations / tokens / seconds), a
critical finding confirmed with verified evidence, no node clearing the threshold at high
difficulty, or an explicit `terminate` decision.

### Reasoning backends

| Spec | Backend | Notes |
|---|---|---|
| `ollama:qwen3:4b` | Ollama `/api/chat` | default; `format: json` enforced |
| `llamacpp:qwen3` | llama.cpp `/v1/chat/completions` | `response_format: json_object` |
| `replay:path.json` | recorded decision stream | deterministic reproduction, no model |

Any non-loopback endpoint is rejected with exit code `5` before a request is sent. There is no
API-key code path and none will be added.

---

## Development

```bash
pip install -e ".[dev]"
ruff check .
black --check .
pytest                      # coverage gate (70%) lives in pyproject.toml addopts
pre-commit install          # ruff, black, trailing-whitespace, end-of-file-fixer
```

Continuous integration (`.github/workflows/ci.yml`) runs ruff, black, the test suite with
coverage on Python 3.10–3.12, and an end-to-end smoke test: a replay decision stream drives the
agent against a local mock TCP service, and the job asserts that the emitted trace contains
steps, tool calls, and findings.

Example artifacts are committed under `examples/`: `decisions.json` (replay stream) and
`trace-example.json` (trace produced by that stream against a local mock service).

## Limitations

- Parsers target current tool output formats; upstream CLI changes require parser updates.
- Validation quality depends on the local model. A 4B model needs a strict prompt and small
  steps; that is why decisions are single-action JSON with schema validation.
- Findings are evidence-linked, not proof-of-impact: a `low` finding is a hypothesis with
  support, not necessarily exploitable.
- There is no web UI, no multi-tenant server, no scheduling, and no chat interface — by design.

## License

MIT — see [LICENSE](LICENSE). Security policy and reporting: [SECURITY.md](SECURITY.md).
Change history: [CHANGELOG.md](CHANGELOG.md).
