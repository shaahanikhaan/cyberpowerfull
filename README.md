# cyberpowerfull

**What is it?** A local-only autonomous penetration-testing agent — a model-backed reasoning
loop **and** a deterministic multi-tool automation engine — that is not a chatbot, needs
no cloud API key, needs no docker for its core loop, and runs real typed tools against an authorized
target with evidence capture: recon, scanning, validation, and reporting.

**What does it do?** Recon, scanning, validation, and reporting against an authorized target —
subdomain and DNS enumeration, port and service discovery, HTTP probing, crawling, content
discovery, TLS review, CMS enumeration, template validation, bounded credential testing,
public-exploit correlation, and budgeted delegation to external autonomous agents.

**What makes it different?** Two execution paths over one guarded tool layer: the reasoning loop
(TDA + EGATS) when you want a model to choose steps, and six deterministic playbooks when you
want reproducible automation with no model at all. Plus a live inventory of the host toolchain,
capability-gated aggression, append-only memory, an offline knowledge base (Exploit-DB, nuclei
templates, NSE scripts), and no cloud API key, no Docker for the core loop, and no chat surface.

[![version](https://img.shields.io/badge/version-3.2.0-blue.svg)](CHANGELOG.md)
[![CI](https://github.com/shaahanikhaan/cyberpowerfull/actions/workflows/ci.yml/badge.svg)](https://github.com/shaahanikhaan/cyberpowerfull/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![CodeQL](https://github.com/shaahanikhaan/cyberpowerfull/actions/workflows/codeql.yml/badge.svg)](https://github.com/shaahanikhaan/cyberpowerfull/actions/workflows/codeql.yml)

| Property | Value |
|---|---|
| Reasoning | local open-weight model (Qwen3-4B / equivalent) via Ollama or llama.cpp — optional |
| Automation | 6 deterministic playbooks, 34 ordered steps, parallel groups, fact-driven adaptivity |
| Typed tools | 26 (22 CLI wrappers, 1 native connector, 3 external-agent adapters) |
| External agents | Strix (headless CLI), PentAGI (REST/GraphQL API), Sn1per (loot workspace) |
| Skill packs | 29 markdown/Jinja behavioural packages, selected per step |
| Host inventory | 68 catalogued binaries, wordlists, nuclei templates, NSE scripts, Exploit-DB |
| Tests | 682 tests, 88% line coverage, `pytest --cov-fail-under=70` enforced in CI |
| Cloud dependencies | none for the core loop (loopback only inference, no telemetry, no SaaS callbacks) |

### Documentation

| Start here | For |
|---|---|
| [docs/GUIDE.md](docs/GUIDE.md) | **user guide**: install → first run → scope → playbooks → results → troubleshooting |
| [docs/HANDOFF.md](docs/HANDOFF.md) | **maintainer map**: invariants, module layout, test reality, gotchas, release checklist |
| [docs/ROADMAP.md](docs/ROADMAP.md) | what shipped and what comes next, with acceptance tests |
| [docs/KALI.md](docs/KALI.md) | host layout, packages, wordlist/template resolution |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | Strix, PentAGI, Sn1per setup and data flow |
| [AGENTS.md](AGENTS.md) | entry point for AI coding agents |
| [CONTRIBUTING.md](CONTRIBUTING.md) | dev setup, standards, how to add a tool |
| [docs/README.md](docs/README.md) | full documentation index |

> **This repository is pentest-only.** The previous general-purpose "assistant" surface, the
> rule-based pseudo-brain, and the unverifiable marketing claims were removed in 2.0. 3.0 adds
> depth (more tools, a real automation engine, external-agent adapters, live host inventory)
> without loosening the authorization model. See [CHANGELOG.md](CHANGELOG.md).

---

## Safety & Scope (read first)

The agent **refuses to run without `scope.json`**. There is no override flag, no "`--force`",
and no interactive confirmation prompt that a user could click through.

- `scope.json` must contain `{"authorized": true}` and a non-empty target list. Anything else
  exits with code `3` before a single tool is invoked.
- Every tool call is re-validated against the scope by the worker layer. A target outside the
  scope is blocked, recorded as a blocked attempt, and never executed (exit code `4` for the
  requested `--target`).
- **Capabilities are explicit opt-ins.** A tool that needs a capability is blocked before
  execution unless `scope.json` grants it. Nothing aggressive is enabled by accident:

  | Capability | Unlocks | Examples |
  |---|---|---|
  | `aggressive` | high-rate scans and full-range sweeps | `masscan`, `naabu` |
  | `credential_testing` | bounded online authentication testing | `hydra` |
  | `external_agents` | delegation to third-party autonomous systems | `strix`, `pentagi`, `sn1per` |
  | `destructive` | reserved; no shipped tool requires it | — |

- Scope, including granted capabilities, is injected into the system prompt by the system, not by
  the model, together with a SHA-256 fingerprint that is embedded in every trace. Changing the
  capability list changes the fingerprint.
- Out-of-band interaction is disabled (`nuclei -no-interactsh`), cloud inference endpoints are
  rejected at the transport layer, and tool subprocesses run with cloud credentials stripped
  from the environment.
- Exploitation is proof-only: no persistence, no lateral movement, no data extraction, no
  denial of service, no webshells. `searchsploit` reports that exploit code exists; it never
  downloads or runs it.
- Recovered passwords from `hydra` are redacted in evidence. Traces and reports are engagement
  artefacts, not a credential store.

**These checks are guardrails, not an operating-system or network sandbox.** Read the precise
limits before pointing the agent at anything that matters:

- Scope is **host-based**: exact hosts/IPs, CIDRs, `example.test` (apex + subdomains), and
  `*.example.test` (subdomains only). It does not restrict ports, paths, or HTTP methods;
  exclusions win over inclusions.
- A DNS answer inside an excluded network is blocked before the native TCP probe and checked
  best-effort before other scanners. External tools may resolve again — enforce exclusions at the
  network boundary too.
- `max_rps` paces native TCP connects and is translated into supported scanner rate/delay flags.
  It is **not a guaranteed global traffic limit**: retries, templates, DNS, subprocesses, and
  parallel groups can exceed it.
- `subfinder` is blocked unless `allow_passive_sources` is set; `ffuf` and `nuclei` accept only
  operator-listed files or files from the local wordlist/template libraries. Indexes are the
  operator's responsibility — review templates before granting them.
- Third-party scanners, templates, and target responses can produce traffic this process cannot
  inspect. Run on an isolated host with egress rules, use test accounts, and watch the run.
- A finding is an observation or a tool-reported candidate, **not proof of impact**. An open port
  does not identify a service; a template match is unverified until the evidence says otherwise.
- Traces, reports, and SQLite memory can contain URLs, cookies, request bodies, and model output.
  New files are owner-only on POSIX but not encrypted; protect and delete them per the agreement.

Test only assets you are contractually authorized to test. Unauthorized access to computer
systems is a criminal offence in most jurisdictions. See [SECURITY.md](SECURITY.md) and the
[readiness audit](docs/readiness-audit.md) for verified behaviour and residual risk.

---

## Architecture

Four components, strict separation, a deterministic control plane around an optional LLM:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1 — REASONING (optional: local model, e.g. Qwen3-4B via Ollama)        │
│   system_prompt.jinja → TDA → EGATS node → one JSON decision per step        │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  {"step": 3, "tool": "delegate", "args": {…}}
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ ROOT AGENT — orchestration only. Permitted actions: delegate | terminate.    │
│   no executor · no shell · no subprocess handle · no memory write access     │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  DelegationRequest (Pydantic, extra keys rejected)
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ LAYER 2 — GUARDED EXECUTION (deterministic, shared by both execution paths)  │
│   workers: recon | scan | validate | external                                │
│   allowlists derived from the registry · phase check · capability gate       │
│   scope re-check · negative cache · argv list (shell=False) · parser         │
│   26 typed tools · 29 skill packs · 6 playbooks                              │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  ToolResult(status, findings, observations)
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ LAYER 3 — MEMORY (deterministic, append-only SQLite)                         │
│   findings · attempts (negative cache) · steps · evidence                    │
│   UPDATE/DELETE rejected by triggers · model sees a read-only MemoryView     │
└──────────────────────────────────────────────────────────────────────────────┘

LIVE HOST INVENTORY  ──►  which/whatis, version banners, /usr/share scans
                          wordlists · nuclei templates · NSE · Exploit-DB
                          feeds the prompt, the playbooks, and --doctor
```

Two execution paths, identical guardrails:

```
path A (reasoning)            path B (playbook)
TDA → EGATS → model → JSON    playbook definition (groups of steps)
        │                            │
        └────────► DelegationRequest ◄────────┘
                         │
              WorkerAgent.execute()  ← scope, phase, capability, cache
                         │
                 typed tool → findings
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

### Repository layout

```
src/cyberpowerfull/
├── cli.py                  # pentest-only CLI, exit-code contract
├── scope.py                # scope.json, capabilities, matching, fingerprint
├── models.py               # Phase, Capability, Severity, Finding, Decision, BudgetState
├── config.py               # RunConfig, ModelConfig, ToolPolicy (env sanitation)
├── inventory.py            # live toolchain: binaries, wordlists, templates, agents
├── knowledge.py            # local Exploit-DB / nuclei templates / NSE readers
├── playbook.py             # deterministic multi-tool engine (6 playbooks)
├── trace.py                # Trace / StepRecord / replay
├── reporting.py            # Markdown report + findings JSON
├── brain/
│   ├── system_prompt.jinja # the behavioural operating system
│   ├── prompt.py           # Jinja2 renderer (StrictUndefined)
│   ├── llm.py              # loopback-only Ollama / llama.cpp / replay clients
│   ├── tda.py              # Task Difficulty Assessment
│   ├── attack_tree.py      # EGATS state machine
│   └── orchestrator.py     # RootAgent, WorkerAgent, Orchestrator
├── tools/                  # 26 typed wrappers + registry + report extractors
├── skills/packs/           # 29 Markdown/Jinja skill packages
├── lab.py                  # real loopback service + playbook (the --lab path)
└── memory/store.py         # append-only SQLite memory

docs/                       # GUIDE, HANDOFF, ROADMAP, KALI, INTEGRATIONS, readiness audit
AGENTS.md                   # entry point for AI coding agents
CONTRIBUTING.md             # dev setup, standards, extension recipes
SECURITY.md  CHANGELOG.md   # policy and history
.github/                    # CI, release, CodeQL, issue forms, PR template, CODEOWNERS
scripts/                    # install.sh (setup) and release_check.py (pre-tag checks)
Makefile                    # setup / lab / doctor / tools / test / docs / release-check
tests/                      # 682 tests across CLI, tools, playbooks, lab, docs, repo hygiene
```

---

## Easy start

Two commands, nothing to configure. `--lab` starts a **real** HTTP service on the loopback
interface and runs a **real** playbook against it: no model, no scanner binaries, no fixture data.

```bash
make setup      # venv + editable install (or: ./scripts/install.sh)
make lab        # serve 127.0.0.1:8080 and scan it with the network playbook
```

After that:

```bash
make doctor     # what this host can actually run (binaries, wordlists, templates, agents)
make toolchain  # live inventory, install hints for everything missing
make tools      # apt-install the scanner set on Debian/Kali (prompts for sudo, review first)
```

On your own engagement, write the scope first — the agent refuses to run without one:

```bash
cyberpowerfull --init-scope scope.json \
    --engagement acme-q4 --targets app.example.test,10.0.0.0/24 \
    --authorize --authorization-ref SOW-2026-014
cyberpowerfull --scope scope.json --target app.example.test --playbook recon
```

`--init-scope` writes a validated file and refuses to mark it authorized without an
`--authorization-ref`; without `--authorize` it writes `"authorized": false` so the file cannot be
run by accident. `cpf` is installed as a short alias for `cyberpowerfull`.

| You want | Run |
|---|---|
| a first run in 30 seconds | `make lab` |
| to know what this host can do | `make doctor` |
| to install the scanners | `make tools` |
| a specific playbook against a real target | `cyberpowerfull --scope scope.json --target HOST --playbook web` |
| the model-driven loop | `ollama serve & ollama pull qwen3:4b` then `cyberpowerfull --scope scope.json --target HOST` |
| to prove a run happened | open `artifacts/report-*.md` or `--replay traces/latest.json` |

## Quick Start

A runnable loopback lab: a local listener, one real run against it with a recorded decision
stream, then the trace rendered back for review. No model, no binaries, no network.

```bash
python -m pip install -e .   # or: make setup
python -m http.server 8000 --bind 127.0.0.1 &
python -m cyberpowerfull.cli --scope scope.json --target 127.0.0.1 --llm replay:examples/decisions.json
cyberpowerfull --replay traces/latest.json
```

The bundled `scope.json` authorises `127.0.0.1` and `localhost` only, so this works out of the box.
`examples/decisions.json` is a recorded decision stream (`replay:` backend), which makes the run
deterministic; `examples/trace-example.json` is the trace it produces.

### Use a local model

```bash
ollama serve & ollama pull qwen3:4b              # Ollama backend (default)
llama-server -m qwen3-4b-instruct.gguf -c 32768  # llama.cpp backend, then --llm llamacpp:qwen3

python -m cyberpowerfull.cli --scope scope.json --target 127.0.0.1 --llm ollama:qwen3:4b
```

Before pointing it at a real engagement, copy `scope.example.json`, set `authorized` to `true`
only after you hold written authorization, replace the targets, and grant only the capabilities
the engagement needs. The agent will not start otherwise.

### Or skip the model entirely

Playbooks run the same tools with no inference at all:

```bash
python -m cyberpowerfull.cli --scope scope.json --target 127.0.0.1 --playbook network
```

### What a playbook run actually does

```
$ cyberpowerfull --scope scope.json --target 127.0.0.1 --playbook network
starting playbook network against 127.0.0.1 (engagement=localhost-lab, steps=9)
[01] playbook         tcp_probe    status=ok       findings=2 difficulty=-  node=net-tcp
...
stop_reason: playbook_complete
steps:       1 (tool calls: 1, tokens: 0/24000)
findings:    2 [info=2]
executed:    1 step(s): net-tcp
skipped:     8
  - net-nmap: binary not installed: nmap
  - net-naabu: binary not installed: naabu
  - net-services: binary not installed: nmap
```

Every skipped step states the real reason, and the same list is written into the trace
(`skipped`) and the report (`## Skipped steps`). Nothing is simulated: if the binary is missing or
the capability is absent, the step does not run and the artifacts say so.

## Automation playbooks

Playbooks are the sn1per-style path: an ordered set of typed tool calls in parallel groups, with
arguments derived from what earlier groups discovered. They use the **same** `WorkerAgent`
guardrails as the reasoning loop, so scope, phase, capability, and the negative cache all apply.

| Playbook | Steps | What it does |
|---|---|---|
| `recon` | 11 | native port sweep, subdomain enumeration, DNS records, HTTP probe, WAF, fingerprint, crawl, nikto |
| `web` | 14 | web fingerprint, crawl, content discovery, nuclei templates, TLS, WordPress (conditional), exploit lookup |
| `network` | 9 | native sweep, nmap, naabu, masscan (aggressive only), service detection, web-port probes, service exploit lookup |
| `stealth` | 6 | low-volume pass: passive names, one HTTP probe, fingerprint, limited crawl, medium+ templates only |
| `api` | 6 | route harvesting, hidden parameters, API templates, path discovery, exploit lookup |
| `full` | 34 | recon + web + network, dependency-ordered |

Adaptivity is deterministic and evidence-based:

- open ports found in group 0 become the exact `-p` list for the service-detection group;
- live URLs and technology fingerprints select testssl, wpscan, arjun, and Exploit-DB queries;
- wordlists are resolved from the host inventory (largest matching uncompressed file, or a
  documented preference order) — never a fabricated path; if none exists, the step is skipped;
- a missing binary skips the step; a missing capability skips the step; a previously failed
  identical invocation is not retried.

```bash
cyberpowerfull --scope scope.json --target app.example.test --playbook web --parallel 4
cyberpowerfull --scope scope.json --target 10.0.0.5 --playbook network --max-steps 20
cyberpowerfull --list-playbooks
```

`examples/playbook-trace-example.json` is a real trace produced by `--playbook network` on a
Debian host with the native connector only; it shows both the executed step and every skip
reason.

---

## External agents: Strix, PentAGI, Sn1per

Three adapters drive real third-party agents. Each requires the engagement capability
`external_agents`; each injects the scope into the delegated instruction and caps cost.

| Adapter | How it runs | What is parsed | Host requirements |
|---|---|---|---|
| `strix` | `strix -n -t <target> --scan-mode <mode> --max-budget <usd> --max-turns <n>` | console output + report files under `strix_runs/` | `pipx install strix-agent`, Docker, `STRIX_LLM`, `LLM_API_KEY` |
| `pentagi` | GraphQL `createFlow` mutation, then poll `flow(id)`; REST fallback | `report` field, REST report body, or prose | running PentAGI, `PENTAGI_URL`, `PENTAGI_API_TOKEN` |
| `sn1per` | `sniper -t <target> -m <mode> -w <workspace>` | real loot files under `/usr/share/sniper/loot/<workspace>` | `sn1per` installed (root) |

```bash
cyberpowerfull --agents                          # live availability check
export PENTAGI_URL=https://127.0.0.1:8443 PENTAGI_API_TOKEN=…
cyberpowerfull --scope scope.json --target app.example.test --llm ollama:qwen3:4b
```

The model can select them like any other tool (`delegate → external → strix`). Their findings are
treated as hypotheses until the underlying request/response is recorded — the extractor only
promotes lines that carry an explicit severity tag, and it re-derives severity from the evidence.

PentAGI self-signed TLS: set `PENTAGI_TLS_VERIFY=false` only on a loopback instance you control.
Details and troubleshooting: [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

---

## Host toolchain and local knowledge

The agent plans against the machine it is actually running on. `--toolchain` probes 68 binaries
(including Kali renames such as `httpx-toolkit` and `testssl.sh`), reads version banners, scans
wordlist directories, counts nuclei templates and NSE scripts, and detects Docker and the
external agents.

```bash
cyberpowerfull --toolchain                 # human-readable inventory + install hints
cyberpowerfull --toolchain --json          # machine-readable snapshot
cyberpowerfull --doctor --scope scope.json # pre-engagement readiness check
cyberpowerfull --wordlists discovery       # discovered content-discovery wordlists
cyberpowerfull --templates cve             # installed nuclei templates matching 'cve'
cyberpowerfull --nse http                  # installed NSE scripts matching 'http'
cyberpowerfull --search-exploits "apache 2.4"   # local Exploit-DB, no network
```

- **No bundled datasets and no fake data.** An empty inventory is reported as empty, and a
  missing knowledge source exits with code `6` instead of returning "no results".
- The system prompt contains the inventory, so the model prefers installed binaries and stops
  proposing work the host cannot do.
- Wordlists are only used when they exist and are uncompressed. Compressed lists are listed and
  flagged, never silently passed to a fuzzer.
- `docs/KALI.md` documents the expected Kali layout, package names, and install commands.

---

## Common invocations

```bash
# First run: real loopback service + playbook, no model, no binaries
python -m cyberpowerfull.cli --lab

# Write a scope (refuses to authorize without a reference)
python -m cyberpowerfull.cli --init-scope scope.json --engagement acme \
    --targets app.example.test --authorize --authorization-ref SOW-2026-014

# Validate scope, capabilities, tool availability, and the local model endpoint
python -m cyberpowerfull.cli --check --scope scope.json --target 127.0.0.1

# Rehearse either path with command lines built but nothing executed
python -m cyberpowerfull.cli --scope scope.json --target 127.0.0.1 --dry-run
python -m cyberpowerfull.cli --scope scope.json --target 127.0.0.1 --playbook web --dry-run

# Emit the whole trace as JSON on stdout (parseable; reports are still written)
python -m cyberpowerfull.cli --scope scope.json --target 127.0.0.1 --playbook network --json

# Inspect what the model is told (regenerate the system prompt)
python -m cyberpowerfull.cli --render-prompt --scope scope.json --target 127.0.0.1

# Catalogues
python -m cyberpowerfull.cli --list-tools
python -m cyberpowerfull.cli --list-skills
python -m cyberpowerfull.cli --list-playbooks
python -m cyberpowerfull.cli --agents
```

Artifacts: `traces/latest.json` (structured run trace), `artifacts/report-<run_id>.md`
(human review), `artifacts/findings-<run_id>.json` (machine review),
`artifacts/memory.sqlite3` (append-only memory).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | run completed, every executed action succeeded (tree exhausted, budget, terminate, critical finding) |
| 1 | unexpected fatal error (e.g. the system prompt could not be rendered) |
| 2 | usage error |
| 3 | `scope.json` missing, invalid, unauthorized, or expired |
| 4 | target outside the authorized scope |
| 5 | local inference unavailable |
| 6 | a tool errored, was missing or timed out, or a local knowledge source is absent |
| 7 | policy violation or a blocked delegation (the root agent tried to run a scanner itself) |
| 8 | unknown playbook name |

A failed or incomplete run still writes its trace and reports, then exits non-zero so scripts and
CI cannot mistake it for a clean result.

---

## Supported Tools

Every wrapper validates arguments with Pydantic (`extra="forbid"`), builds an argv list with
`shell=False`, executes through `subprocess` (or an in-process connector), and parses output into
typed findings. Cloud credentials are stripped from the subprocess environment. Alternate binary
names are resolved automatically (`httpx` → `httpx-toolkit`, `testssl.sh` → `testssl`).

| Tool | Phase | Input schema (key fields) | Output format | Status |
|---|---|---|---|---|
| `tcp_probe` | recon | `target`, `ports` (≤64), `timeout_s` | native JSON | tested (unit + live loopback) |
| `subfinder` | recon | `target` (domain), `all_sources`, `recursive` | hostnames per line | tested (unit) |
| `amass` | recon | `target` (domain), `timeout_minutes` | hostnames per line | tested (unit) |
| `dnsrecon` | recon | `target` (domain), `scan_type`, `lifetime_s` | JSON file (`-j`) | tested (unit) |
| `httpx` | recon | `target` (URL), `ports`, `tech_detect`, `follow_redirects` | JSONL | tested (unit) |
| `katana` | recon | `target` (URL), `depth`, `concurrency`, `rate_limit`, `js_crawl` | JSONL | tested (unit) |
| `wafw00f` | recon | `target` (URL), `find_all` | JSON file | tested (unit) |
| `nmap` | scanning | `target`, `ports` (`top-N`/list), `service_detection`, `timing`, `scripts` (allowlist) | XML (`-oX -`) | tested (unit) |
| `masscan` | scanning | `target`, `ports`, `rate`, `wait_s` | JSON (`-oJ -`) | tested (unit) |
| `naabu` | scanning | `target`, `top_ports`, `ports`, `rate`, `exclude_cdn` | JSONL | tested (unit) |
| `whatweb` | scanning | `target` (URL), `aggression` | JSON log | tested (unit) |
| `nikto` | scanning | `target`, `port`, `ssl`, `tuning` | plain text | tested (unit) |
| `ffuf` | scanning | `target` (must contain `FUZZ`), `wordlist`, `method`, `match_codes` | JSON file | tested (unit) |
| `gobuster` | scanning | `target`, `mode` (dir/dns/vhost/fuzz), `wordlist` (auto-resolved) | text (`-o`) | tested (unit) |
| `feroxbuster` | scanning | `target`, `wordlist` (auto-resolved), `depth`, `threads` | JSONL | tested (unit) |
| `arjun` | scanning | `target`, `method` (GET/POST/JSON), `threads` | JSON file | tested (unit) |
| `testssl` | scanning | `target` (URL), `severity_floor`, `protocol` | JSON file | tested (unit) |
| `wpscan` | scanning | `target` (URL), `enumerate`, `plugins_detection` | JSON file | tested (unit) |
| `nuclei` | validation | `target`, `severity`, `tags`, `templates`, `rate_limit` | JSONL | tested (unit) |
| `sqlmap` | validation | `target` (URL), `parameter`, `level`, `risk`, `technique` | stdout parse | tested (unit) |
| `dalfox` | validation | `target` (URL), `method`, `data`, `cookie`, `workers` | JSON file | tested (unit) |
| `searchsploit` | validation | `target`, `query` (product/CVE) | JSON | tested (unit) |
| `hydra` | validation | `target`, `service`, `username`, `password_list` (capped), `tasks` (≤8) | text parse | tested (unit) |
| `strix` | validation | `target` (URL), `scan_mode`, `max_budget_usd`, `max_turns`, `instruction` | console + run dir | tested (unit, mocked binary) |
| `pentagi` | validation | `target` (URL), `provider`, `max_wait_s`, `poll_s`, `instruction` | GraphQL/REST | tested (unit, mocked HTTP) |
| `sn1per` | scanning | `target`, `mode`, `workspace`, `port`, `loot_dir` | loot files | tested (unit, tmp loot) |

Status legend: *unit* means argv construction, output parsing, error paths, and `subprocess`
interactions are covered by tests with mocked subprocess or HTTP calls. These wrappers have not
been validated against live third-party targets in CI; treat the parsers as version-sensitive.
`tcp_probe` is also exercised end-to-end by the CI smoke job against a real local socket.

Capability-gated tools (`masscan`, `naabu`, `hydra`, `strix`, `pentagi`, `sn1per`) are blocked by
the worker layer before execution unless `scope.json` grants the capability.

---

## Skills

Skill packs are Markdown/Jinja packages rendered into the system prompt. Each pack states the
signals that justify it, the probe order, the validation criteria, the evidence required to
report a finding, and its stop criteria. A skill is a behavioural contract, not executable code.

The prompt carries **at most eight** packs per step: the skills named by the active attack-tree
hypotheses first, then the packs that fit the current phase. That keeps a 32k-context local model
from drowning in guidance it cannot act on.

| Skill pack | Covers | Primary tools |
|---|---|---|
| `information_disclosure` | banners, debug endpoints, backups, leaked metadata | nmap, httpx, nikto, nuclei, ffuf, tcp_probe |
| `subdomain_enum` | passive-first subdomain discovery and scoped resolution | subfinder, amass, dnsrecon, gobuster, httpx |
| `subdomain_takeover` | dangling DNS records pointing at unclaimed resources | subfinder, httpx |
| `network_services` | port surface, service identification, exploit availability | nmap, masscan, naabu, tcp_probe, searchsploit |
| `active_directory` | domain discovery and anonymous read access on AD services | nmap, dnsrecon, tcp_probe |
| `tls_hardening` | protocol, cipher, and certificate weaknesses | testssl, httpx |
| `api_security` | route harvesting, hidden parameters, object authorisation | katana, arjun, nuclei, ffuf |
| `graphql` | introspection exposure, field suggestions, mutation authorisation | katana, arjun, nuclei |
| `cms_wordpress` | core, plugin and theme enumeration with advisory matching | wpscan, whatweb, nuclei |
| `authentication_jwt` | token handling, `alg` confusion, claim tampering, session lifecycle | httpx, ffuf |
| `idor` | horizontal and vertical object access with two identities | httpx, ffuf |
| `csrf` | token presence, SameSite behaviour, Origin validation | httpx |
| `sql_injection` | boolean differentials, error signatures, confirmation-only sqlmap | sqlmap, ffuf |
| `xss` | reflection context mapping, payload confirmation | dalfox, ffuf |
| `ssrf` | server-initiated requests to in-scope collaborators only | httpx, nuclei |
| `xxe` | DOCTYPE/entity handling in XML, SVG, SOAP, documents | httpx, nuclei |
| `rce` | proof-only evaluation of interpreters and template engines | nuclei, httpx |
| `deserialization` | serialised blobs, type confusion, proof-only validation | httpx, nuclei |
| `business_logic` | client-controlled value, entitlement, and workflow state | httpx, ffuf |
| `race_conditions` | check-then-act limits with small parallel bursts | httpx |
| `path_traversal` | encoded traversal sequences against file parameters | ffuf, httpx |
| `open_redirect` | Location-header control through redirect parameters | httpx, nuclei |
| `mass_assignment` | privileged fields accepted from client bodies | httpx |
| `file_uploads` | type, extension, and serving behaviour of uploaded content | httpx, ffuf |
| `cloud_metadata` | link-local reachability from client-controlled fetches | httpx, nuclei |
| `container_kubernetes` | orchestrator and kubelet endpoints, read-only exposure checks | httpx, nuclei, testssl |
| `credential_testing` | explicit, capped, account-scoped authentication testing | hydra, httpx |
| `exploit_availability` | local Exploit-DB correlation against confirmed versions | searchsploit, nuclei |
| `external_validation` | budgeted delegation to an external autonomous agent | strix, pentagi, sn1per |

```bash
python -m cyberpowerfull.cli --list-skills
```

---

## How the agent behaves

The system prompt (`src/cyberpowerfull/brain/system_prompt.jinja`) is the behavioural operating
system. It is rendered with `StrictUndefined` — a missing context key is a hard failure, never a
silently partial contract — and contains, in order:

1. `root_agent_directive` — orchestration and delegation only; forbidden actions are listed
   explicitly and enforced in code (`RootAgent.ALLOWED_ACTIONS`).
2. `core_capabilities` — identity as an authorized pentest validation agent, and the capabilities
   it explicitly does not have.
3. `communication_rules` — exactly one JSON object per step, the decision schema, and tool-call
   requirements.
4. `execution_guidelines` — authorization, recon → scanning → validation order, evidence rules,
   tool-selection rules (prefer installed binaries, respect capabilities), proof-only exploitation.
5. `authorized_scope` — the system-verified scope block, granted capabilities, and fingerprint.
6. `task_difficulty_assessment` — the four dimensions, the composite score, and the directive.
7. `evidence_guided_attack_tree_search` — the selection rule and current tree state.
8. `memory` — read-only digest of findings, severities, failures, and success rate.
9. `host_toolchain` — installed and missing binaries, wordlists, templates, external agents.
10. `tool_catalogue` — every tool with phase, install state, capability, and argument schema.
11. `skill_packs` — the selected packs for this step.
12. `current_objective`, 13. `stop_conditions`, 14. `safety`.

Stop conditions: attack tree exhausted, budget exhausted (iterations / tokens / seconds), a
critical finding confirmed with verified evidence, no node clearing the threshold at high
difficulty, an explicit `terminate`, or a negative-cache hit on the chosen invocation.

### Reasoning backends

| Spec | Backend | Notes |
|---|---|---|
| `ollama:qwen3:4b` | Ollama `/api/chat` | default; `format: json` enforced |
| `llamacpp:qwen3` | llama.cpp `/v1/chat/completions` | `response_format: json_object` |
| `replay:path.json` | recorded decision stream | deterministic reproduction, no model |

Any non-loopback endpoint is rejected with exit code `5` before a request is sent. There is no
API-key code path for inference and none will be added.

---

## Development

```bash
pip install -e ".[dev]"
ruff check .
black --check .
pytest                      # 682 tests, coverage gate (70%) in pyproject.toml addopts
pre-commit install          # ruff, black, trailing-whitespace, end-of-file-fixer
```

Contributor workflow, standards, and extension recipes: [CONTRIBUTING.md](CONTRIBUTING.md).
Continuous integration (`.github/workflows/ci.yml`) runs ruff, black, the test suite with
coverage on Python 3.10–3.12, plus CodeQL and a tag-triggered release workflow, and two
end-to-end smoke jobs:

- a replay decision stream drives the agent against a local mock TCP service; the job asserts
  that the emitted trace contains steps, tool calls, and findings;
- a playbook run plus `--toolchain --json` prove that the no-model path and the live inventory
  work without optional binaries.

Example artifacts are committed under `examples/`: `decisions.json` (replay stream),
`trace-example.json` (trace produced by that stream), and `playbook-trace-example.json`
(real playbook trace with executed and skipped steps).

## Limitations

- Parsers target current tool output formats; upstream CLI changes require parser updates.
- Validation quality depends on the local model. A 4B model needs a strict prompt and small
  steps; that is why decisions are single-action JSON with schema validation and why skill text
  is selected per step.
- Playbooks do not reason: they execute a fixed, evidence-driven plan. Use the reasoning loop for
  hypothesis testing, and playbooks for reproducible coverage.
- External agents run with their own LLM budget and their own judgement. Their findings are
  hypotheses until local evidence backs them, and their cost is billed by their provider.
- `searchsploit` reports availability of public exploit code; it does not prove exploitability.
- Findings are evidence-linked, not proof-of-impact: a `low` finding is a hypothesis with
  support, not necessarily exploitable.
- There is no web UI, no multi-tenant server, no scheduling, and no chat interface — by design.

## Contributing

Issues and pull requests are welcome, with one condition: nothing may weaken the scope gate,
the capability gate, loopback-only inference, append-only memory, proof-only exploitation, or the
exit-code contract. Read [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/HANDOFF.md §4](docs/HANDOFF.md#4-invariants-do-not-break-these)
first; bug and feature forms are in `.github/ISSUE_TEMPLATE/`. Security defects go through
[SECURITY.md](SECURITY.md), never a public issue.

## License

MIT — see [LICENSE](LICENSE). Security policy and reporting: [SECURITY.md](SECURITY.md).
Change history: [CHANGELOG.md](CHANGELOG.md). Kali layout and install notes:
[docs/KALI.md](docs/KALI.md). External agent setup: [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).
Full documentation index: [docs/README.md](docs/README.md).
