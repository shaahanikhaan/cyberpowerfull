# cyberpowerfull

**What is it?** A local-only autonomous penetration-testing agent: a model-backed reasoning loop
that calls typed tools and records evidence against an authorized target. It is not a chatbot.

**What does it do?** Recon, scanning, validation, and reporting against an authorized target —
port discovery, HTTP probing, content discovery, template validation, and evidence reporting.

**What makes it different?** Difficulty-aware planning, a typed tool layer, append-only memory,
no cloud API key, no Docker, and a reproducible local lab mode.

[![version](https://img.shields.io/badge/version-2.0.0-blue.svg)](CHANGELOG.md)
[![CI](https://github.com/shaahanikhaan/cyberpowerfull/actions/workflows/ci.yml/badge.svg)](https://github.com/shaahanikhaan/cyberpowerfull/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

The current checkout is version **2.0.0**; there is no published v1.5 specification in this
repository. This is beta software, not a substitute for a professional assessment. See the
[readiness audit](docs/readiness-audit.md) for research, verified behavior, and residual risks.

## Safety & Scope (read first)

Use only on systems you own or have explicit written authorization to test. The program requires
an authorized `scope.json` and checks the primary target and phase before every delegated call.
A missing, invalid, unauthorized, or expired scope exits `3`; an out-of-scope CLI target exits `4`.

**These checks are guardrails, not an operating-system or network sandbox.** Third-party scanners,
local templates, DNS, redirects, tool configuration, and target responses can cause traffic that
the Python process cannot fully inspect or constrain. Run in an isolated environment with
operator-controlled DNS and outbound firewall rules; review the selected tools, templates,
wordlists, and target traffic before use. Some scanner tests can change server state. Do not run
against a production service without agreeing on those risks and rate limits with its owner.

- `targets` are exact hosts/IPs or CIDRs. `domains` include the named domain and its subdomains;
  `*.example.test` includes subdomains only, not the apex. Exclusions take precedence. Scope is
  **host-based**: it does not restrict ports, paths, or HTTP methods.
- A DNS lookup resolving into an excluded IP network is blocked before the native TCP probe and
  checked on a best-effort basis before other scanners. External tools can resolve again; enforce
  exclusions at the network boundary too.
- `max_rps` paces native TCP connections and is translated into supported scanner rate/delay
  flags. It is **not a guaranteed global traffic limit**: tool versions, retries, DNS, templates,
  subprocesses, and concurrent runs can exceed it. Use an external rate limiter when required.
- `subfinder` contacts third-party sources and is blocked unless `allow_passive_sources` is
  explicitly set to `true`. `ffuf` requires an existing file listed in `allowed_wordlists`;
  `nuclei` requires explicit, existing files listed in `allowed_nuclei_templates`. Paths are
  operator-controlled, not chosen freely by the model. Only allow files you have reviewed.
- `nuclei` is started with Interactsh, HTTP redirects, and update checks disabled; `httpx` may
  follow only same-host redirects; sqlmap is told not to follow redirects or proxies. These flags
  do not make arbitrary third-party templates or binaries safe. Model traffic is restricted to
  loopback and does not follow redirects or use environment HTTP proxies.
- Findings are observations or tool-reported candidates, **not proof of impact**. A Nuclei
  template match is unverified; an open port alone does not identify a service. Review findings
  and evidence manually.

Traces, reports, and SQLite memory can contain sensitive URLs, cookies, request bodies, model
output, and evidence. New files are written with owner-only permissions on POSIX, but they are
**not encrypted**; existing directory permissions are not changed. Protect and delete engagement
files according to your agreement. See [SECURITY.md](SECURITY.md).

## Architecture

```
operator scope + target
       │
       ▼
local model or recorded decisions ─► root agent (delegate / terminate only)
       │                                     │
       │                              TDA + attack tree
       │                                     ▼
       └──────────────────────────► worker + scope/policy checks
                                             │
                                   typed tool / native TCP probe
                                             │
                                             ▼
                              run-isolated append-only SQLite memory
                                             │
                                             ▼
                                  JSON trace + Markdown/JSON reports
```

The model selects one action at a time; it does not build shell commands. Workers validate typed
arguments, check the authorized target, apply per-tool guardrails, and execute argv lists with
`shell=False`. A deterministic task-difficulty assessment (TDA) and evidence-guided attack tree
help select the next hypothesis. Recon → scanning → validation is a planning guideline, not a
hard phase-order guarantee. Two identical consecutive failed attempts are blocked in a run.

SQLite records are keyed by run ID, so findings and failures from an earlier run do not enter a
new run's prompts or suppress its findings. SQL triggers reject ordinary UPDATE/DELETE operations;
they do not protect the database from someone with filesystem or schema access.

## Quick Start

Python 3.10+ is required. Installing the package downloads its Python dependencies if they are
not already available. No model or external scanner is needed for the following **loopback-only**
lab. Commands assume a checkout of this repository.

In terminal 1, install and start a self-owned test service on port 8000:

```bash
python -m pip install -e .
python -m http.server 8000 --bind 127.0.0.1
```

In terminal 2, run the recorded decisions and inspect the report:

```bash
cyberpowerfull --scope scope.json --target 127.0.0.1 --llm replay:examples/decisions.json
cyberpowerfull --replay traces/latest.json
```

The first command **does connect** to your local service using the native `tcp_probe`; it is not a
simulation. It should produce an informational open-port finding and an exit code of `0`. The
second command only regenerates reports from the saved trace and contacts neither a target nor a
model. Stop the HTTP server with Ctrl+C when finished. The bundled lab scope has no expiry and
authorizes only the listed loopback names/IPs; use an appropriate expiry for real engagements.

### Use a local model

Install and start [Ollama](https://github.com/ollama/ollama), then pull `qwen3:4b` using its
normal installation instructions. Model downloads require network access and can be large. In
another terminal:

```bash
ollama pull qwen3:4b
cyberpowerfull --check --scope scope.json --target 127.0.0.1 --llm ollama:qwen3:4b
cyberpowerfull --scope scope.json --target 127.0.0.1 --llm ollama:qwen3:4b
```

`--check` confirms scope, looks for tool executables on `PATH`, and checks model-server
reachability and the exact Ollama model tag. It does **not** verify scanner versions or prove
that a scan will succeed. Missing optional binaries are reported; only `tcp_probe` is built in.
A local model may still choose unavailable or disallowed tools; inspect the trace and exit code.
llama.cpp is available through `--llm llamacpp:MODEL`, with its server listening on loopback.

### Other useful commands

```bash
# Build commands without connecting to the target; still needs a local model or replay stream.
cyberpowerfull --scope scope.json --target 127.0.0.1 --llm replay:examples/decisions.json --dry-run

# Inspect scope and available tool/skill contracts.
cyberpowerfull --render-prompt --scope scope.json --target 127.0.0.1
cyberpowerfull --list-tools
cyberpowerfull --list-skills

# Machine-readable trace on stdout; progress goes to stderr.
cyberpowerfull --scope scope.json --target 127.0.0.1 --llm replay:examples/decisions.json --json
```

Artifacts default to `traces/latest.json`, `artifacts/report-<run_id>.md`,
`artifacts/findings-<run_id>.json`, and `artifacts/memory.sqlite3`. Use `--out`, `--trace`, and
`--memory` to choose paths. A dry run still uses the model or decision stream and writes these
local artifacts; it does not execute or resolve tool targets.

### Configure an engagement

Copy `scope.example.json`, set the engagement name, authorization reference, exact targets,
exclusions, allowed phases, rate, and expiry to match the written agreement. The template starts
with `"authorized": false`; set it to `true` only after confirming written permission. Do not use
the example domains as real targets. Optional properties default to disabled/empty:

```json
{
  "allow_passive_sources": false,
  "allowed_wordlists": ["/absolute/path/to/reviewed-wordlist.txt"],
  "allowed_nuclei_templates": ["/absolute/path/to/reviewed-template.yaml"]
}
```

This is a fragment, not a complete scope file. Allowlisted paths must be existing files. The
wrappers currently require simple ASCII paths without spaces or `..`; ffuf also supports `~`.
A Nuclei delegation must explicitly name its allowed template files; unrestricted default-template
scans are not allowed. An allowlisted file can still contain unsafe behavior, so review it and
restrict network access separately.

Environment variables `CYBERPOWERFULL_SCOPE`, `CYBERPOWERFULL_LLM`,
`CYBERPOWERFULL_LLM_BACKEND`, `CYBERPOWERFULL_MODEL`, `CYBERPOWERFULL_LLM_ENDPOINT`,
`CYBERPOWERFULL_MAX_ITERATIONS`, `CYBERPOWERFULL_MAX_TOKENS`, and
`CYBERPOWERFULL_MAX_SECONDS` provide defaults; explicit CLI options take precedence. Model
endpoints must be loopback HTTP(S) addresses. `localhost` is pinned to IPv4 loopback by the
transport; use `[::1]` explicitly for an IPv6-only service.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | run/replay completed without a failed or blocked action; inspect `stop_reason` for normal budget/tree termination |
| 1 | local storage, trace validation, or prompt-rendering failure |
| 2 | invalid CLI usage or non-positive budget |
| 3 | scope missing, invalid, unauthorized, or expired |
| 4 | requested CLI target outside scope |
| 5 | inference unavailable, invalid model response, or invalid local model configuration |
| 6 | a delegated tool failed, timed out, was missing, or received invalid arguments |
| 7 | root policy violation or blocked worker delegation |
| 130 | interrupted by the operator |

A run saves its trace and reports before returning `5`, `6`, or `7` when possible. A later
`--replay` reports whether replay itself succeeded, not whether the original run succeeded.
Time and token budgets are checked at decision boundaries; token counts are estimates. DNS and
third-party subprocess behavior can exceed a wall-clock budget, so use an external supervisor
for strict deadlines.

## Supported Tools

External tools are **optional** and installed separately. The wrapper is unit-tested against
sample output; third-party CLI flags and output formats are version-sensitive and are not a
promise of live compatibility with every release. The native probe is exercised against a real
loopback service in the test suite. Inspect and independently validate results.

| Tool | Input schema (key fields) | Output format | Status |
|---|---|---|---|
| `nmap` | `target`, `ports`, `service_detection`, allowlisted `scripts` | XML → open ports and banners | tested with mocked subprocess; default NSE script set rejected |
| `httpx` | URL `target`, `ports`, `tech_detect`, `follow_redirects`, `threads` | JSONL → status, title, technology | tested with mocks; install ProjectDiscovery's httpx |
| `subfinder` | domain `target`, `all_sources`, `recursive` | hostnames → candidates | tested with mocks; external-source opt-in required |
| `nuclei` | URL `target`, `severity`, `tags`, `templates`, `rate_limit` | JSONL → unverified template matches | tested with mocks; reviewed allowlisted templates required |
| `nikto` | `target`, `port`, `ssl`, `tuning` | text → observations | tested with mocks; ambiguous error exits are surfaced |
| `ffuf` | URL with `FUZZ` in path/query, allowlisted `wordlist`, `method` | JSON file → discovered paths | tested with mocks; no authority fuzzing or redirects |
| `sqlmap` | URL `target`, `data`, `parameter`, `level`, `risk`, `technique` | text → injection candidates | tested with mocks; preliminary heuristics stay unverified |
| `dalfox` | URL `target`, `method`, `data`, `cookie`, `workers` | JSON file → XSS candidates | tested with mocks; review compatibility and output |
| `tcp_probe` | `target`, `ports` (≤64), `timeout_s` | native JSON → open TCP ports | tested with mocks and a loopback service |

## Skills

The 16 Markdown/Jinja skill packs are planning guidance, not independent executable features or
proof that the agent can fully test every category. They are included in the model prompt.

| Skill pack | Focus |
|---|---|
| `authentication_jwt` | authentication and token handling |
| `idor` | object-level authorization |
| `sql_injection` | SQL injection candidates |
| `xss` | cross-site scripting candidates |
| `ssrf` | server-side request handling |
| `csrf` | cross-site request forgery |
| `xxe` | XML external entities |
| `rce` | remote code execution candidates |
| `business_logic` | workflow and entitlement rules |
| `race_conditions` | concurrent workflow behavior |
| `path_traversal` | path handling |
| `open_redirect` | redirect validation |
| `mass_assignment` | client-controlled object fields |
| `file_uploads` | upload handling |
| `information_disclosure` | exposed metadata and services |
| `subdomain_takeover` | dangling service references |

## How the agent behaves

The system prompt includes the system-loaded scope and fingerprint, a read-only digest of the
current run's memory, TDA/attack-tree state, tool schemas, and skill guidance. The root role may
only delegate or terminate; workers use a separate allowlist. Model output is schema-validated,
but the model and target-controlled output remain untrusted. Prompt instructions are not a
security boundary. A run may stop on a budget, exhausted tree, confirmed critical finding,
explicit termination, inference error, or policy violation.

| Spec | Backend | Notes |
|---|---|---|
| `ollama:qwen3:4b` | Ollama `/api/chat` | local JSON output; Qwen3 thinking is disabled for short structured decisions |
| `llamacpp:MODEL` | llama.cpp `/v1/chat/completions` | local OpenAI-compatible JSON endpoint |
| `replay:examples/decisions.json` | recorded decisions | no model, but delegated tools execute unless `--dry-run` is set |
| `--replay traces/latest.json` | trace replay | reports only; no model or target traffic |

## Development

```bash
python -m pip install -e ".[dev]"
ruff check .
black --check .
pytest
```

CI runs lint, formatting, coverage, a loopback lab smoke test, and a package-install check. The
tests include scope bypass regressions, run isolation, output/exit handling, local-model HTTP
transport, and real loopback TCP probing. External scanner tests use fixtures and mocked
subprocesses; they do not establish compatibility with arbitrary installed versions. See
[docs/readiness-audit.md](docs/readiness-audit.md) for the research and remaining limitations.

## Limitations

- This is beta software; manually verify all results and supervise every engagement.
- Network isolation, rate enforcement, data loss prevention, and scanner sandboxing are the
  operator's responsibility. Local inference does not mean all scanner activity is offline.
- Local model quality and available context affect planning; skill packs are not guarantees.
- There is no web UI, scheduler, multi-tenant server, or general chat interface.

## License

MIT — see [LICENSE](LICENSE). Security reporting: [SECURITY.md](SECURITY.md). Changes:
[CHANGELOG.md](CHANGELOG.md).
