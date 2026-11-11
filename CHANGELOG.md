# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Sn1per-style live console**: every run prints a banner (version, target, engagement,
  steps), one banner per step group, the exact command line of every dispatched tool
  (`[*] nmap: $ nmap -sV …`, `●` for in-process natives), live skips as they happen, and a
  `SCAN COMPLETE` banner — on stderr, so stdout stays machine-readable.
- **`cpf -v / --verbose`**: finished steps also print the tool's captured output excerpt.
  Secret-bearing argv values (`--header`, `--body`, `--cookie`, `--data`, `--password`,
  `--token`) always render as `***`, with or without `-v`.
- **Finding titles for every severity** on the done line (high/critical keep the `!!`
  alarm; medium/low/info print dimmed), plus shell-completion entries for the new flag.


### Fixed

- **`--doctor` names the fix for every missing scanner**: the readiness table's third column
  shows the install command (`apt install nmap`, …) instead of going blank.
- **Error hints match the actual problem**: a malformed target now says `fix the target`
  instead of pointing at the scope file; `--lab-port 9` says `not permitted (privileged
  port)` instead of `already in use`.
- **`--help` grouped like professional CLIs**: 7 sections (target, one-command, playbooks,
  agent loop, intel, output, setup) instead of one 195-line list; `-m` help and examples now
  list all 8 playbooks; `--max-steps` gains its missing help text; every flag is asserted to
  carry help text.

## [5.2.0] — Recon depth, code + cloud playbooks, guided first run

### Added

- **14 tool wrappers (43 total)**: `dnsx`, `tlsx`, `rustscan`, `uncover` (recon);
  `netexec` (SMB null/guest only), `metasploit` (allowlisted modules, `aggressive` only);
  `gitleaks`, `trufflehog`, `semgrep`, `trivy` (local code audit); `zap` (passive default,
  active needs `aggressive`); `kubebench`, `kubescape`, `prowler` (cloud posture, real OCSF).
  All parsers verified against upstream schemas and golden fixtures.
- **`code` playbook**: secrets + SAST + dependency audit of a local repo, contained to the new
  `scope.allowed_paths` (sibling paths blocked, fail-fast message points at `cpf --init`).
- **`cloud` playbook**: kube-bench CIS, kubescape posture, prowler provider audit; credentials
  stay in the environment, never in traces.
- **Nuclei DAST + KEV-first**: `kev_only` mode runs CISA-KEV templates before the broad pass;
  OAST callback support stays tri-state (off by default).
- **`cpf --init`**: guided 5-question setup (target → playbook → permissions → authorization →
  scope file) with a recorded-stdin test; `--examples` prints copy-paste recipes;
  `--completion` emits bash/zsh/fish scripts.
- **Plain-language findings**: every report finding carries a `what this means` line
  (`explain.py`, 27 rules); unknown playbooks get a did-you-mean suggestion; every error exit
  code prints the exact command that fixes it.
- **README rewritten easy-first**: 60-second quickstart, jobs table, contents, live counts
  (43 tools, 8 playbooks, 106 steps, 79 binaries, 1000+ tests).

### Changed

- Default token budget 24k → 32k (`RunConfig`, `BudgetState`, `$CYBERPOWERFULL_MAX_TOKENS`):
  the 43-tool catalogue no longer starves the end-to-end agent runs.

## [5.1.0] — Sn1per-style UX, self-update, verified agent integrations

### Added

- **`-t` and `-m`/`--mode` short flags**: `cpf example.com -m web` runs one area with the
  scope derived automatically; `-m` is an alias for `--playbook` and the profile keeps its
  budgets. `--playbook` with `cpf TARGET` used to be silently ignored — it now selects the
  plan, and an unknown mode fails with exit `8` before any attestation.
- **`cyberpowerfull --update`**: pulls the git checkout the running copy was installed from
  and reinstalls it, then exits without scanning. Refuses a dirty tree unless `--force` is
  given, explains a missing upstream branch, and never elevates itself (a system-wide install
  gets the exact `sudo` command that finishes the reinstall).

### Fixed

- **PentAGI rewritten against the real v2.2.0 API**: GraphQL `createFlow(modelProvider, input)`
  first, REST `POST /api/v1/flows/` second; polls `flow(flowId:)`; reads results from
  `tasks(flowId:)` (there is no `report` field and no `/report` route); `waiting` stops with
  instructions instead of hanging; HTTP 401 names the token/salt fix.
- **Sn1per modes verified against 9.2**: `discover` removed (needs a CIDR `HostInput` cannot
  express); `port`/`webporthttp`/`webporthttps` require `-p` up front (Sn1per exits 0 on the
  no-port no-op); a non-root run reports blocked with the fix instead of an empty result.
- **Strix 1.7.1**: a missing Docker CLI, missing `STRIX_LLM`, or a model-connection failure
  stops with the fix spelled out; report parsing covers the `./strix_runs/<run>/` layout.
- **Nuclei 3.11.1**: bulk size and max host errors are configurable (`-bs`, `-mhe`); web and
  API playbooks use focused template tags instead of the full sweep.
- **`--agents` availability now means runnable**: Strix needs its binary *and* Docker, PentAGI
  needs URL *and* token, Sn1per needs its binary *and* root.
- **`--ai` with `-m`/`--playbook` is now a usage error**: each path used to silently ignore
  one of the two.

### Docs

- `docs/INTEGRATIONS.md` corrected (PentAGI flow, Sn1per mode list, Strix report paths); the
  default `PENTAGI_URL` is now `http://127.0.0.1:8080` (upstream default port, TLS off).

## [5.0.1] — Missing-tool experience

Real-target runs on a bare host drowned the operator in missing-binary noise, and the
installer itself could fail entirely when a single package name was unknown. This patch
makes the gap obvious up front, condenses the noise, and hardens the installer.

### Fixed

- **Installer installs per package** (`scripts/install.sh`, `make tools`): one unknown
  package name (stock Debian lacks some Kali-only packages) no longer aborts the whole
  set — each failure is reported and the rest still install, with a summary at the end.
- **Installer now includes `metasploit-framework`**: the shipped Metasploit wrapper was
  never installable via the documented path (`msfconsole` stayed missing forever).
- **`--check` condenses missing tools** into one summary line plus the install command,
  instead of one `MISSING binary` line per tool.
- **One-command runs warn up front**: `cpf TARGET` prints scanner coverage
  (`note: 5/30 scanners ready; …`) to stderr before a long run instead of surprising
  the operator with skips at the end.
- **Test runner works on a plain install**: coverage flags moved out of
  `pyproject.toml` `addopts` (bare `pytest` failed with `unrecognized arguments`
  without the `dev` extra); the 70% gate is enforced by `make test` and CI.
- **`engagements/` is now git-ignored**: one-command scopes carry authorization
  claims and must never be committed.

## [5.0.0] — Built-in auto agent

No model download, no model server, no setup beyond the install: the default backend is now
a built-in Python agent that plans and runs the engagement itself, with a live progress
display in the foreground. The Ollama backend is removed; llama.cpp stays for operators who
want a local model in the loop. Guardrails did not move: authorization is still recorded
before anything runs, and inference endpoints are still loopback-only.

### Added

- **Built-in auto agent (`auto`, the default backend)**: a 19-step ladder with 7
  escalations, a run journal, and delegation to the existing worker agents. It needs no
  model, spends no tokens, and calls no external tools (`brain/agent.py`).
- **Live foreground display**: per-step progress with a spinner on TTYs and a plain
  `[01/12]` fallback otherwise (plus `NO_COLOR` support); `--json` keeps machine output
  on stdout and progress on stderr (`live.py`, `step_start` hooks in the orchestrator,
  playbook runner, and lab).
- **Result payloads with signal**: worker results carry the top finding titles and top
  severity so the live display and the trace show what matters, not just `ok`.

### Changed

- **Faster runs**: one-pass parallel groups raised to 4/8/12, playbook argument building
  and tool descriptions cached, identical duplicate invocations skipped.
- **testssl.sh wrapper rewritten** against the testssl.sh v3.2.5 source: protocols-only
  by default (`-p`), full run emits no check flag, `-t` is always a STARTTLS protocol
  pair, `--severity`/`--warnings batch`/`--quiet`/`--color 0` enforced, bounded connect
  and openssl timeouts, `WARN` maps to medium, telemetry severities skipped, and only
  exit `0` counts as success.
- **URL targets normalized**: `https://host:port/path` scopes the host while keeping the
  full URL for web builders; scheme-less `host/path` input no longer leaks a path into
  the scope.

### Removed

- **Ollama backend** (`OllamaClient`, `ollama:` specs, setup docs). Pointing `--llm` at an
  `ollama:` spec now fails with a migration error instead of silently doing something
  else. Use the default `auto` agent or `--llm llamacpp:model` with `llama-server`.

## [4.0.0] — One command

The first run is now one line: `cpf TARGET` (or `./run.sh TARGET` straight after cloning).
The target is the only required input; the scope file, the playbook choice, the budgets, and
the report are all derived from it, and everything the run did is explained back in plain
language. The guardrails did not move: the new mode writes an authorized scope only after an
explicit, recorded attestation, and it refuses to run — unchanged — without one.

### Added

- **One-command mode (`cpf TARGET`)**: the positional target is reduced to a scopeable host,
  an engagement scope is loaded or created under `engagements/`, a profile is run, and the
  result is printed as `RESULT` / `WHAT I FOUND` / `NEXT STEPS` in plain words. New module
  `src/cyberpowerfull/onepass.py`; no target and no explicit scope flag prints a quickstart
  and exits 2.
- **Profiles**: `--profile quick|standard|deep` pick a real playbook plus time/parallelism
  budgets (`recon`/10 min/2, `full`/30 min/3, `full`/2 h/4). `--polite` shrinks the footprint
  further; `--plan` prints what would run and sends nothing.
- **Recorded authorization**: `--i-am-authorized` (optionally `--authorization-ref REF`), or a
  typed `yes` at an interactive prompt that says exactly what permission is being claimed. The
  claim is stored in the scope's `authorization_ref` and `notes`; a non-interactive run without
  the flag fails closed with exit 3, and an existing scope is never widened (out-of-scope host
  is an error, not a merge).
- **`./run.sh`**: zero-setup wrapper for a fresh clone — creates `.venv`, installs the package
  editable, then runs `cpf`. `./run.sh TARGET`, `./run.sh --lab`, `./run.sh --doctor`.
- **SARIF 2.1.0 export**: every run writes `artifacts/findings-<run_id>.sarif` (one rule per
  skill/CVE/CWE, severity mapped to SARIF level, `verified` carried in rule properties,
  skipped steps as execution notifications).
- **Run manifest**: every run writes `artifacts/run-<run_id>.json` (`schema:
  cyberpowerfull.run/1`) with per-step status, tool status counts, budget, skip reasons,
  verified findings, and artifact paths.
- **`tests/test_onepass.py`** (48 tests): host reduction, profile mapping, scope creation that
  never happens without attestation and never widens an existing scope, `--plan` silence,
  CLI exit codes, SARIF/manifest shape, and the four-artefact dry run.

### Changed

- The end-of-run summary is a scannable `RESULT` block (target, engagement, ran/skipped
  counts, severity breakdown, verified count, trace/report/SARIF/manifest paths, up to six
  skip reasons) followed by findings and concrete next steps derived from the run itself.
- `write_reports()` now returns `{report, findings, sarif, run}` and writes all four files.
- `scripts/install.sh` and the README/GUIDE lead with the one-command path; the manual
  `--init-scope` → `--playbook` route is unchanged and still documented underneath.
- `docs/HANDOFF.md` documents the one-command layering and a new second invariant
  ("Attested, never assumed"); the suite is at 831 passed, 3 skipped, 87%.

### Fixed

- `pyproject.toml` carried a duplicate `description` key (a merge artefact) that broke
  `pip install -e .` with `TOMLDecodeError`; packaging now parses and installs cleanly.
- `docs/HANDOFF.md` and `docs/ROADMAP.md` version history now matches the real release
  sequence (3.2.0 offline intelligence, 3.3.0 repository maturity).

## [3.3.0] — Repository maturity

The code did not change much in this release; the repository around it did. A tool people cannot
audit, extend, or release cleanly is not a professional tool.

### Added

- **`docs/HANDOFF.md`** — the internal map: shipped history, module-by-module responsibilities,
  the nine invariants, what the tests actually prove (and what they do not), extension recipes,
  the gotchas that already cost time, known gaps, and the release checklist.
- **`docs/GUIDE.md`** — task-oriented user guide: install (three routes), first run, authorizing a
  real engagement, choosing a path, playbooks, the reasoning loop, capabilities, reading results,
  external agents, a troubleshooting table keyed on exit codes, and recipes.
- **`docs/ROADMAP.md`** — shipped versions plus the next three with acceptance tests, a research
  backlog, and an explicit out-of-scope list.
- **`docs/README.md`** — documentation index that links every document.
- **`AGENTS.md`** — entry point for AI coding agents: how to use the tool safely, how to change
  it, which invariants to preserve, and the testing facts that trip agents up.
- **`CONTRIBUTING.md`** — dev setup, standards table, extension recipes, test notes, commit style,
  release process.
- **Community files** — pull request template with a safety checklist, YAML issue forms (bug +
  feature) with a security-link redirect, and Dependabot for pip and actions.
- **`.github/workflows/release.yml`** — tag-triggered release: verifies the tag matches the package
  version, re-runs lint/tests with coverage, builds sdist + wheel, writes `SHA256SUMS`, and
  publishes a GitHub release with notes extracted from this changelog.
- **`.github/workflows/codeql.yml`** — CodeQL `security-and-quality` analysis on push, PR, and a
  weekly schedule.
- **`tests/test_repository.py`** — 76 tests that keep all of the above honest: required files,
  issue-form schema, workflow triggers and permissions, release job ordering, CodeQL wiring,
  broken relative links in every document, coverage of each user-facing command in the guide, the
  handoff module map versus the real source tree, heading anchors, and the roadmap sections.
- **`.editorconfig`** and **`.github/CODEOWNERS`** (guardrails and workflows owned explicitly).
- **`scripts/release_check.py`** plus `make docs` / `make release-check`, so version, changelog,
  README badge, and tag cannot drift apart.

### Changed

- README gains a documentation table, a CodeQL badge, a contributing section, and the new files in
  the repository layout.
- `Makefile` gains `make docs` (renders the doc index and verifies links) and `make release-check`
  (lint + tests + version/tag consistency).
- Version 3.2.0.

### Notes

- No behaviour change to the agent, the guardrails, or the artefacts. Everything in
  `docs/HANDOFF.md §4` still holds, and the tests that enforce it are unchanged.
- Numbering: 3.2.0 shipped offline intelligence upstream at the same time this documentation
  release was prepared, so the docs release is 3.3.0. It merged into `main` labelled 3.2.0; the
  heading here is the correct number.

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
