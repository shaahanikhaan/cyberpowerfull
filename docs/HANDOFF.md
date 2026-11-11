# Handoff — state of the project for the next maintainer or agent

Read this before changing anything. It records what exists, what must not break, where things
live, what the tests actually prove, and what is deliberately unfinished. `README.md` is the
public description; this file is the internal map.

- **Version:** 5.0.1
- **Last known good:** `main` after the 5.0.1 merge, CI green on Python 3.10–3.12
- **Test suite:** 879 passed, 3 skipped, 84% line coverage (gate: 70%)
- **Audience note:** this repository is a pentest-only agent. It refuses to run without an
  authorized `scope.json`. One-command mode can *write* that file, but only after a typed
  attestation that is recorded in it. Do not "fix" that away.

---

## 1. What the project is, in one paragraph

A local-only autonomous penetration-testing agent with **two execution paths over one guarded
tool layer**: (a) an autonomous agent loop driven by the built-in auto agent (or an optional
loopback-only local model), and (b) eight deterministic playbooks that run the same typed tools
with no model at all. Both paths
are wrapped in a capability gate, per-call scope validation, an append-only SQLite memory, and a
structured trace → Markdown report / findings JSON pipeline. A live host inventory tells the agent
what the machine can actually run; nothing is bundled or simulated.

## 2. Shipped history

| Version | What landed | Where to look |
|---|---|---|
| 2.0.0 | Pentest-only hard fork: 3-layer brain, typed tools, append-only memory, scope gate, 16 skills | `CHANGELOG.md`, `docs/readiness-audit.md` |
| 2.1.0 | Readiness and safety hardening: run-isolated SQLite reads, strict scope/DNS checks, bounded subprocess output, loopback transport, truthful exit codes, owner-only artifacts | `CHANGELOG.md`, `tests/test_readiness_*.py` |
| 3.0.0 | 26 tools, capability model, 6 playbooks, live inventory, offline knowledge base, 29 skills, Strix/PentAGI/Sn1per adapters | `CHANGELOG.md`, `tests/test_playbook.py`, `tests/test_capabilities.py` |
| 3.1.0 | One-command first run: `--lab`, `--init-scope`, `make`, `scripts/install.sh`, `cpf` | `src/cyberpowerfull/lab.py`, `tests/test_lab.py` |
| 3.2.0 | Offline CVE intelligence: advisory corpus + importers, version ranger, correlator, proof-only payload engine (55 payloads / 14 skills), native `http_probe`, bash toolkit | `intel/`, `payloads/`, `tools/bash/`, `tests/test_intel.py` |
| 3.3.0 | Repository maturity: handoff/guide/roadmap docs, issue + PR templates, release and CodeQL workflows, doc-hygiene tests | `docs/`, `AGENTS.md`, `CONTRIBUTING.md`, `.github/`, `tests/test_repository.py` |
| 4.0.0 | One command: `cpf TARGET` / `./run.sh TARGET` derives the scope, attests authorization, picks a profile, runs, and explains the result; SARIF + run manifest artefacts | `onepass.py`, `run.sh`, `tests/test_onepass.py`, `reporting.py` |
| 5.0.0 | Built-in auto agent (default backend, Ollama removed), live foreground display, faster parallel runs, testssl.sh wrapper rewritten against v3.2.5 | `brain/agent.py`, `live.py`, `brain/llm.py`, `tools/testssl.py`, `tests/test_agent.py`, `tests/test_live.py`, `tests/test_testssl_wrapper.py` |
| 5.0.1 | Missing-tool experience: per-package installer (+`metasploit-framework`), condensed `--check`, pre-run coverage note, plain-install `pytest`, `engagements/` ignored | `scripts/install.sh`, `Makefile`, `cli.py`, `pyproject.toml`, `.gitignore`, `tests/test_cli.py`, `tests/test_lab.py` |
| 5.1.0 | Sn1per-style UX (`-t`/`-m`), `--update` self-update, PentAGI v2.2.0 rewrite, verified Strix/Sn1per/Nuclei integrations | `selfupdate.py`, `cli.py`, `tools/pentagi.py`, `tools/strix.py`, `tools/sn1per.py`, `tools/nuclei.py`, `playbook.py`, `inventory.py`, `docs/INTEGRATIONS.md`, `tests/test_selfupdate.py` |

## 3. Module map (what lives where, and why)

```
src/cyberpowerfull/
├── cli.py            argparse + every handler. Dispatch order matters (see §7).
├── onepass.py        ONE-COMMAND MODE: target -> host, attestation -> scope file, profile ->
│                     playbook/budget, plain-language plan, progress lines, next steps.
│                     Pure helpers (target_host, ensure_scope, render_plan, next_steps) are
│                     tested without touching the network.
├── lab.py            real loopback http.server + playbook run (the "first run" path)
├── selfupdate.py     --update: git pull --ff-only + pip reinstall;
│                     refuses a dirty tree without --force, never sudoes
├── scope.py          scope.json model, capability parsing, host matching, fingerprint,
│                     bootstrap_scope()/write_scope() for --init-scope
├── models.py         Phase, Capability, Severity, Finding, Decision, BudgetState
├── config.py         RunConfig, ModelConfig, ToolPolicy (env sanitation, output caps)
├── inventory.py      live probe: 79 catalogued binaries, aliases, versions, wordlists,
│                     nuclei templates, NSE, Exploit-DB, Docker/agent detection, install hints
├── knowledge.py      read-only readers over the local Kali libraries
├── playbook.py       6 deterministic playbooks, Facts, PlaybookRunner, COMMON_TCP_PORTS
├── trace.py          Trace/StepRecord (schema 1.0). `skipped` is additive: list of reasons
├── reporting.py      render_markdown() (playbook-aware methodology, skipped-step section),
│                     render_sarif() (SARIF 2.1.0), render_run_json() (run manifest),
│                     write_reports() -> report/findings/sarif/run artefacts for one run
├── native_scan.py    in-process scanning helpers used by the native tools
├── storage.py        owner-only atomic writes for artefacts
├── templating.py     Jinja2 environment used by prompt and skill rendering
├── brain/
│   ├── system_prompt.jinja   14 sections, StrictUndefined
│   ├── prompt.py             PromptContext + renderers (skill_limit applies here)
│   ├── llm.py                auto agent (default); llama.cpp / replay backends; loopback assert
│   ├── agent.py              AutoAgent: ladder + escalations + journal, no tokens
│   ├── tda.py                four-dimension difficulty assessment
│   ├── attack_tree.py        EGATS scoring and pruning
│   └── orchestrator.py       RootAgent (delegate|terminate) + WorkerAgent (guarded execute)
├── live.py               LiveDisplay: spinner TTY / plain fallback, stderr only
├── tools/
│   ├── base.py               BaseTool: validate -> build_argv -> apply_policy -> run -> parse
│   ├── registry.py           29 tools, allowlists per worker, external agent catalogue
│   ├── extract.py            shared report/JSON finding extractors
│   ├── http_probe.py         native single-request probe (no binary needed)
│   ├── payload.py            proof-only payload builder (catalogue lives in payloads/)
│   ├── cve_correlate.py      component -> advisory correlation tool
│   └── <26 more wrappers>.py
├── intel/            offline advisory corpus: store.py (SQLite, merge-on-import),
│                     importer.py (NVD 2.0/1.1, KEV, native), versioning.py (tokeniser/ranger),
│                     correlator.py, service.py (DEFAULT_INTEL_PATH), models.py, data/
├── payloads/         library.py (55 proof-only templates / 14 skills), engine.py, models.py
├── memory/store.py   append-only SQLite; UPDATE/DELETE trigged; MemoryView for the model
└── skills/packs/     29 Markdown/Jinja skill packs

tools/bash/           cve_hunt.sh, payload_run.sh, scan_cycle.sh + lib/common.sh — same scope
                      engine, usable without Python
run.sh                zero-setup wrapper: creates .venv, installs, then runs cpf
scripts/install.sh    explicit setup (+ --with-tools apt install), never edits a scope
scripts/release_check.py  version / changelog / badge consistency (make release-check)
```

Documentation set: `README.md` (public, tested by `tests/test_docs.py`), `docs/GUIDE.md` (user
guide; §0 is one-command mode), `docs/KALI.md` (host layout), `docs/INTEGRATIONS.md`
(Strix/PentAGI/Sn1per), `docs/INTEL.md` (offline corpus), `docs/PAYLOADS.md` (proof vectors),
`docs/ROADMAP.md` (next versions), `docs/readiness-audit.md` (2.0-era audit with a v3 note),
`AGENTS.md` (agent-facing quick map), `CONTRIBUTING.md` (dev workflow).

### One-command mode (`cpf TARGET`) — how it is built

`cli._one_pass()` is the only caller of `onepass.py`; keep the layering that way.

1. `target_host()` reduces a URL/`host:port`/path to the host the scope engine can match.
2. `ensure_scope()` loads an existing scope (and refuses to widen it) or writes a new one after
   the `attest` callback returns True. The CLI's callback is `--i-am-authorized` or a typed `yes`
   at a TTY; a non-TTY without the flag fails closed with exit 3.
3. `profile_for()` maps `--profile {quick,standard,deep}` to a real playbook plus budgets.
   `-m`/`--mode` overrides the playbook (budgets stay on the profile); an unknown mode fails
   with exit 8 before any attestation.
4. `PlaybookRunner` executes it exactly as `--playbook` would: same policy, same worker
   allowlists, same skip accounting.
5. `write_reports()` writes report + findings JSON + SARIF + run manifest; `next_steps()` turns
   the actual skips and findings into the closing advice.

It is deliberately not a new execution engine. If you change guardrails, they still only live in
`scope.py`, `tools/base.py` and `brain/orchestrator.py`.

## 4. Invariants (do not break these)

1. **No scope, no run.** Missing/invalid/unauthorized/expired `scope.json` → exit 3, before any
   tool. No force flag, no `--force`, no unauthenticated bypass.
2. **Attested, never assumed.** One-command mode may *create* a scope only from an explicit
   attestation (`--i-am-authorized`, or a typed `yes` on a TTY); the claim is recorded in
   `authorization_ref` and in `notes`. Non-interactive without the flag fails closed (exit 3), and
   an existing scope is never widened — an out-of-scope host is an error, not a merge.
3. **Per-call scope re-validation.** `WorkerAgent.execute()` re-checks the target (and the
   canonical validated target) for every delegation → exit 4 when the CLI target is outside.
4. **Capability gate before argv.** `masscan`, `naabu` need `aggressive`; `hydra` needs
   `credential_testing`; `strix`, `pentagi`, `sn1per` need `external_agents`. Unknown/absent
   capability ⇒ `ToolStatus.BLOCKED`, never executed.
5. **Loopback-only inference.** `assert_local_endpoint()`; no API-key code path. An endpoint
   passed as a model id (`llamacpp:http://…`) is rejected with an actionable message.
6. **Append-only memory.** SQLite triggers reject UPDATE/DELETE; the model only sees
   `MemoryView`.
7. **No shell.** argv lists only, `shell=False`, sanitized env, spooled bounded output.
8. **Proof-only exploitation.** No persistence, lateral movement, data extraction, or DoS;
   `searchsploit` reports availability only; hydra credentials are redacted.
9. **Offline intelligence.** The corpus is local; feeds are operator-supplied files and the
   agent never fetches one. A correlation is a *candidate*: `verified=False` until local evidence
   confirms it, and the score is a confidence, never a verdict.
10. **Honest reporting.** Skipped/failed work is disclosed (`trace.skipped`, report
   `## Skipped steps`); no fabricated findings, paths, or inventories.
11. **Exit-code contract.** 0 ok, 1 fatal, 2 usage, 3 scope, 4 out-of-scope, 5 inference, 6
   tool/knowledge failure, 7 policy violation, 8 unknown playbook. Failed runs still write
   artifacts and then exit non-zero.

## 5. What the tests actually prove (and what they do not)

- **Proven:** argv construction, parsing of realistic tool output, error paths, scope/capability
  behaviour, playbook scheduling/adaptivity, report rendering, CLI contract, exit codes, real
  loopback sockets (`tcp_probe`, lab server), mocked HTTP for PentAGI, provider-free replay.
- **Not proven:** live behaviour of the 22 third-party binaries (this sandbox has none) and the
  real Strix/PentAGI/Sn1per services. The README status column says so; keep it honest.
- **Where regressions hide:** `tests/test_tools_extended.py` mocks `subprocess.run` by writing
  into the spooled stdout/stderr handles — a mock that only sets `return_value.stdout` looks like
  an empty result. `tests/test_readiness_*.py` encode the hardened scope/DNS/storage behaviour.
- **One-command mode:** `tests/test_onepass.py` proves the scope is created only after
  attestation, never widened when it already exists, that `--plan` sends nothing, and that a dry
  run writes all four artefacts. The interactive prompt itself is the thin part: only the
  callback wiring is unit-tested, because it needs a TTY.
- **SARIF/manifest:** shape, rule ids (CVE → CWE → title slug), severity→level mapping, and
  `properties.verified` are asserted; nothing here has been validated against GitHub's uploader.
- **Coverage gate:** 70% is enforced by `make test` and CI (plain `pytest` runs without the coverage plugin); the suite sits at ~84%.

## 6. Recipes: how to extend the project

- **New tool:** `src/cyberpowerfull/tools/<name>.py` with a Pydantic `input_model` (extra="forbid"),
  `build_argv()` returning a list, `parse()` returning `Finding`s, optional `required_capability`
  and `binary_alternatives`; register in `tools/registry.py`; add to the right worker allowlist;
  add a fixture-based test in `tests/test_tools_extended.py`; add a row to the README tool table
  (the docs test asserts every registered tool appears there).
- **New playbook:** add `PlaybookStep`s in `playbook.py` with a facts-derivation function
  returning `None` when the precondition is absent, then add it to `PLAYBOOKS`. Steps that cannot
  run must be skipped with a reason, never stubbed.
- **New skill pack:** add `skills/packs/<name>.md.jinja` and register it in `skills/__init__.py`
  with phase/category/tools. The prompt carries at most 8 packs per step (`skill_limit`); keep it
  that way or a 32k model loses coherence.
- **New CLI flag:** parse in `build_parser()`, handle in `main()` in the existing dispatch order,
  document in `README.md` and `docs/GUIDE.md`, cover in `tests/test_cli.py` or `tests/test_lab.py`.
- **New doc:** link it from `README.md` *and* `docs/README.md`; `tests/test_repository.py` checks
  that relative links resolve.

## 7. Gotchas that already cost time

- **SQLite is thread-bound.** Never touch `MemoryStore` from worker threads; do cache lookups and
  recording on the scheduler thread (`playbook.py` does this).
- **dispatch order in `main()`** is load-bearing: update → listings → toolchain → knowledge/intel →
  init-scope → one-pass → doctor → lab → playbook → replay → check → render-prompt → run.
  `--ai` with `-m`/`--playbook` is a usage error: each path used to silently ignore one of them.
- **`--lab` implies target `127.0.0.1`** and needs it inside the scope; it never invents one.
- **masscan** prints banners before JSON: use `_first_json_array()` (`raw_decode`), not a regex.
- **JSON reports** (PentAGI, nuclei) must go through record extractors, not prose extraction.
- **`ffuf`/`nuclei` file policy:** operator allowlists *or* files inside the local wordlist /
  nuclei-template libraries. Arbitrary host paths stay blocked; do not "simplify" this to a bare
  `isfile()` check.
- **`python3 -m venv .venv` is required** in fresh sandboxes (system Python is PEP 668 managed and
  may lack pydantic). `.venv/` is not committed.
- **CI runs on a bare runner:** no nmap/nuclei/ffuf, so every playbook assertion must tolerate
  skips. CI proves port evidence on 8080 plus skip disclosure.

## 8. Known gaps / honest limits

- Parsers track current upstream output formats; no version matrix is pinned or tested against
  real binaries.
- Playbooks do not reason: they follow a fixed plan with fact-driven arguments.
- Findings are evidence-linked, not impact-proven; a `low` finding is a supported hypothesis.
- External agents bring their own model budget and provider; their output is a hypothesis until
  local evidence backs it.
- No SARIF export, no resume-after-failure, no scheduling/server mode, no Web UI (by design).
- `docs/readiness-audit.md` predates v3; re-verify claims per engagement.

## 9. Where to start next

See `docs/ROADMAP.md`. The short version: (1) a parser conformance matrix against real tool
versions, (2) SARIF + `run.json` artefacts so CI and dashboards can consume runs, (3) resumable
playbooks, (4) signed releases and a container image, (5) live validation of the external-agent
adapters against real Strix/PentAGI instances.

## 10. Release checklist

1. `make lint && make test && make docs` (ruff, black, 70% coverage gate, doc hygiene) and
   `make release-check` (version/changelog/badge consistency) — all must be clean.
2. Update `CHANGELOG.md` (Keep a Changelog sections), bump `pyproject.toml` + `__init__.py`.
3. Update the README badge and any count that changed (tools/skills/tests); `tests/test_docs.py`
   fails if the badge is stale.
4. Run `make lab` and `--init-scope` once; both are user-facing contracts.
5. Tag `vX.Y.Z`; `.github/workflows/release.yml` builds sdist+wheel, runs the suite, and publishes
   a GitHub release with the artefacts.
