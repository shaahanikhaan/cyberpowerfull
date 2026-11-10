# Handoff — state of the project for the next maintainer or agent

Read this before changing anything. It records what exists, what must not break, where things
live, what the tests actually prove, and what is deliberately unfinished. `README.md` is the
public description; this file is the internal map.

- **Version:** 3.3.0
- **Last known good:** `main` after the 3.2.0 merge, CI green on Python 3.10–3.12
- **Test suite:** 788 passed, 3 skipped, 87% line coverage (gate: 70%)
- **Audience note:** this repository is a pentest-only agent. It refuses to run without an
  authorized `scope.json`. Do not "fix" that away.

---

## 1. What the project is, in one paragraph

A local-only autonomous penetration-testing agent with **two execution paths over one guarded
tool layer**: (a) a model-driven reasoning loop (TDA + EGATS, loopback-only inference), and
(b) six deterministic playbooks that run the same typed tools with no model at all. Both paths
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
| 3.2.0 | Offline CVE intelligence, proof-only payloads, native HTTP probe, bash toolkit | `src/cyberpowerfull/intel/`, `payloads/`, `tools/http_probe.py`, `tools/payload.py`, `tools/cve_correlate.py`, `tools/bash/` |
| 3.3.0 | Repository maturity: handoff/guide/roadmap docs, issue + PR templates, release and CodeQL workflows, doc + link + anchor hygiene tests | `docs/`, `AGENTS.md`, `CONTRIBUTING.md`, `.github/`, `tests/test_repository.py` |

## 3. Module map (what lives where, and why)

```
src/cyberpowerfull/
├── cli.py            argparse + every handler. Dispatch order matters (see §7).
├── lab.py            real loopback http.server + playbook run (the "first run" path)
├── scope.py          scope.json model, capability parsing, host matching, fingerprint,
│                     bootstrap_scope()/write_scope() for --init-scope
├── models.py         Phase, Capability, Severity, Finding, Decision, BudgetState
├── config.py         RunConfig, ModelConfig, ToolPolicy (env sanitation, output caps)
├── inventory.py      live probe: 68 catalogued binaries, aliases, versions, wordlists,
│                     nuclei templates, NSE, Exploit-DB, Docker/agent detection, install hints
├── knowledge.py      read-only readers over the local Kali libraries
├── intel/            offline advisory corpus: SQLite store (merge-on-import), NVD/KEV
│                     importers, dependency-free version ranger, correlator, curated snapshot
├── payloads/         proof-only payload catalogue (55 entries, 14 skills) + request builder;
│                     destructive templates refused before a request exists
├── playbook.py       6 deterministic playbooks, Facts, PlaybookRunner, COMMON_TCP_PORTS
├── trace.py          Trace/StepRecord (schema 1.0). `skipped` is additive: list of reasons
├── reporting.py      render_markdown() (playbook-aware methodology, skipped-step section),
│                     write_reports() -> report-<run_id>.md + findings-<run_id>.json
├── storage.py        owner-only atomic writes for artefacts
├── templating.py     Jinja2 environment used by prompt and skill rendering
├── brain/
│   ├── system_prompt.jinja   14 sections, StrictUndefined
│   ├── prompt.py             PromptContext + renderers (skill_limit applies here)
│   ├── llm.py                Ollama / llama.cpp / replay clients; loopback-only assert
│   ├── tda.py                four-dimension difficulty assessment
│   ├── attack_tree.py        EGATS scoring and pruning
│   └── orchestrator.py       RootAgent (delegate|terminate) + WorkerAgent (guarded execute)
├── tools/
│   ├── base.py               BaseTool: validate -> build_argv -> apply_policy -> run -> parse
│   ├── registry.py           26 tools, allowlists per worker, external agent catalogue
│   ├── extract.py            shared report/JSON finding extractors
│   └── <26 wrappers>.py
├── memory/store.py   append-only SQLite; UPDATE/DELETE trigged; MemoryView for the model
└── skills/packs/     29 Markdown/Jinja skill packs
```

Also at the repository root: `tools/bash/` (three shell entry points that call the Python scope
engine: `cve_hunt.sh`, `payload_run.sh`, `scan_cycle.sh`) and `scripts/` (`install.sh`,
`release_check.py`).

Documentation set: `README.md` (public, tested by `tests/test_docs.py`), `docs/GUIDE.md` (user
guide), `docs/KALI.md` (host layout), `docs/INTEGRATIONS.md` (Strix/PentAGI/Sn1per),
`docs/ROADMAP.md` (next versions), `docs/readiness-audit.md` (2.0-era audit with a v3 note),
`AGENTS.md` (agent-facing quick map), `CONTRIBUTING.md` (dev workflow), `docs/README.md` (index).
`tests/test_repository.py` enforces required files, links, anchors, workflow wiring, and the
coverage of each user-facing command in the guide.

## 4. Invariants (do not break these)

1. **No scope, no run.** Missing/invalid/unauthorized/expired `scope.json` → exit 3, before any
   tool. No force flag, no interactive bypass.
2. **Per-call scope re-validation.** `WorkerAgent.execute()` re-checks the target (and the
   canonical validated target) for every delegation → exit 4 when the CLI target is outside.
3. **Capability gate before argv.** `masscan`, `naabu` need `aggressive`; `hydra` needs
   `credential_testing`; `strix`, `pentagi`, `sn1per` need `external_agents`. Unknown/absent
   capability ⇒ `ToolStatus.BLOCKED`, never executed.
4. **Loopback-only inference.** `assert_local_endpoint()`; no API-key code path. An endpoint
   passed as a model id (`ollama:http://…`) is rejected with an actionable message.
5. **Append-only memory.** SQLite triggers reject UPDATE/DELETE; the model only sees
   `MemoryView`.
6. **No shell.** argv lists only, `shell=False`, sanitized env, spooled bounded output.
7. **Proof-only exploitation.** No persistence, lateral movement, data extraction, or DoS;
   `searchsploit` reports availability only; hydra credentials are redacted; the payload catalogue
   refuses destructive templates and every payload proves a signal (arithmetic, timing,
   reflection, entity expansion, trust-flag change) rather than taking an action.
8. **Offline intelligence.** The advisory corpus is a local SQLite file the operator fills by
   importing feeds they fetched. The agent never calls a feed URL; absent data yields no
   candidate, and every correlation stays `verified=False` until local evidence confirms it.
9. **Honest reporting.** Skipped/failed work is disclosed (`trace.skipped`, report
   `## Skipped steps`); no fabricated findings, paths, or inventories.
10. **Exit-code contract.** 0 ok, 1 fatal, 2 usage, 3 scope, 4 out-of-scope, 5 inference, 6
   tool/knowledge failure, 7 policy violation, 8 unknown playbook. Failed runs still write
   artifacts and then exit non-zero.

## 5. What the tests actually prove (and what they do not)

- **Proven:** argv construction, parsing of realistic tool output, error paths, scope/capability
  behaviour, playbook scheduling/adaptivity, report rendering, CLI contract, exit codes, real
  loopback sockets (`tcp_probe`, `http_probe`, lab server), CVE version-ranger and merge semantics,
  payload catalogue auditing, mocked HTTP for PentAGI, provider-free replay.
- **Not proven:** live behaviour of the 22 third-party binaries (this sandbox has none) and the
  real Strix/PentAGI/Sn1per services. The README status column says so; keep it honest.
- **Where regressions hide:** `tests/test_tools_extended.py` mocks `subprocess.run` by writing
  into the spooled stdout/stderr handles — a mock that only sets `return_value.stdout` looks like
  an empty result. `tests/test_readiness_*.py` encode the hardened scope/DNS/storage behaviour.
- **Coverage gate:** 70% is configured in `pyproject.toml` `addopts`; the suite sits at ~88%.

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
  The guide test asserts that each user-facing flag appears there, so a flag without docs fails CI.
- **Advisory/feed work:** importers live in `intel/importer.py`, the merge semantics in
  `intel/store.py`, version comparison in `intel/versioning.py`. Add a feed format with a fixture
  and an error-accounting test; never let a new importer abort the whole import.
- **Payload work:** `payloads/library.py` is audited for destructive templates on generation
  (`payloads/engine.py`); a new entry must state the signal it proves and must be refused if it
  would modify state.
- **New doc:** link it from `README.md` *and* `docs/README.md`; `tests/test_repository.py` checks
  that relative links resolve.

## 7. Gotchas that already cost time

- **SQLite is thread-bound.** Never touch `MemoryStore` from worker threads; do cache lookups and
  recording on the scheduler thread (`playbook.py` does this).
- **dispatch order in `main()`** is load-bearing: listings → toolchain → knowledge → init-scope →
  doctor → lab → playbook → replay → check → render-prompt → run.
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
