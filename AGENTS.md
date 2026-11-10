# AGENTS.md — guide for AI coding agents

This repository is a **local-only autonomous penetration-testing agent**. Two kinds of agents
touch it: agents that *use* it to run an authorized assessment, and agents that *change* the code.
Both start here.

- Internal map, invariants, gotchas, and the release checklist: **[docs/HANDOFF.md](docs/HANDOFF.md)**
- What is planned next: **[docs/ROADMAP.md](docs/ROADMAP.md)**
- User-facing guide: **[docs/GUIDE.md](docs/GUIDE.md)**
- Dev workflow and standards: **[CONTRIBUTING.md](CONTRIBUTING.md)**

## Using it (do not skip the scope step)

```bash
make setup && make lab        # real loopback service + real playbook run, no model needed
make doctor                   # what this host can actually run
make toolchain                # live inventory with install hints
```

Offline intelligence (no network call by the agent; you import feeds you fetched):

```bash
cyberpowerfull --import-feed nvd-2026.json
cyberpowerfull --intel-status
cyberpowerfull --correlate 'openssh=9.6p1' --target 127.0.0.1
cyberpowerfull --payload xss --target 'http://127.0.0.1:8080/search'
```

For a real engagement, a scope file is mandatory — the agent exits `3` without one:

```bash
cyberpowerfull --init-scope scope.json --engagement NAME --targets HOST \
    --authorize --authorization-ref "SOW-XXXX"

cyberpowerfull --scope scope.json --target HOST --playbook recon     # no model
cyberpowerfull --scope scope.json --target HOST --llm ollama:qwen3:4b # model loop
```

Rules for using it:

1. Never run against assets you are not contractually authorized to test.
2. Do not grant capabilities (`aggressive`, `credential_testing`, `external_agents`) unless the
   engagement allows them.
3. Read the report, not just the exit code: skipped steps are listed with their real reason.
4. Treat `artifacts/`, `traces/`, and `*.sqlite3` as engagement-confidential; they are gitignored.

## Changing it

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
make lint        # ruff + black --check
make docs        # doc links, required files, templates
make release-check  # version + changelog + badge + tag consistency
make test        # 788 tests, 70% coverage gate (currently ~87%)
```

Ten invariants must survive any change: no-scope-no-run, per-call scope re-validation, capability
gate before argv, loopback-only inference, append-only memory, no shell, proof-only exploitation,
honest reporting of skips/failures, and the exit-code contract. They are spelled out in
[docs/HANDOFF.md §4](docs/HANDOFF.md#4-invariants-do-not-break-these).

Recipes for adding a tool, playbook, skill pack, CLI flag, or doc are in
[docs/HANDOFF.md §6](docs/HANDOFF.md#6-recipes-how-to-extend-the-project). A new tool needs a
Pydantic input model, an argv list, a parser, a registry entry, a worker allowlist entry, a test,
and a README table row — the docs test fails if the README row is missing.

Testing facts that trip agents up:

- Subprocess mocks must write into the spooled stdout/stderr handles (`tests/test_tools_extended.py`).
- `MemoryStore` is thread-bound; never call it from a playbook worker thread.
- CI has no scanner binaries: playbook assertions must tolerate real skips.
- Exit codes are tested; add a test for any new failure mode instead of returning `1`.

## Reporting problems

Security defects in this software go through private reporting (`SECURITY.md`), not public issues.
Bugs in third-party tools (nmap, nuclei, sqlmap, …) belong upstream.
