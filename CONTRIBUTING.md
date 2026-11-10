# Contributing

Thanks for considering a change. This project is a pentest tool: correctness and honesty about
what the agent did matter more than feature count.

## Ground rules

- Read [docs/HANDOFF.md §4](docs/HANDOFF.md#4-invariants-do-not-break-these).
  The ten invariants are not negotiable; a PR that weakens one will be closed.
- No simulated behaviour. If a capability is unavailable (missing binary, missing capability,
  missing knowledge source), report it and skip — never fake a result, a fixture, or a finding.
- One concern per PR. A new tool, a new playbook, and a refactor are three PRs.
- Test the failure path, not only the happy path. Exit codes are part of the contract.

## Setup

```bash
git clone https://github.com/shaahanikhaan/cyberpowerfull && cd cyberpowerfull
make setup          # venv + editable install with dev deps
make lab            # prove the runtime path works before changing it
make lint && make test
```

Python 3.10, 3.11 and 3.12 are supported (CI matrix). System Python on Debian/Kali is PEP 668
managed — always work inside `.venv/`.

## Standards

| Area | Rule |
|---|---|
| Formatting | `black` (line length 100), `ruff check` clean; `make fmt`, `make lint` |
| Typing | full annotations on new public functions; `from __future__ import annotations` |
| Errors | raise the project's error types (`ScopeError`, `InvalidToolArguments`, `LLMError`, …) so the CLI maps them to documented exit codes |
| Subprocess | argv lists only, `shell=False`, sanitized env, bounded output — never `shell=True` |
| Files | artefacts go through `storage.write_private_text` (owner-only) |
| Logging | nothing on stdout except the documented CLI output; progress goes to stderr |
| Tests | `pytest`; coverage gate 70% in `pyproject.toml`, currently ~87% (788 tests) |

## Adding things

Recipes with exact file lists live in [docs/HANDOFF.md §6](docs/HANDOFF.md#6-recipes-how-to-extend-the-project).
The short version:

- **Tool wrapper** — `src/cyberpowerfull/tools/<name>.py` (Pydantic input model with
  `extra="forbid"`, `build_argv()`, `parse()`, optional `required_capability` /
  `binary_alternatives`), register in `tools/registry.py`, allowlist it for a worker in
  `brain/orchestrator.py`, add fixture tests, add a README table row. `tests/test_docs.py` fails
  if the README row is missing.
- **Playbook** — steps in `playbook.py` with a facts-derivation function that returns `None` when
  its precondition is absent; register in `PLAYBOOKS`; cover adaptivity in `tests/test_playbook.py`.
- **Skill pack** — `skills/packs/<name>.md.jinja` plus a registration entry; keep the per-step
  budget at eight packs.
- **Doc** — link it from `README.md` and `docs/README.md`; `tests/test_repository.py` checks that
  relative links resolve.

## Tests

```bash
make test                          # everything, with the coverage gate
.venv/bin/python -m pytest tests/test_playbook.py -q --no-cov
.venv/bin/python -m pytest -k "lab and not slow" -q --no-cov
```

Notes that save time:

- Mocked `subprocess.run` must write into the spooled stdout/stderr handles (see
  `tests/test_tools_extended.py::_run_with`); setting only `return_value.stdout` yields "no output".
- `MemoryStore` is thread-bound: never touch it from a playbook worker thread.
- CI has no scanner binaries, so playbook tests must assert on skips as well as findings.

## Commits and PRs

- Conventional-ish subject lines: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`.
- Explain *why* in the body, and state which invariant the change touches (or "none").
- Update `CHANGELOG.md` under the right Keep-a-Changelog heading.
- Fill in the pull request template; a PR without a test or a stated manual verification is a
  draft.
- Never commit engagement artefacts (`artifacts/`, `traces/`, `*.sqlite3`), credentials, or scope
  files from a real client.

## Releases

Maintainers follow the checklist in [docs/HANDOFF.md §10](docs/HANDOFF.md#10-release-checklist);
`make release-check` enforces the mechanical part (version, changelog heading, README badge).
Tags (`vX.Y.Z`) trigger `.github/workflows/release.yml`, which builds the sdist/wheel, runs the
suite, and publishes a GitHub release.
