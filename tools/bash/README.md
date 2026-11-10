# Bash toolkit

Three scripts for the "one command" first pass. They are wrappers around the Python package, not
a parallel implementation: scope checks, parsing, and findings all come from
`cyberpowerfull` itself.

| Script | What it does |
|---|---|
| `cve_hunt.sh` | resolve → native port scan → HTTP facts → component inventory → offline CVE correlation |
| `payload_run.sh` | generate proof payloads for one skill, then deliver exactly one with `http_probe` |
| `scan_cycle.sh` | the full first pass (hunt + optional payload plan) plus a Markdown summary |
| `lib/common.sh` | interpreter discovery, scope gate, JSON helpers, findings table |

## Requirements

- `bash` 4+
- a Python that can `import cyberpowerfull` — the scripts look for `./.venv/bin/python`, then
  `python3`, then `python`; override with `CPF_PYTHON=/path/to/python`
- no nmap, no nuclei, no model, no internet connection

## Mandatory scope

Every script requires `--scope scope.json` and exits `2` without it. Each target is re-checked by
the Python scope engine before any request, so a typo cannot fall outside the engagement.

```bash
tools/bash/cve_hunt.sh --target 127.0.0.1
# error: --scope scope.json is required (authorisation is mandatory)
```

## Usage

```bash
# offline CVE hunt with default common ports
tools/bash/cve_hunt.sh --scope scope.json --target 127.0.0.1

# explicit ports, import a feed first, hide low scores, machine-readable result
tools/bash/cve_hunt.sh --scope scope.json --target app.lab \
  --ports 22,80,443,8080 --import-feed nvd-2026.json --min-cvss 7 --json

# prefer nmap XML CPE data over banner guessing
tools/bash/cve_hunt.sh --scope scope.json --target app.lab --nmap-xml scan.xml

# dry-run a payload plan, then deliver it
tools/bash/payload_run.sh --scope scope.json --url http://127.0.0.1:8080/search --skill sqli --param id
tools/bash/payload_run.sh --scope scope.json --url http://127.0.0.1:8080/search --skill sqli --send

# the whole cycle plus summary.md
tools/bash/scan_cycle.sh --scope scope.json --target 127.0.0.1 --skill xss
```

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `CPF_PYTHON` | auto-detected | interpreter used for every Python call |
| `CPF_ARTIFACTS` | `artifacts` | root for run output (git-ignored) |
| `CPF_INTEL_STORE` | `intel/advisories.sqlite3` | advisory corpus used by the scripts |

## Output

`cve_hunt.sh` writes timestamped JSON next to each other:

```
artifacts/intel/<target>-<timestamp>.resolve.json
artifacts/intel/<target>-<timestamp>.ports.json
artifacts/intel/<target>-<timestamp>.http.json
artifacts/intel/<target>-<timestamp>.components.json
artifacts/intel/<target>-<timestamp>.findings.json
```

`payload_run.sh` writes the generated plan (`<skill>-<timestamp>.json`) and, with `--send`, one
`<payload-id>-<timestamp>.result.json`.

`scan_cycle.sh` writes everything above into `artifacts/cycle/<target>-<timestamp>/` plus
`summary.md` with ports, components, candidates, and the payload plan.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | completed, no candidates |
| `1` | completed, candidates found (also used by `cve_hunt.sh` to signal a hit) |
| `2` | usage error, missing scope, out-of-scope target, or missing feed |
| `4` | a target was rejected by the scope engine inside `native_scan` |
