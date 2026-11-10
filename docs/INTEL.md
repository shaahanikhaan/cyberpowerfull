# Offline CVE intelligence

`cyberpowerfull` correlates the products and versions it actually observes against an advisory
corpus that lives on disk. The agent makes no network request for intelligence: you fetch a feed
once, import it, and the corpus is available to the CLI, the `cve_correlate` tool, and the bash
toolkit.

## Why a local corpus

- **No API key, no rate limits, no per-query cost.** An engagement works offline.
- **Auditable.** Every candidate can be traced back to a stored advisory, its range, and its
  source file.
- **Current.** The bundled snapshot is deliberately small and stable; importing today's NVD and
  KEV feeds brings in newly published CVEs (including 2025–2026 entries) the moment they exist.
- **Honest.** If the corpus has no matching advisory, no candidate is produced. The agent never
  synthesises a CVE.

## Corpus location and lifecycle

| Path | Purpose |
|---|---|
| `intel/advisories.sqlite3` | default corpus (git-ignored, rebuilt by import) |
| `src/cyberpowerfull/intel/data/bundled_advisories.json` | curated snapshot seeded into an empty corpus |
| `:memory:` | tests and one-shot queries |

Merge-on-import rules (`intel/store.py`):

| Field | Rule |
|---|---|
| severity | highest rank wins |
| CVSS | highest score wins (a later feed never lowers a known score) |
| ranges / references | unioned, detail never dropped |
| `kev`, `exploited_in_wild` | logical OR |
| title / vendor / product | first non-empty value wins |

Advisory identifiers are validated by family (`CVE`, `GHSA`, `RHSA`, `USN`, `DSA`, `MSRC`,
`ZDI`, `CNVD`, `BDU`); CVE identifiers must match `CVE-YYYY-NNNN…`. Malformed rows are counted as
import errors, not stored.

## Importing feeds

```bash
# NVD 2.0 API response (single page or merged pages), NVD 1.1 JSON, CISA KEV JSON, or native
cyberpowerfull --import-feed nvd-2026.json
cyberpowerfull --import-feed known_exploited_vulnerabilities.json --feed-format kev
cyberpowerfull --import-feed snapshot.json --intel-store /srv/intel/advisories.sqlite3

cyberpowerfull --intel-status            # total, KEV count, years, severities, distinct products
cyberpowerfull --intel-status --json
```

Fetch is out of scope for this tool by design — use `curl`, a browser, or your organisation's
mirror. Any locally produced file in one of the supported shapes works.

Format auto-detection looks for `CVE_Items` (NVD 1.1), `vulnerabilities[].cve` (NVD 2.0),
`vulnerabilities[].cveID` (KEV), and `advisories[]` (native).

## Correlation

```bash
cyberpowerfull --correlate 'log4j=2.14.1;openssh=9.6p1;apache httpd=2.4.49' --target 127.0.0.1
cyberpowerfull --correlate components.json --min-cvss 7 --json
```

`components.json` is either a list of component objects or an inventory produced by
`python -m cyberpowerfull.native_scan inventory …`:

```json
{
  "target": "127.0.0.1",
  "components": [
    {"product": "openssh", "version": "9.6p1", "port": 22, "source": "nmap", "confidence": 0.8}
  ]
}
```

Matching logic:

1. product aliases (`apache httpd` / `http_server`, `big-ip` / `big_ip`, `sshd` / `openssh`, …)
2. version-range membership (`introduced` inclusive, `fixed` exclusive, `last_affected` inclusive,
   `exact`)
3. confidence: base 0.40, +0.15 with an observed version, +0.15 for KEV, −0.10 for product-level
   advisories only, clamped to 0.15–0.80
4. severity is capped at `medium` when the component has no version, because the candidate cannot
   be confirmed

Every result is a `Finding` with `verified=False`, `tool="cve_correlate"`, and the rationale in
its evidence field. A candidate becomes a finding only through a template check, an
authenticated version comparison, or a payload proof.

## In the agent loop

`cve_correlate` is a native (binary-free) tool on the validation phase, so the reasoning agent
can call it directly:

```json
{"step": 7, "tool": "delegate", "args": {
  "worker": "validate", "tool": "cve_correlate",
  "args": {"target": "127.0.0.1",
           "components": [{"product": "log4j", "version": "2.14.1"}],
           "min_severity": "high"}}}
```

It reads the corpus from `--intel-store` (or `intel/advisories.sqlite3`), reports corpus
statistics, and returns candidate findings. `exploit_availability` and `network_services` skill
packs list it, so it is offered to the model when those skills are selected.

## Scripted first pass

```bash
tools/bash/cve_hunt.sh --scope scope.json --target 127.0.0.1 \
  --import-feed nvd-2026.json --min-cvss 7
```

The script resolves the target, runs a native TCP connect scan, probes each open port for HTTP
facts, builds a component inventory, correlates offline, writes five timestamped JSON artifacts,
and prints a severity-sorted table. Exit code is `1` when candidates exist, `0` when none do,
`2` on usage or scope errors.

## Tests

`tests/test_intel.py` covers version comparison, range membership, product aliases, store
merging, all four feed formats, malformed rows, correlation scoring, severity capping,
de-duplication, and seeding. `tests/test_native_tools.py` exercises the tool end-to-end
against a temporary corpus.
