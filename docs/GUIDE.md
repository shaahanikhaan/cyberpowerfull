# User guide

Everything needed to run an authorized assessment with `cyberpowerfull`, in the order you will
need it. If you only have two minutes, run:

```bash
make setup && make lab
```

and read `artifacts/report-*.md`. That lab is a **real** loopback HTTP service scanned by a
**real** playbook — no model, no scanner binaries, no demo data.

- [1. Install](#1-install)
- [2. First run: the lab](#2-first-run-the-lab)
- [3. Authorize a real engagement](#3-authorize-a-real-engagement)
- [4. Choose an execution path](#4-choose-an-execution-path)
- [5. Playbooks in practice](#5-playbooks-in-practice)
- [6. The reasoning loop (local model)](#6-the-reasoning-loop-local-model)
- [7. Tools, capabilities, and packets](#7-tools-capabilities-and-packets)
- [8. Reading the results](#8-reading-the-results)
- [9. External agents (Strix, PentAGI, Sn1per)](#9-external-agents-strix-pentagi-sn1per)
- [10. Troubleshooting](#10-troubleshooting)
- [11. Recipes](#11-recipes)
- [12. FAQ](#12-faq)

---

## 1. Install

Three supported routes. All need Python 3.10+; nothing else is mandatory.

```bash
# A. repository (recommended for an engagement host)
git clone https://github.com/shaahanikhaan/cyberpowerfull && cd cyberpowerfull
make setup                 # venv + editable install + version check
# or: ./scripts/install.sh  (same, plus optional --with-tools)

# B. isolated CLI
pipx install "git+https://github.com/shaahanikhaan/cyberpowerfull"
cpf --version

# C. plain pip in a venv you manage yourself
python3 -m venv .venv && .venv/bin/pip install "git+https://github.com/shaahanikhaan/cyberpowerfull"
```

Add the scanner set on Debian/Kali (prompts for sudo, review the list first):

```bash
make tools        # or ./scripts/install.sh --with-tools
```

`cyberpowerfull` and `cpf` are the same program.

## 2. First run: the lab

```bash
make lab            # or: cyberpowerfull --lab
```

What happens, in order:

1. a free port is chosen from `8080, 8443, 9200, 27017, 6379, 5900, 8008` (verified free — a busy
   port is an error, never a silent no-op);
2. a real `http.server` listener starts on `127.0.0.1:<port>` serving a fixed page and `/health`;
3. the `network` playbook runs against `127.0.0.1` through the normal worker guardrails;
4. the trace and report are written, then the listener is stopped.

You get genuine findings for the loopback ports that are actually open, plus a list of the steps
this host could not run:

```
lab service: http://127.0.0.1:8080/ (real loopback listener, stopped now)
findings:    3 [info=3]
executed:    1 step(s): net-tcp
skipped:     8 (host tools this lab does not need)
  - net-nmap: binary not installed: nmap
  - net-services: binary not installed: nmap
```

Next, see what the machine can genuinely do:

```bash
make doctor        # scope, binaries, wordlists, templates, agents, model (same as --doctor)
make toolchain     # full inventory + install hints (same as --toolchain)
```

## 3. Authorize a real engagement

The agent refuses to run without an authorized scope (exit `3`). There is no override flag.

```bash
cyberpowerfull --init-scope scope.json \
    --engagement acme-q4 \
    --targets app.example.test,api.example.test,10.0.0.0/24 \
    --capabilities aggressive \
    --expires 2027-01-31 \
    --authorize --authorization-ref "SOW-2026-014 / signed 2026-11-01"
```

- `--authorize` **requires** `--authorization-ref`; without both, the file is written with
  `"authorized": false` and cannot be run.
- An existing file is never overwritten without `--force`.
- Confirm with `cyberpowerfull --doctor --scope scope.json --target app.example.test`.

Scope semantics (host-based, exclusions win):

| Field | Meaning |
|---|---|
| `targets` | exact hosts, IPs, CIDRs, or `*.wildcard` |
| `domains` | apex + all subdomains (`*.x.test` = subdomains only) |
| `exclude` | hosts/CIDRs removed from the above, including DNS answers that land inside them |
| `allowed_phases` | default `recon`, `scanning`, `validation` |
| `capabilities` | explicit opt-ins, see §7 |
| `allow_passive_sources` | enables `subfinder`'s third-party sources |
| `allowed_wordlists` / `allowed_nuclei_templates` | exact extra paths; local Kali libraries are already allowed |
| `max_rps` | rate hint translated into scanner delay flags (not a hard egress limit) |
| `expires`, `contact` | expiry enforcement and the person to call |

## 4. Choose an execution path

| Path | Command | Needs | Good for |
|---|---|---|---|
| Playbook | `--playbook <name>` | nothing (uses installed binaries) | reproducible coverage, CI, "just run it" |
| Reasoning loop | `--target HOST` | a local model | hypothesis-driven testing, judgment calls |

Both use the same tools, the same scope checks, and the same report format. Playbooks are the
default recommendation on a fresh host; the model adds value once you have findings to chase.

## 5. Playbooks in practice

| Playbook | Steps | Use when |
|---|---|---|
| `recon` | 11 | first look at a host or domain |
| `web` | 14 | you have an HTTP(S) app in scope |
| `network` | 9 | port surface and service identification |
| `stealth` | 6 | low request volume, no brute force |
| `api` | 6 | REST/GraphQL endpoints |
| `full` | 34 | recon + web + network, ordered by dependency |

```bash
cyberpowerfull --scope scope.json --target app.example.test --playbook recon
cyberpowerfull --scope scope.json --target app.example.test --playbook web --parallel 4
cyberpowerfull --scope scope.json --target 10.0.0.5 --playbook network --max-steps 20
cyberpowerfull --scope scope.json --target app.example.test --playbook full --dry-run
```

How a run adapts (deterministic, evidence-based):

- open ports from group 0 become the exact `-p` list for service detection;
- live URLs and technology fingerprints select `testssl`, `wpscan`, `arjun`, `searchsploit`;
- wordlists come from the host inventory (largest matching, never compressed); none → step skipped;
- missing binary or missing capability → skipped with the reason, recorded in trace and report;
- an identical invocation that already failed is not retried (`negative cache`).

Dry-run prints the argv that would be executed and touches nothing:

```bash
cyberpowerfull --scope scope.json --target app.example.test --playbook web --dry-run --json | jq '.steps[0].result.argv'
```

## 6. The reasoning loop (local model)

```bash
ollama serve &
ollama pull qwen3:4b
cyberpowerfull --scope scope.json --target app.example.test --llm ollama:qwen3:4b
```

- The endpoint must be loopback (`127.0.0.1`, `localhost`, `::1`); anything else is rejected before
  a packet leaves the host (exit `5`).
- `--llm llamacpp:model` for llama.cpp on `:8080`.
- `--llm replay:examples/decisions.json` re-runs a recorded decision stream — useful for tests.
- `--max-iterations`, `--max-tokens`, `--max-seconds` bound the run; `--dry-run` rehearses it.
- The model sees the scope, the host inventory, the tool catalogue, at most eight skill packs, and
  a read-only memory digest. It can only `delegate` or `terminate`.

Inspect what the model is told:

```bash
cyberpowerfull --render-prompt --scope scope.json --target app.example.test | less
```

## 7. Tools, capabilities, and packets

26 typed tools: `tcp_probe`, `subfinder`, `amass`, `dnsrecon`, `httpx`, `katana`, `wafw00f`,
`nmap`, `masscan`, `naabu`, `whatweb`, `nikto`, `ffuf`, `gobuster`, `feroxbuster`, `arjun`,
`testssl`, `wpscan`, `nuclei`, `sqlmap`, `dalfox`, `searchsploit`, `hydra`, `strix`, `pentagi`,
`sn1per`. List them with their install state:

```bash
cyberpowerfull --list-tools
```

Capability gate — a tool that needs a capability is blocked before its argv is built:

| Capability | Tools | Notes |
|---|---|---|
| `aggressive` | `masscan`, `naabu` | high packet rate / wide sweeps |
| `credential_testing` | `hydra` | capped candidates, first hit only, password redacted |
| `external_agents` | `strix`, `pentagi`, `sn1per` | data leaves the host for their model/provider |
| `destructive` | none | reserved |

Rate and volume: `max_rps` is translated into `--delay`/`--rate`/`-Pause` where the tool supports it.
It is a hint, not a traffic shaper — put an egress rule in place if the engagement requires one.

## 8. Reading the results

| Artifact | Content |
|---|---|
| `artifacts/report-<run_id>.md` | findings table, per-finding evidence, execution trace, **skipped steps with reasons** |
| `artifacts/findings-<run_id>.json` | machine-readable findings |
| `traces/latest.json` (or `--trace`) | full trace: steps, args, statuses, findings, scope fingerprint, `skipped` list |
| `artifacts/memory.sqlite3` | append-only memory: findings, attempts, evidence |

```bash
cyberpowerfull --replay traces/latest.json --out /tmp/review   # re-render without touching tools
cyberpowerfull --scope scope.json --target app.example.test --json | jq '.findings | length'
```

Finding quality: `severity` and `confidence` are separate. An open port is `info`; a template match
is a candidate until the evidence shows otherwise. Always read the evidence field.

## 9. External agents (Strix, PentAGI, Sn1per)

Require `external_agents` in the scope. Setup, environment variables, and the exact parsing
behaviour are in [INTEGRATIONS.md](INTEGRATIONS.md). Quick check:

```bash
cyberpowerfull --agents
```

Costs and data flow are the operator's responsibility: Strix and PentAGI use their own model
provider. If the agreement forbids that, do not grant the capability — playbooks do not need it.

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| exit `3`, "scope file not found" | no `scope.json`; run `--init-scope` (the lab prints the exact command) |
| exit `3`, "not marked authorized" | `"authorized": false`; re-run with `--authorize --authorization-ref REF` |
| exit `4` | the target is not inside `targets`/`domains`; fix the scope, not the tool |
| exit `5` | model unreachable or non-loopback endpoint; check `ollama serve` / `--llm` |
| exit `6` | a tool failed or a knowledge source is missing; the report names the step |
| exit `7` | policy block: capability missing, tool not allowed for the worker, or phase not permitted |
| exit `8` | unknown playbook; `--list-playbooks` |
| "binary not installed: X" | `make tools`, or check `make toolchain` for the package name |
| "wordlist ... not found" | install `seclists`/`wordlists`, or set `allowed_wordlists` |
| "no free lab port" | something is on 8080/8443/9200/27017/6379/5900/8008; `--lab-port` |
| lab finds nothing | nothing is listening on the swept ports; run `make lab` itself to prove the path |
| slow run | lower `--max-steps`, use `--playbook stealth`, or raise `--parallel` |

Every failure writes the trace it managed to produce. Read `stop_reason` and `skipped` first.

## 11. Recipes

```bash
# A. Recon a domain, no model
cyberpowerfull --init-scope scope.json --engagement acme --targets acme.test \
  --authorize --authorization-ref "SOW-1"
cyberpowerfull --scope scope.json --target acme.test --playbook recon --parallel 4

# B. Web app, then look up confirmed versions in Exploit-DB
cyberpowerfull --scope scope.json --target app.acme.test --playbook web
cyberpowerfull --search-exploits "wordpress 6.4"

# C. CI job: scan a staging host, fail the build only on real failures
cyberpowerfull --scope scope.json --target staging.acme.test --playbook stealth --quiet \
  --out artifacts --trace traces/staging.json || echo "exit $?"

# D. Rehearse everything before touching the target
cyberpowerfull --scope scope.json --target app.acme.test --playbook full --dry-run

# E. Give the model the loop, bounded
cyberpowerfull --scope scope.json --target app.acme.test --llm ollama:qwen3:4b \
  --max-iterations 8 --max-seconds 600
```

## 12. FAQ

**Does it need internet or an API key?** No. Inference is loopback-only. Target traffic needs
whatever network path the engagement allows.

**Does it need Kali?** It needs the binaries you want to use. `tcp_probe` is native, so a minimal
host still produces real evidence; everything else is skipped with a reason.

**Can I trust an `info` finding?** It is evidence-linked: open port, header, version, or template
match — all recorded. It is not a claim of impact.

**Why did a step not run?** Read the `## Skipped steps` section in the report; it names the exact
reason (missing binary, ungranted capability, unpermitted phase, negative cache, no fact).

**How do I add a tool or playbook?** `docs/HANDOFF.md §6` has the recipe; `CONTRIBUTING.md` has the
standards and the test expectations.

**Where do reports go?** `artifacts/` and `traces/` by default, both gitignored. They can contain
URLs, cookies, and model output; treat them as confidential and delete them after the engagement.
