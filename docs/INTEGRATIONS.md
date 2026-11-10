# External agent integrations: Strix, PentAGI, Sn1per

All three adapters are typed tools in the same registry as `nmap`. They require the
`external_agents` capability in `scope.json`, they re-check the target against the scope, and
they return `Finding` objects like any other tool. `--agents` shows what is reachable right now.

```json
{
  "engagement": "example",
  "authorized": true,
  "targets": ["app.example.test"],
  "capabilities": ["external_agents"]
}
```

## Strix

Open-source autonomous agent: <https://github.com/usestrix/strix>.

```bash
pipx install strix-agent
export STRIX_LLM="openai/gpt-5"      # any provider Strix supports
export LLM_API_KEY="…"
docker info                          # Strix pulls a sandbox image
cyberpowerfull --agents              # strix: available
```

The wrapper runs:

```
strix -n -t <target> --scan-mode <quick|standard|deep> \
       --max-budget <usd> --max-turns <n> \
       --instruction "<scope statement + optional operator instruction>"
```

- `-n` is mandatory: the interactive TUI blocks automation.
- The scope statement is prepended to `--instruction`, and the operator instruction is collapsed
  to one line so it cannot inject new flags.
- Reports are read from `strix_runs/` (Strix 1.7.1 writes `./strix_runs/<run>/` with `run.json`,
  `vulnerabilities.json`, and per-finding Markdown), with `agent_runs/`, `.strix_runs/`, and
  `$STRIX_RUNS_DIR` as fallback search paths (newest files first), plus the console output. A
  missing Docker CLI, missing `STRIX_LLM`, or a model-connection failure stops the run with the
  fix spelled out instead of an empty result. Only lines with an explicit severity tag become
  findings, and severity is re-derived from the evidence rather than copied.
- Cost is bounded by `max_budget_usd` (default 5) and `max_turns` (default 120). Raise them
  deliberately.

## PentAGI

Self-hosted multi-agent platform: <https://github.com/vxcontrol/pentagi>.

```bash
docker compose up -d                     # PentAGI listens on 8080, plain HTTP, by default
export PENTAGI_URL=http://127.0.0.1:8080
export PENTAGI_API_TOKEN="…"             # created in the PentAGI UI
export PENTAGI_TLS_VERIFY=false          # only for a loopback self-signed instance
cyberpowerfull --agents
```

Flow of a single call:

1. `POST /api/v1/graphql` with the `createFlow` mutation (`modelProvider`, `input`); if the
   server rejects it, the REST endpoint `POST /api/v1/flows/` (`input`, `provider`) is tried.
2. Poll `flow(flowId:)` (GraphQL), falling back to `GET /api/v1/flows/{id}`, until the status is
   `finished`, `failed`, or `waiting`, or `max_wait_s` (default 900) elapses. `waiting` means the
   flow needs input in the PentAGI UI, so the run stops with that message instead of hanging; a
   flow that never finishes is reported as `timeout`, never as a success.
3. Fetch results from `tasks(flowId:)`, falling back to `GET /api/v1/flows/{id}/tasks/`. Each
   task becomes a `### title [status]` section; if no task text comes back, the last known flow
   state is returned as JSON so the run still shows what happened. There is no `report` field
   and no `/report` route in v2.2.0. A structured JSON list is parsed as records; task prose
   uses the severity-tagged line extractor.

The objective sent to PentAGI states the target and the constraints (in-scope only, no
persistence, no lateral movement, no data extraction). Nothing is created if the server returns
an error: the exact HTTP status and body are surfaced in `ToolResult.error`, and an HTTP 401
names the fix (create a token in the PentAGI UI, set `PENTAGI_API_TOKEN`, and make sure the
server auth salt is not the default).

PentAGI offers no stable machine report schema, so task prose is evidence to verify, not
findings to copy blindly. The adapter is deliberately tolerant and returns what the instance
provides.

## Sn1per

Automated recon/vulnerability suite: <https://github.com/1N3/Sn1per>.

```bash
git clone https://github.com/1N3/Sn1per /opt/Sn1per
sudo bash /opt/Sn1per/install.sh
cyberpowerfull --agents
```

```
sniper -t <target> -m <normal|stealth|port|web|webporthttp|webporthttps|webscan|fullportonly|vulnscan> [-w workspace]
```

- The workspace name defaults to the sanitised target.
- Modes are the single-target set from Sn1per 9.2: `discover` needs a CIDR (`HostInput` cannot
  express one) and the mass modes need `-f targets.txt`, so both are excluded rather than run
  wrong. `port`, `webporthttp`, and `webporthttps` require `-p` up front: without it Sn1per
  prints an error and still exits 0.
- Loot is searched in `--loot_dir`, `$SNIPER_LOOT_DIR`, `/usr/share/sniper/loot`, `~/loot`, and
  `./loot`. Only files under a directory matching the workspace are read, capped at 40 files and
  512 KiB each.
- Findings come from `vulnerabilities/`, `findings/`, or `exploit/` text files plus
  severity-tagged console lines. An empty workspace produces no findings and says so.
- Sn1per refuses to run unless started as root; the wrapper reports that as blocked with the
  fix (re-run elevated) instead of an empty result.

## Choosing between them

| Situation | Use |
|---|---|
| Reproducible coverage with no model | a playbook (`--playbook web`) |
| Hypothesis-driven testing with a local model | the reasoning loop (default) |
| Multi-step exploitation reasoning, budget available | `strix` or `pentagi` |
| Broad recon sweep with an existing Sn1per install | `sn1per` |

Never chain them: one delegated agent per hypothesis, and its output is evidence to verify, not a
conclusion to copy.
