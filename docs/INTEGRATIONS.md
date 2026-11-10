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
- Reports are read from `strix_runs/`, `agent_runs/`, or `$STRIX_RUNS_DIR` (newest files first),
  plus the console output. Only lines with an explicit severity tag become findings, and severity
  is re-derived from the evidence rather than copied.
- Cost is bounded by `max_budget_usd` (default 5) and `max_turns` (default 120). Raise them
  deliberately.

## PentAGI

Self-hosted multi-agent platform: <https://github.com/vxcontrol/pentagi>.

```bash
docker compose up -d                     # PentAGI on https://localhost:8443
export PENTAGI_URL=https://127.0.0.1:8443
export PENTAGI_API_TOKEN="…"             # created in the PentAGI UI
export PENTAGI_TLS_VERIFY=false          # only for a loopback self-signed instance
cyberpowerfull --agents
```

Flow of a single call:

1. `POST /api/v1/graphql` with the `createFlow` mutation (`modelProvider`, `input`); if the
   server rejects it, the documented REST endpoint `POST /api/v1/flows` is tried.
2. Poll `flow(id)` (GraphQL), falling back to `GET /api/v1/flows/{id}`, until the status is
   terminal or `max_wait_s` elapses. A flow that does not finish is reported as `timeout`, not
   as a success.
3. Fetch the report from the `report` field, `GET /api/v1/flows/{id}/report`, or the last known
   flow state. Structured JSON reports are parsed as records; prose reports use the
   severity-tagged line extractor.

The objective sent to PentAGI states the target and the constraints (in-scope only, no
persistence, no lateral movement, no data extraction). Nothing is created if the server returns
an error: the exact HTTP status and body are surfaced in `ToolResult.error`.

PentAGI has no documented JSON report export, so do not expect a stable machine schema from the
report endpoint. The adapter is deliberately tolerant and returns what the instance provides.

## Sn1per

Automated recon/vulnerability suite: <https://github.com/1N3/Sn1per>.

```bash
git clone https://github.com/1N3/Sn1per /opt/Sn1per
sudo bash /opt/Sn1per/install.sh
cyberpowerfull --agents
```

```
sniper -t <target> -m <normal|stealth|recon|web|webscan|fullportonly|port> [-w workspace]
```

- The workspace name defaults to the sanitised target.
- Loot is searched in `--loot_dir`, `$SNIPER_LOOT_DIR`, `/usr/share/sniper/loot`, `~/loot`, and
  `./loot`. Only files under a directory matching the workspace are read, capped at 40 files and
  512 KiB each.
- Findings come from `vulnerabilities/`, `findings/`, or `exploit/` text files plus
  severity-tagged console lines. An empty workspace produces no findings and says so.
- Sn1per needs root for many modules; run the engagement host accordingly or accept the skips.

## Choosing between them

| Situation | Use |
|---|---|
| Reproducible coverage with no model | a playbook (`--playbook web`) |
| Hypothesis-driven testing with a local model | the reasoning loop (default) |
| Multi-step exploitation reasoning, budget available | `strix` or `pentagi` |
| Broad recon sweep with an existing Sn1per install | `sn1per` |

Never chain them: one delegated agent per hypothesis, and its output is evidence to verify, not a
conclusion to copy.
