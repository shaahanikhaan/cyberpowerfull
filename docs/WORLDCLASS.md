# How cyberpowerfull becomes #1 — research and plan

*Date: 2026-11-11. All competitor numbers were pulled live from the GitHub API and
published benchmark reports on this date; re-run the queries before quoting them.*

The question is not "how do we add more features" but "what does the crown actually
require". So this document does three things: (1) measures where the crown is, (2) extracts
what every winner has in common, (3) turns that into a phased plan with numbers, not adjectives.

## 1. Where the crown is (measured 2026-11-11)

| Project | Stars | Scale fact | Automation model |
|---|---|---|---|
| Metasploit | 39,482 | **5,077 modules** (2,686 exploits, 1,332 auxiliary, 541 payloads, 435 post) | interactive framework + community modules |
| Nuclei | 32,785 | **14,211 templates** (YAML, crowdsourced) | template engine, CI-native |
| Sn1per | 11,532 | 90+ integrations, 30+ modes, loot workspace | bash orchestration, one command |
| BBOT | 11,099 | 115 modules, event-driven, 13+ output modules (Splunk, Elastic, Neo4j, Slack…) | recursive scan engine + Python library API |
| ReconFTW | 8,358 | bash + config files, Axiom-distributed | pipeline automation |
| OWASP Nettacker | 5,721 | multi-engine scanner | profile-driven scans |
| **cyberpowerfull** | **0** | **43 typed tools, 8 playbooks, 106 steps, 1,075 tests** | deterministic + AI hybrid, proof-only |

Benchmark state of the art (autonomous exploitation, CVE-Bench 40 critical web CVEs):

| System | Setting | Score |
|---|---|---|
| BountyKai (Oct 2026, v2.2.0) | zero-day, success@1 | **60% (24/40)** — current best claim |
| PenForge | zero-day, success@5 | 30% |
| CVE-Bench paper best (T-Agent) | zero-day / one-day | 13% / 25% |
| XBOW (HackerOne, live) | real bug bounty | #1 leaderboard, but **~12% valid** (130 of ~1,060) |
| ARTEMIS (live 8k-host net) | infra pentest vs humans | 2nd of 11, **82% valid** |

Two facts matter more than any table:

1. **The #1 failure mode is insufficient exploration (67–80% of zero-day failures).**
   Winners do not win by exploiting better — they win by *seeing more* before they act.
   Coverage is the game.
2. **Volume without verification is worthless.** XBOW's 1,060 reports at ~12% valid is the
   cautionary tale; ARTEMIS's 82% valid at 2nd place is the template. Trust is the moat.

## 2. The five laws every winner obeys

1. **Ecosystem beats product.** Metasploit's 5,077 modules came from 62 contributors in one
   year (39 first-timers). Nuclei's 14,211 templates are crowdsourced. BBOT ships module
   *templates* so a new passive source is ~40 lines. Nobody reaches #1 with a closed core.
2. **Verification decides trust.** Proof-only output (every finding re-proven with evidence)
   is what separates a tool professionals bet engagements on from a report-spam machine.
3. **Composability decides adoption.** BBOT runs as a 5-line Python library; Metasploit has
   `search/use/set`; winners emit to SIEM/SOAR (Splunk, Elastic, webhooks), not just files.
4. **Automation depth decides the demo.** One command from target to report; then fleets
   (distributed), then always-on (ASM/continuous). Each level 10×es the addressable user.
5. **Public benchmarks decide the claim.** "Most powerful" is meaningless without a number.
   CVE-Bench success rate is the leaderboard that matters; unmeasured means unranked.

## 3. Our unfair advantages (already built, nobody else has all five)

- **Deterministic + AI hybrid.** 8 playbooks run with no model at all; the agent loop uses a
  local model when wanted. Reproducible automation *and* adaptive reasoning, one tool layer.
- **Proof-only exploitation.** Payloads deliver exactly one verified proof; hypotheses never
  become findings. This is the ARTEMIS religion, built into the architecture.
- **Authorization-first.** Scope gate, capability gate, append-only memory, honest skips.
  Enterprise-legal by construction — cloud-agent vendors cannot match this story.
- **Typed everything.** 43 Pydantic-validated tools, `shell=False` argv, bounded output.
  added reliably instead of stringly-typed bash.
- **Local-only.** No cloud key, no telemetry, no data leaves the box. A requirement, not a
  feature, for banks, governments, and bug-bounty hunters guarding their methods.

## 4. The honest gap list

| Gap | Us | Winner |
|---|---|---|
| Tool coverage | 43 tools, 79 binaries | Kali ships 600+; BBOT 115 modules |
| Exploit/verification depth | proof payloads, msf allowlisted wrapper | Metasploit 2,686 exploits, 1,332 auxiliary |
| Template crowd | reads host's nuclei templates | 14,211 templates + contributor flywheel |
| Plugin API | none — adding a tool is a 6-file fork recipe | entry points / 40-line module templates |
| Library API | CLI only | `Scanner("evilcorp.com")` in 5 lines |
| SOC outputs | SARIF/JSON/Markdown (CI-good, SOC-weak) | Splunk, Elastic, webhooks, SOAR |
| Measured rank | no CVE-Bench score | published scores up to 60% |
| Always-on | one-shot runs | ASM/continuous, distributed fleets |
| Auth-aware scans | none | cookie/header/SSO session handling |
| Community | 0 stars, 0 external contributors | thousands of stars, hundreds of contributors |

## 5. The plan: five pillars to #1

Each pillar has a number. If the number does not move, the pillar failed.

### Pillar 1 — Coverage engine (v6.x): see more than everyone

*Why:* exploration failure is 67–80% of zero-day losses. Coverage IS power.
- 43 → **150 typed tools**: wrap the Kali top-100 by install base (httpx-class first),
  every wrapper schema-pinned against upstream like the current 43.
- **KEV coverage metric**: `cpf --kev-coverage` reports which CISA-KEV CVEs have a
  detection path (nuclei template id / msf module / probe) in this install. Target: 80%.
- **CWE coverage map**: every finding maps to CWE; publish the covered-CWE count per release.
- Auth-aware crawling (scoped credential store, secrets never touch traces) + OpenAPI import.
- *Acceptance:* 150 tools, KEV coverage ≥80%, all parsers golden-fixture-tested (roadmap 5.4.0).

### Pillar 2 — Proof engine (v7.x): the verified-findings leaderboard

*Why:* XBOW proved volume is cheap; ARTEMIS proved validity wins engagements.
- **CVE-Bench harness**: `cpf --cvebench` runs the agent loop against the public harness
  (Docker + Kali, same as everyone) and prints the success@1/success@5 line.
- Target: **top-3 open-source score**, published in the README with version + date.
- Cross-prover: every HIGH/CRITICAL finding is re-checked by an independent second tool
  before it ships (nuclei↔zap, sqlmap↔payload-marker); disagreements become explicit
  `unverified` findings instead of silent claims.
- False-positive budget: track `verified / total` per run; fail CI if the lab's valid rate
  drops below the pinned floor.
- *Acceptance:* published CVE-Bench score, valid-rate metric in every report.

### Pillar 3 — Ecosystem (v8.x): other people build our moat

*Why:* all five laws say the winner is a platform. 39 first-time msf contributors in a year
is the number to beat.
- **Plugin API**: `cyberpowerfull.tools` entry points — a third-party wrapper installs via
  pip and appears in `cpf --list-tools` with zero core patches (roadmap 5.6.0 item, promoted).
- **`cpf new-tool` scaffold**: answers 4 questions, emits wrapper + fixture test + docs row.
  Adding a tool drops from a 6-file recipe to one command.
- **Library API**: `from cyberpowerfull import Scanner` — `Scanner("target", playbook="web")`
  streams events, BBOT-style. CLI becomes a thin client of the library.
- *Acceptance:* 10 external plugins installable from PyPI; 3 merged from non-maintainers.

### Pillar 4 — Enterprise gravity (v9.x): runs where the money is

*Why:* adoption compounds when the tool lives inside the customer's existing machine.
- Output modules: **webhook, Splunk HEC, Elastic, Jira/GitHub-issues** — findings flow into
  the SOC, not just files.
- **Campaigns**: multi-target runs with one scope, one report, diff-against-last (`--compare`
  graduates from two runs to full campaign history).
- **Continuous mode**: `cpf watch` — scheduled re-scans with new/resolved alerting (the ASM
  wedge, still CLI, still local).
- Signed releases + container image + `pipx`/brew (roadmap 5.6.0, finished).
- *Acceptance:* a SOC can run cpf on a cron and wake up to webhook findings; image on ghcr.io.

### Pillar 5 — Community flywheel (always on, compounds everything)

*Why:* 0 stars is the single most honest line in section 1. Technology does not market itself.
- Docs as product: keep the 60-second quickstart true on a bare VPS; video/gif of `--lab`.
- **Benchmark page**: CVE-Bench + KEV-coverage + valid-rate, updated every release. Numbers
  are the marketing the security community actually trusts.
- Contribution ladder: `good-first-tool` issues auto-generated from the Kali top-100 gap
  list; conformance CI (golden fixtures) makes drive-by modules safe to merge.
- *Acceptance:* 1,000 stars, 10 external contributors, monthly release cadence.

## 6. What we will NOT do

- No web UI / SaaS / multi-tenant server. The crown for *automation* belongs to the best
  engine, and every hour on dashboards is an hour stolen from coverage and proof. Outputs
  (SARIF, webhooks, SIEM) are how other people's UIs consume us.
- No cloud planner, no API-key code path. Local-only is the enterprise moat; XBOW already
  owns the cloud corner and we do not fight there.
- No bundled wordlists/templates/exploits. We read the host's libraries (legal everywhere,
  fresh everywhere).
- No volume-without-verification. We will never chase report counts at the cost of the
  valid rate. ARTEMIS, not XBOW.

## 7. Scoreboard (updated every release)

| Metric | Today (5.2.0) | v6 target | v7 target | #1 bar |
|---|---|---|---|---|
| Typed tools | 43 | 150 | 200 | Kali 600+ |
| CVE-Bench zero-day | unmeasured | harness runs | top-3 OSS | 60% (BountyKai) |
| Valid rate (lab) | unmeasured | pinned floor | published | 82% (ARTEMIS) |
| KEV coverage | unmeasured | ≥80% | ≥90% | — |
| External plugins | 0 | API ships | 10 on PyPI | msf 5,077 modules |
| Stars / contributors | 0 / 0 | 100 / 3 | 1,000 / 10 | msf 39k |

*Next action: Pillar 1 sprint 1 — Kali top-100 gap list generated from live Kali metapackages,
first 20 wrappers schema-pinned, `--kev-coverage` shipped.*
