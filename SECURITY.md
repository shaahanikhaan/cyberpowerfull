# Security Policy

## Intended use and safety boundaries

`cyberpowerfull` is intended only for assets you own or are explicitly authorized to assess.
Supply an accurate, current `scope.json` and agree on methods, allowable traffic, and incident
contacts with the asset owner before running it. The bundled scope is for a loopback lab only.

The CLI rejects missing/unauthorized/expired scope, checks primary delegated targets and phases,
restricts model endpoints to loopback, and prevents model-server redirects and proxy use. Passive
third-party sources require an explicit scope opt-in; model-selected wordlists and Nuclei templates
must be operator-allowlisted files (files from the local Kali wordlist and nuclei-template
directories are accepted because they are the operator's own libraries, not arbitrary host files).
Those controls reduce mistakes; **they are not a sandbox**.

## Capability gate

Aggressive or credential-touching tools are blocked before a command line is even built unless
`scope.json` grants the matching capability:

| Capability | Unlocks | Blocked message |
|---|---|---|
| `aggressive` | `masscan`, `naabu` | "requires the 'aggressive' capability" |
| `credential_testing` | `hydra` | "requires the 'credential_testing' capability" |
| `external_agents` | `strix`, `pentagi`, `sn1per` | "requires the 'external_agents' capability" |
| `destructive` | reserved; no shipped tool requires it | - |

The granted list is part of the SHA-256 scope fingerprint recorded in every trace, so a run can be
attributed to a specific set of permissions. `hydra` stops at the first valid credential, caps
concurrency at 8, rejects oversized candidate lists, and redacts the recovered password in
evidence and reports.

## External agents and third-party processing

`strix`, `pentagi`, and `sn1per` are third-party autonomous systems. With `external_agents`
granted they run their own tooling and, for Strix and PentAGI, their own model provider - which
means engagement data (targets, responses, findings) leaves this machine and is processed by that
provider.

- They never run without the capability, and the target is re-checked against `scope.json` first.
- The delegated instruction always states the in-scope target and the engagement constraints.
- Cost and runtime are bounded (`max_budget_usd`, `max_turns`, `max_wait_s`).
- Their output is a hypothesis: it is only promoted to a finding when the adapter can attach
  concrete evidence, and its severity is re-derived locally.

If the agreement forbids third-party processing, do not grant `external_agents`. The reasoning
loop and every playbook work without it.

Third-party scanner binaries, DNS, redirects, templates, subprocesses, local configuration, and
model/target output are not fully controlled by this application. Scanner tests may change data or
contact destinations other than the declared target. Enforce egress allowlists and rate limits at
the network boundary, use isolated test accounts, review tools and templates, and supervise runs.
See [the readiness audit](docs/readiness-audit.md) for precise limitations.

## Reporting a vulnerability in this software

If you find a security defect in the package itself, do not open a public issue. Use GitHub's
private vulnerability reporting for this repository (Security → Advisories → “Report a vulnerability”) or contact the repository maintainers through their GitHub profile. Include the
affected version or commit, minimal reproduction, impact, and suggested remediation if known.

## Scope of this policy

In scope: the Python package, CLI contract, scope and local-inference guardrails, and
run-isolation guarantees. Report vulnerabilities in third-party tools to their own maintainers.
Claims requiring modification of the declared authorization or a malicious locally installed
binary do not demonstrate a standalone authorization boundary.

## Engagement data

Traces, reports, and SQLite memory can contain sensitive request arguments, cookies, model output,
and evidence. New files are created with owner-only permissions on POSIX, but existing directories
retain their permissions and data is not encrypted. Scanner processes can still access local files
and may contact third-party services when configured or explicitly opted in. Use encryption,
restricted access, retention limits, and secure deletion appropriate to the engagement.
