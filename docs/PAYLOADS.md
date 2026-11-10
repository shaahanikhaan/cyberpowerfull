# Proof-only payloads

`cyberpowerfull` generates requests that **prove** a vulnerability class with the smallest
possible signal. It does not ship exploit chains, shellcode, or destructive payloads, and the
catalogue is audited on every generation.

## What "proof-only" means

| Skill | Proof | Not in the catalogue |
|---|---|---|
| SQL injection | arithmetic/boolean differential, one time-based delay, `UNION SELECT NULL` width probe | `DROP`, `INTO OUTFILE`, `LOAD_FILE`, stacked queries |
| XSS | marker reflection in the correct context | cookie theft, keyloggers, network beacons |
| SSRF | loopback / decimal / IPv6 forms, `/dev/null` scheme probe | metadata credential harvesting |
| SSTI | `7*7` arithmetic for the engine | sandbox escape chains |
| Path traversal | `/etc/hostname`, `win.ini` | `/etc/shadow`, private keys |
| Command injection | `echo $((7*7))`, one `sleep 5` | reverse shells, `nc -e`, `bash -i` |
| XXE | internal entity expansion, `file:///dev/null`, in-scope OOB canary | `/etc/passwd` exfiltration |
| JWT | `alg=none` and empty-signature tokens carrying a marker | real credential reuse |
| Open redirect | `example.org` and scheme-relative forms | phishing infrastructure |
| IDOR | neighbouring identifiers (`0`, `1`, `-1`) | bulk enumeration |
| Mass assignment | `role` / `verified` flags plus a marker | destructive profile changes |
| Cache poisoning | unkeyed-header canary host | cache flooding |
| CRLF | a single injected response header | response splitting with bodies |
| API discovery | GraphQL `__typename`, OpenAPI documents, `OPTIONS` | authenticated scraping |

`FORBIDDEN_TOKENS` in `payloads/models.py` rejects destructive fragments (`rm -rf`, `mkfs`,
`/etc/shadow`, `nc -e`, `bash -i`, `169.254.169.254`, `DROP TABLE`, `xp_cmdshell`, …). The audit
runs on import, on `--payload`, and inside the `payload` tool. A single violation blocks the
whole generation.

## Using it

```bash
# print ready-to-send requests for one skill
cyberpowerfull --payload sqli --target 'http://127.0.0.1:8080/item?id=1' --payload-param id

# one specific vector, JSON for tooling
cyberpowerfull --payload jwt --target http://127.0.0.1/admin --payload-ids jwt_alg_none --json

# deliver exactly one request and read the evidence
cyberpowerfull --http-probe 'http://127.0.0.1:8080/search?q=cpf7391' --probe-marker cpf7391

# generate, then deliver the first vector, from the shell
tools/bash/payload_run.sh --scope scope.json --url http://127.0.0.1:8080/search --skill xss --send
```

Rendering rules:

| Mode | Behaviour |
|---|---|
| `query` | value URL-encoded and appended to the existing query string |
| `path` | joined to the base URL (traversal and API-discovery entries) |
| `header` | sent as the named header; `Authorization` gets a `Bearer ` prefix |
| `body` | sent as the body with `application/json` or `application/xml` inferred |

The marker (`cpf7391` by default) must be alphanumeric so it survives HTML, SQL, and JSON
contexts unchanged.

## In the agent loop

`payload` is a native validation-phase tool. The intended sequence is: `payload` → pick one
entry → `http_probe` → read the finding. The payload tool itself produces no findings — only a
plan — because a generated request is not evidence.

## Safety posture

- Scope is re-checked in Python before any request leaves the process.
- `http_probe` follows at most one same-host redirect and never chases an external one.
- One payload, one request, one marker: there is no fuzzing loop in the catalogue.
- OOB entries only accept collaborators you control inside the authorised scope.

## Tests

`tests/test_payloads.py` asserts catalogue uniqueness, skill coverage, alias resolution,
query/path/header/body rendering, JWT construction, generation limits, forbidden-token refusal,
and the tool's no-findings contract. `tests/test_native_tools.py` delivers generated payloads
to a local `ThreadingHTTPServer` and checks the resulting findings.
