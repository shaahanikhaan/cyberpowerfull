#!/usr/bin/env bash
# payload_run.sh - generate (and optionally deliver) one proof-only payload.
#
# Safety posture:
#   * the generator refuses destructive templates before a request is built
#   * one payload, one request, one marker: no fuzzing loop
#   * delivery goes through http_probe, so scope is re-checked in Python
#
# usage:
#   tools/bash/payload_run.sh --scope scope.json --url 'http://127.0.0.1:8080/search?q=x' --skill xss
#   tools/bash/payload_run.sh --scope scope.json --url http://127.0.0.1/ --skill sqli --param id --send
#   tools/bash/payload_run.sh --scope scope.json --url http://127.0.0.1/api --skill jwt --send
#   tools/bash/payload_run.sh --scope scope.json --url http://127.0.0.1/ --skill xss --id xss_html_script

. "$(cd "$(dirname "$0")" && pwd)/lib/common.sh"

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

SCOPE=""
URL=""
SKILL=""
PARAM="q"
ID=""
SEND=0
MARKER="cpf7391"
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --url) URL="${2:-}"; shift 2 ;;
    --skill) SKILL="${2:-}"; shift 2 ;;
    --param) PARAM="${2:-}"; shift 2 ;;
    --id) ID="${2:-}"; shift 2 ;;
    --marker) MARKER="${2:-}"; shift 2 ;;
    --send) SEND=1; shift ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

SCOPE="$(cpf_require_scope "$SCOPE")"
[[ -n "$URL" ]] || die "--url is required"
[[ -n "$SKILL" ]] || die "--skill is required (sql_injection, xss, ssrf, ssti, ...)"

HOST="$("$(cpf_python)" - "$URL" <<'PY'
import sys
from urllib.parse import urlparse
print(urlparse(sys.argv[1]).hostname or "")
PY
)"
[[ -n "$HOST" ]] || die "could not parse a host from $URL"
cpf_assert_scope "$SCOPE" "$HOST" >/dev/null
log "in scope: $HOST"

OUT="${OUT:-$CPF_ARTIFACTS/payloads}"
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

GEN_ARGS=(--payload "$SKILL" --target "$URL" --payload-param "$PARAM" --json)
[[ -n "$ID" ]] && GEN_ARGS+=(--payload-ids "$ID")
cpf_cli "${GEN_ARGS[@]}" > "$OUT/$SKILL-$STAMP.json"
log "generated payload plan: $OUT/$SKILL-$STAMP.json"

"$(cpf_python)" - "$OUT/$SKILL-$STAMP.json" <<'PY'
import json, sys
items = json.load(open(sys.argv[1], encoding="utf-8"))
for item in items:
    print(f"[{item['id']}] {item['technique']} -> {item['method']} {item['url']}")
    for name, value in item.get("headers", {}).items():
        print(f"    {name}: {value}")
    if item.get("body"):
        print(f"    body: {item['body']}")
    print(f"    expect: {item['expected_signal']}")
PY

if [[ "$SEND" -eq 0 ]]; then
  log "dry run: pass --send to deliver exactly one payload"
  exit 0
fi

FIRST="$("$(cpf_python)" - "$OUT/$SKILL-$STAMP.json" <<'PY'
import json, sys
items = json.load(open(sys.argv[1], encoding="utf-8"))
print(items[0]["id"] if items else "")
PY
)"
[[ -n "$FIRST" ]] || die "no payload generated"
log "delivering one payload: $FIRST"

"$(cpf_python)" - "$OUT/$SKILL-$STAMP.json" "$FIRST" "$MARKER" <<'PY' > "$OUT/$FIRST-$STAMP.result.json"
import json, sys
from cyberpowerfull.tools.http_probe import HttpProbeTool
items = json.load(open(sys.argv[1], encoding="utf-8"))
payload = next(item for item in items if item["id"] == sys.argv[2])
result = HttpProbeTool().run(
    {
        "target": payload["url"],
        "method": payload["method"],
        "headers": payload.get("headers") or {},
        "body": payload.get("body"),
        "marker": sys.argv[3],
    }
)
print(json.dumps(
    {
        "payload": payload["id"],
        "status": result.status.value,
        "error": result.error,
        "findings": [item.model_dump(mode="json") for item in result.findings],
        "observations": result.observations,
    },
    indent=2,
))
PY

cpf_findings_table "$OUT/$FIRST-$STAMP.result.json"
log "result: $OUT/$FIRST-$STAMP.result.json"
