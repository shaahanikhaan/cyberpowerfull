#!/usr/bin/env bash
# cve_hunt.sh - offline CVE hunt for one in-scope host.
#
#   1. native TCP connect scan (no nmap required)
#   2. HTTP banner facts for discovered web ports (no curl required)
#   3. component inventory (product/version from banners and nmap XML, if given)
#   4. offline correlation against the local advisory corpus
#
# Feeds are never downloaded here: fetch NVD/KEV JSON with your own tooling and
# import it with --import-feed. Everything runs locally.
#
# usage:
#   tools/bash/cve_hunt.sh --scope scope.json --target 127.0.0.1
#   tools/bash/cve_hunt.sh --scope scope.json --target app.lab --ports 80,443,8080
#   tools/bash/cve_hunt.sh --scope scope.json --target app.lab --import-feed nvd.json
#   tools/bash/cve_hunt.sh --scope scope.json --target app.lab --nmap-xml scan.xml --min-cvss 7

. "$(cd "$(dirname "$0")" && pwd)/lib/common.sh"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

SCOPE=""
TARGET=""
PORTS="common"
TIMEOUT="0.6"
NMAP_XML=""
FEEDS=()
MIN_CVSS="0"
OUT=""
JSON=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --ports) PORTS="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    --nmap-xml) NMAP_XML="${2:-}"; shift 2 ;;
    --import-feed) FEEDS+=("${2:-}"); shift 2 ;;
    --min-cvss) MIN_CVSS="${2:-}"; shift 2 ;;
    --intel-store) CPF_INTEL_STORE="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

SCOPE="$(cpf_require_scope "$SCOPE")"
[[ -n "$TARGET" ]] || die "--target is required"
cpf_assert_scope "$SCOPE" "$TARGET" >/dev/null

for feed in "${FEEDS[@]:-}"; do
  [[ -n "$feed" ]] || continue
  [[ -f "$feed" ]] || die "feed not found: $feed"
  log "importing advisory feed: $feed"
  cpf_cli --import-feed "$feed" --intel-store "$CPF_INTEL_STORE" >/dev/null
done

OUT="${OUT:-$CPF_ARTIFACTS/intel}"
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BASE="$OUT/$(printf '%s' "$TARGET" | tr '/:' '__')-$STAMP"

log "resolving $TARGET"
"$(cpf_python)" -m cyberpowerfull.native_scan --scope "$SCOPE" resolve --host "$TARGET" > "$BASE.resolve.json"

log "scanning $TARGET (ports: $PORTS)"
"$(cpf_python)" -m cyberpowerfull.native_scan --scope "$SCOPE" ports \
  --host "$TARGET" --ports "$PORTS" --timeout "$TIMEOUT" > "$BASE.ports.json"

HTTP_FACTS="$BASE.http.json"
"$(cpf_python)" - "$BASE.ports.json" "$TARGET" > "$HTTP_FACTS" <<'PY'
import json, sys
from cyberpowerfull.native_scan import http_facts

ports = json.load(open(sys.argv[1], encoding="utf-8")).get("open_ports", [])
target = sys.argv[2]
schemes = {443: "https", 8443: "https", 9443: "https"}
records = []
for item in ports:
    port = item["port"]
    scheme = schemes.get(port, "http")
    facts = http_facts(f"{scheme}://{target}:{port}/")
    if facts.get("status") and not facts.get("error"):
        records.append(facts)
    elif scheme == "http":
        alt = http_facts(f"https://{target}:{port}/")
        if alt.get("status") and not alt.get("error"):
            records.append(alt)
print(json.dumps(records, indent=2))
PY
HTTP_COUNT="$("$(cpf_python)" -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$HTTP_FACTS")"
log "http services responding: $HTTP_COUNT"

log "building component inventory"
INVENTORY_ARGS=()
[[ -n "$NMAP_XML" ]] && INVENTORY_ARGS+=(--nmap-xml "$NMAP_XML")
INVENTORY_ARGS+=(--http-json "$HTTP_FACTS")
"$(cpf_python)" -m cyberpowerfull.native_scan inventory --target "$TARGET" \
  "${INVENTORY_ARGS[@]}" --out "$BASE.components.json" >/dev/null

log "correlating against the local advisory corpus"
cpf_cli --correlate "$BASE.components.json" --target "$TARGET" \
  --min-cvss "$MIN_CVSS" --json --intel-store "$CPF_INTEL_STORE" > "$BASE.findings.json"

if [[ "$JSON" -eq 1 ]]; then
  cat "$BASE.findings.json"
else
  cpf_findings_table "$BASE.findings.json"
  log "artifacts: $BASE.{resolve,ports,http,components,findings}.json"
fi

COUNT="$("$(cpf_python)" - "$BASE.findings.json" <<'PY'
import json, sys
print(len(json.load(open(sys.argv[1], encoding="utf-8"))))
PY
)"
[[ "$COUNT" -gt 0 ]] && exit 1 || exit 0
