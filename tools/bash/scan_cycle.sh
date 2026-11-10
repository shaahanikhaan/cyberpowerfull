#!/usr/bin/env bash
# scan_cycle.sh - one command, one host, a complete offline first pass.
#
#   resolve -> native port scan -> HTTP facts -> component inventory
#           -> CVE correlation -> payload plan -> markdown summary
#
# No nmap, no nuclei, no model and no internet connection are required. When
# nmap XML is supplied (--nmap-xml) its CPE data is preferred over banners.
#
# usage:
#   tools/bash/scan_cycle.sh --scope scope.json --target 127.0.0.1
#   tools/bash/scan_cycle.sh --scope scope.json --target app.lab --ports 22,80,443 --nmap-xml scan.xml
#   tools/bash/scan_cycle.sh --scope scope.json --target app.lab --skill xss --send

. "$(cd "$(dirname "$0")" && pwd)/lib/common.sh"

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

SCOPE=""
TARGET=""
PORTS="common"
NMAP_XML=""
SKILL=""
PARAM="q"
SEND=0
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --ports) PORTS="${2:-}"; shift 2 ;;
    --nmap-xml) NMAP_XML="${2:-}"; shift 2 ;;
    --skill) SKILL="${2:-}"; shift 2 ;;
    --param) PARAM="${2:-}"; shift 2 ;;
    --send) SEND=1; shift ;;
    --intel-store) CPF_INTEL_STORE="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

SCOPE="$(cpf_require_scope "$SCOPE")"
[[ -n "$TARGET" ]] || die "--target is required"

OUT="${OUT:-$CPF_ARTIFACTS/cycle}"
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN="$OUT/$(printf '%s' "$TARGET" | tr '/:' '__')-$STAMP"
mkdir -p "$RUN"
SUMMARY="$RUN/summary.md"

log "cycle start: $TARGET -> $RUN"
HUNT_ARGS=(--scope "$SCOPE" --target "$TARGET" --ports "$PORTS" --out "$RUN")
[[ -n "$NMAP_XML" ]] && HUNT_ARGS+=(--nmap-xml "$NMAP_XML")
# cve_hunt exits 1 when it finds candidates; that is information, not failure.
"$CPF_SCRIPT_DIR/cve_hunt.sh" "${HUNT_ARGS[@]}" || true

PAYLOAD_NOTE="not requested"
if [[ -n "$SKILL" ]]; then
  BASE="$RUN/$(printf '%s' "$TARGET" | tr '/:' '__')-$STAMP"
  URL="$("$(cpf_python)" - "$BASE.http.json" "$TARGET" <<'PY'
import json, sys
records = json.load(open(sys.argv[1], encoding="utf-8"))
for record in records:
    if record.get("status") and not record.get("error"):
        print(record["url"].rstrip("/"))
        break
else:
    print(f"http://{sys.argv[2]}/")
PY
)"
  PAYLOAD_ARGS=(--scope "$SCOPE" --url "$URL" --skill "$SKILL" --param "$PARAM" --out "$RUN")
  [[ "$SEND" -eq 1 ]] && PAYLOAD_ARGS+=(--send)
  "$CPF_SCRIPT_DIR/payload_run.sh" "${PAYLOAD_ARGS[@]}" > "$RUN/payload.log" 2>&1 || true
  PAYLOAD_NOTE="skill=$SKILL url=$URL log=$RUN/payload.log"
fi

"$(cpf_python)" - "$RUN" "$TARGET" "$PAYLOAD_NOTE" <<'PY'
import json, sys
from pathlib import Path

run, target, payload_note = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
def load(name, default):
    path = run / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default

ports = load("ports.json", {}).get("open_ports", [])
http = load("http.json", [])
components = load("components.json", {}).get("components", [])
findings = sorted(
    run.glob("*.findings.json"), key=lambda p: p.stat().st_mtime
)
findings = json.loads(findings[-1].read_text(encoding="utf-8")) if findings else []

lines = [
    f"# Offline scan summary: {target}",
    "",
    f"- open ports: {', '.join(str(item['port']) for item in ports) or 'none'}",
    f"- http services: {len([item for item in http if item.get('status')])}",
    f"- components: {len(components)}",
    f"- CVE candidates: {len(findings)}",
    f"- payload plan: {payload_note}",
    "",
    "## Components",
]
lines += [f"- {item.get('vendor') or ''} {item['product']} {item.get('version') or ''} "
          f"(port {item.get('port') or '-'}, source {item.get('source')})" for item in components] or ["- none"]
lines += ["", "## CVE candidates (unverified)"]
lines += [f"- {item.get('cve')} [{item.get('severity')}] conf={item.get('confidence')} {item.get('title')}"
          for item in findings] or ["- none"]
lines += ["", "Candidates require a template check, an authenticated version comparison, or a payload proof."]
(run / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
PY

log "cycle complete: $SUMMARY"
