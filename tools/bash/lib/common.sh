#!/usr/bin/env bash
# Shared helpers for the cyberpowerfull bash toolkit.
#
# Design rules:
#   * every script refuses to run without an explicit scope.json
#   * every target is gated by the Python scope engine, never by shell globbing
#   * nothing here needs the network; feeds and wordlists are local files
#
# Source this file:  . "$(dirname "$0")/lib/common.sh"

set -euo pipefail

CPF_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CPF_ARTIFACTS="${CPF_ARTIFACTS:-artifacts}"
CPF_INTEL_STORE="${CPF_INTEL_STORE:-intel/advisories.sqlite3}"

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

# Resolve the interpreter that can import the package.
cpf_python() {
  if [[ $# -gt 0 ]]; then
    die 'cpf_python takes no arguments; call "$(cpf_python)" -m cyberpowerfull ...'
  fi
  if [[ -n "${CPF_PYTHON:-}" ]]; then
    printf '%s\n' "$CPF_PYTHON"
    return 0
  fi
  local candidate
  for candidate in "./.venv/bin/python" "python3" "python"; do
    if command -v "$candidate" >/dev/null 2>&1 || [[ -x "$candidate" ]]; then
      if "$candidate" -c "import cyberpowerfull" >/dev/null 2>&1; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done
  die "cannot import cyberpowerfull; activate the venv or set CPF_PYTHON"
}

cpf_cli() {
  "$(cpf_python)" -m cyberpowerfull "$@"
}

# Convert a python expression-free JSON path query (key lookup only) to stdout.
cpf_json() {
  local file="$1" key="$2"
  "$(cpf_python)" - "$file" "$key" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
value = payload
for part in sys.argv[2].split("."):
    if part:
        value = value[part]
print(json.dumps(value) if isinstance(value, (dict, list)) else value)
PY
}

# Require --scope and verify it exists; echoes the path.
cpf_require_scope() {
  local scope="${1:-}"
  [[ -n "$scope" ]] || die "--scope scope.json is required (authorisation is mandatory)"
  [[ -f "$scope" ]] || die "scope file not found: $scope"
  printf '%s\n' "$scope"
}

# Verify a host is inside scope before doing anything to it.
cpf_assert_scope() {
  local scope="$1" host="$2"
  "$(cpf_python)" - "$scope" "$host" <<'PY'
import sys
from cyberpowerfull.scope import load_scope
scope = load_scope(sys.argv[1])
scope.require(sys.argv[2])
print(f"in scope: {sys.argv[2]}")
PY
}

# Print a compact, human-readable findings table from a JSON findings list.
cpf_findings_table() {
  local file="$1"
  "$(cpf_python)" - "$file" <<'PY'
import json, sys
items = json.load(open(sys.argv[1], encoding="utf-8"))
if isinstance(items, dict):
    items = items.get("findings", [])
if not items:
    print("no findings")
    raise SystemExit(0)
items.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.get("severity", "info"), 5))
print(f"{'severity':<9} {'cve':<16} {'conf':<5} title")
for f in items:
    print(f"{f.get('severity',''):<9} {f.get('cve') or '-':<16} {f.get('confidence', 0):<5} {(f.get('title') or '')[:70]}")
print(f"\n{len(items)} finding(s); candidates stay unverified until a check or proof confirms them")
PY
}

cpf_web_ports_json() {
  local ports_json="$1"
  "$(cpf_python)" - "$ports_json" <<'PY'
import json, sys
WEB = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443}
payload = json.load(open(sys.argv[1], encoding="utf-8"))
open_ports = [item["port"] for item in payload.get("open_ports", [])]
print(json.dumps([port for port in open_ports if port in WEB]))
PY
}
