#!/usr/bin/env bash
# The one command.
#
#   ./run.sh TARGET                  install once, then scan + write a report
#   ./run.sh TARGET --profile deep    longer, wider pass
#   ./run.sh TARGET --plan            show what it would do, send nothing
#   ./run.sh --lab                    real loopback lab, no target and no setup
#   ./run.sh --doctor                 what this host can run
#   ./run.sh --install-tools          apt-get the scanner set (Debian/Kali, asks first)
#   ./run.sh --setup                  prepare the Python environment only
#
# Anything else is passed straight through to cyberpowerfull/cpf.
# This wrapper never touches scope.json, never runs sudo on its own, and never bypasses
# the authorization gate: the target still has to be attested, once, in the terminal.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${CYBERPOWERFULL_VENV:-$ROOT/.venv}"
PYTHON_BIN="${PYTHON:-python3}"

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
}

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  --install-tools)
    exec "$ROOT/scripts/install.sh" --with-tools "${@:2}"
    ;;
  --setup)
    exec "$ROOT/scripts/install.sh" "${@:2}"
    ;;
esac

if [[ ! -x "$VENV/bin/cpf" ]]; then
  command -v "$PYTHON_BIN" >/dev/null 2>&1 ||
    die "python3 not found; install Python 3.10+ (Kali/Debian: sudo apt install python3 python3-venv)"
  "$PYTHON_BIN" - <<'PY' || die "Python 3.10 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
  say "first run: creating $VENV and installing cyberpowerfull (pydantic + jinja2 only)"
  "$PYTHON_BIN" -m venv "$VENV"
  "$VENV/bin/python" -m pip --quiet install --upgrade pip
  "$VENV/bin/python" -m pip --quiet install -e "$ROOT" ||
    die "install failed; run ./run.sh --setup for the verbose path"
  say "ready: $("$VENV/bin/cpf" --version)"
fi

exec "$VENV/bin/cpf" "$@"
