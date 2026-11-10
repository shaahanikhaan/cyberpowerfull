#!/usr/bin/env bash
# One-shot setup for cyberpowerfull.
#
#   ./scripts/install.sh              # venv + package, then a real loopback lab run
#   ./scripts/install.sh --with-tools # also apt-install the scanner set (Debian/Kali)
#   ./scripts/install.sh --dev        # also install ruff/black/pytest/pre-commit
#
# The script never edits scope.json, never runs sudo on its own, and never
# bypasses the authorization gate: it only prepares the Python environment and
# prints the two commands that come next.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WITH_TOOLS=0
DEV=1
VENV_DIR="${CYBERPOWERFULL_VENV:-.venv}"

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-tools) WITH_TOOLS=1 ;;
    --dev) DEV=1 ;;
    --no-dev) DEV=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m !\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# -- python ----------------------------------------------------------------
PYTHON_BIN="${PYTHON:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "python3 not found; install Python 3.10+ first"
"$PYTHON_BIN" - <<'PY' || die "Python 3.10 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
say "$("$PYTHON_BIN" -V) at $(command -v "$PYTHON_BIN")"

# -- venv ------------------------------------------------------------------
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  say "creating virtualenv in $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
else
  say "reusing virtualenv in $VENV_DIR"
fi

say "installing the package (this pulls pydantic + jinja2 only)"
"$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
if [[ "$DEV" -eq 1 ]]; then
  "$VENV_DIR/bin/python" -m pip install -e ".[dev]"
else
  "$VENV_DIR/bin/python" -m pip install -e .
fi

# -- optional scanner set --------------------------------------------------
if [[ "$WITH_TOOLS" -eq 1 ]]; then
  command -v apt-get >/dev/null 2>&1 || die "--with-tools needs apt-get (Debian/Kali)"
  warn "about to apt-get install the scanner set; review the list in the Makefile"
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    APT=(apt-get); NUCLEI_SUDO=()
  else
    APT=(sudo apt-get); NUCLEI_SUDO=(sudo)
  fi
  "${APT[@]}" update
  "${APT[@]}" install -y nmap masscan naabu subfinder amass dnsrecon httpx-toolkit \
    katana ffuf gobuster feroxbuster whatweb wafw00f nikto nuclei sqlmap dalfox \
    arjun wpscan testssl.sh hydra exploitdb wordlists seclists \
    || warn "some packages were unavailable; the agent will report them as missing"
  if command -v nuclei >/dev/null 2>&1; then
    "${NUCLEI_SUDO[@]}" nuclei -update-templates || warn "nuclei template update failed"
  fi
fi

# -- verify ----------------------------------------------------------------
say "installed: $("$VENV_DIR/bin/cyberpowerfull" --version)"
say "tools: $("$VENV_DIR/bin/cyberpowerfull" --toolchain | head -1)"

cat <<EOF

Ready. The shortest path:

  ./run.sh TARGET                 # install once, then scan + report (asks you to attest)

See it work with nothing to configure:

  ./run.sh --lab                  # real loopback service, scanned end to end
  ./run.sh --doctor               # what this host can run

Write a scope by hand instead of attesting at the prompt:

  $VENV_DIR/bin/cyberpowerfull --init-scope scope.json \\
      --engagement NAME --targets HOST \\
      --authorize --authorization-ref REF

Then: $VENV_DIR/bin/cyberpowerfull --scope scope.json --target HOST --playbook full

Optional model (the reasoning loop; playbooks do not need it):

  ollama serve & ollama pull qwen3:4b
  $VENV_DIR/bin/cyberpowerfull --scope scope.json --target HOST --llm ollama:qwen3:4b

Assets you are not authorized to test are out of scope. See SECURITY.md.
EOF
