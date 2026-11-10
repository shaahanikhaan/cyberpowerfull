# Convenience entry points. `make` with no target prints this list.
#
# Everything here is a thin wrapper over documented commands: no target does
# anything the CLI cannot do, and none of them bypass scope checks.

PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
CLI := $(BIN)/cyberpowerfull
PORT ?=

.DEFAULT_GOAL := help
.PHONY: help setup install install-dev lab doctor toolchain tools test lint fmt clean

help: ## show this help
	@printf 'cyberpowerfull\n\nusage: make <target>\n\n'
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@printf '\nfirst run: make setup && make lab\n'

setup: install-dev ## create the venv, install dev deps, print readiness
	@$(BIN)/python -c "import cyberpowerfull; print('cyberpowerfull', cyberpowerfull.__version__)"
	@echo ""
	@echo "next: make lab        # real loopback lab, no model needed"
	@echo "      make doctor     # what this host can actually run"

install: ## create the venv and install the package (runtime only)
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e .

install-dev: ## create the venv and install the package with dev tools
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e ".[dev]"

lab: ## serve a real page on 127.0.0.1:8080 and scan it (no model, no binaries)
	$(CLI) --lab $(if $(PORT),--lab-port $(PORT),)

doctor: ## readiness check against the bundled loopback scope
	$(CLI) --doctor --scope scope.json

toolchain: ## live inventory of binaries, wordlists, templates on this host
	$(CLI) --toolchain

tools: ## install the scanner set on Debian/Kali (needs sudo; review first)
	@echo "installing: nmap masscan naabu subfinder amass dnsrecon httpx-toolkit katana \\"
	@echo "  ffuf gobuster feroxbuster whatweb wafw00f nikto nuclei sqlmap dalfox arjun \\"
	@echo "  wpscan testssl.sh hydra exploitdb wordlists seclists"
	sudo apt-get update
	sudo apt-get install -y nmap masscan naabu subfinder amass dnsrecon httpx-toolkit \
		katana ffuf gobuster feroxbuster whatweb wafw00f nikto nuclei sqlmap dalfox \
		arjun wpscan testssl.sh hydra exploitdb wordlists seclists
	@echo "then: sudo nuclei -update-templates"

test: ## run the test suite with the coverage gate
	$(BIN)/python -m pytest

lint: ## ruff + black, non-mutating
	$(BIN)/ruff check .
	$(BIN)/black --check .

fmt: ## apply ruff fixes and black formatting
	$(BIN)/ruff check . --fix
	$(BIN)/black .

clean: ## remove run artefacts (traces, reports, local memory)
	rm -rf traces artifacts strix_runs
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
