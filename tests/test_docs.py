"""Documentation and repository-hygiene checks.

These tests encode the acceptance criteria that are about the repository itself:
no hype in the README, the documented commands exist, required files are present,
and the CI configuration really runs the checks it claims.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
README_HEAD = "\n".join(README.splitlines()[:10])

HYPE_TERMS = [
    "1000009",
    "1000000*",
    "self-trained",
    "beyond hacker",
    "beyond openai",
    "hacker ai",
    "openai cyber",
    "hummwin",
    "10* powerfull",
]

SKILL_NAMES = [
    "authentication_jwt",
    "idor",
    "sql_injection",
    "xss",
    "ssrf",
    "csrf",
    "xxe",
    "rce",
    "business_logic",
    "race_conditions",
    "path_traversal",
    "open_redirect",
    "mass_assignment",
    "file_uploads",
    "information_disclosure",
    "subdomain_takeover",
    "subdomain_enum",
    "network_services",
    "tls_hardening",
    "api_security",
    "graphql",
    "deserialization",
    "cms_wordpress",
    "cloud_metadata",
    "active_directory",
    "container_kubernetes",
    "credential_testing",
    "exploit_availability",
    "external_validation",
]

TOOL_NAMES = [
    "tcp_probe",
    "http_probe",
    "payload",
    "cve_correlate",
    "subfinder",
    "amass",
    "dnsrecon",
    "httpx",
    "katana",
    "wafw00f",
    "nmap",
    "masscan",
    "naabu",
    "whatweb",
    "nikto",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "arjun",
    "testssl",
    "wpscan",
    "nuclei",
    "sqlmap",
    "dalfox",
    "searchsploit",
    "hydra",
    "strix",
    "pentagi",
    "sn1per",
]


class TestReadme:
    def test_first_lines_state_what_what_and_why(self) -> None:
        head = README_HEAD.lower()
        assert "local-only" in head
        assert "penetration-testing agent" in head
        assert "recon" in head and "validation" in head and "reporting" in head
        assert "no cloud api key" in head
        assert "no docker" in head
        assert "chatbot" in head

    def test_required_sections_present(self) -> None:
        for heading in (
            "## Safety & Scope",
            "## Architecture",
            "## Quick Start",
            "## Supported Tools",
            "## Skills",
            "## Automation playbooks",
            "## External agents: Strix, PentAGI, Sn1per",
            "## Host toolchain and local knowledge",
            "## How the agent behaves",
            "## Development",
            "## License",
        ):
            assert heading in README, heading

    def test_safety_section_is_above_architecture(self) -> None:
        assert README.index("## Safety & Scope") < README.index("## Architecture")

    def test_quick_start_is_a_runnable_loopback_lab(self) -> None:
        start = README.index("## Quick Start")
        end = README.index("### Use a local model", start)
        quickstart = README[start:end]
        assert "python -m pip install -e ." in quickstart
        assert "python -m http.server 8000 --bind 127.0.0.1" in quickstart
        assert "--target 127.0.0.1 --llm replay:examples/decisions.json" in quickstart
        assert "cyberpowerfull --replay traces/latest.json" in quickstart
        assert "--target example.com" not in quickstart

    def test_badges(self) -> None:
        assert "badge.svg" in README
        assert "version-5.0.1" in README
        assert "actions/workflows/ci.yml/badge.svg" in README

    @pytest.mark.parametrize("term", HYPE_TERMS)
    def test_no_hype_terms(self, term: str) -> None:
        assert term not in README.lower()

    @pytest.mark.parametrize("skill", SKILL_NAMES)
    def test_skill_table_lists_every_pack(self, skill: str) -> None:
        assert f"`{skill}`" in README

    @pytest.mark.parametrize("tool", TOOL_NAMES)
    def test_tool_table_lists_every_wrapper(self, tool: str) -> None:
        assert f"`{tool}`" in README

    def test_tool_table_documents_schema_and_status(self) -> None:
        table = README[README.index("## Supported Tools") : README.index("## Skills")]
        assert "Input schema" in table
        assert "Output format" in table
        assert "Status" in table
        assert "tested" in table

    def test_no_empty_marketing_sections(self) -> None:
        assert "**POWERFULL**" not in README


class TestRepositoryFiles:
    def test_license_is_mit(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        assert license_text.startswith("MIT License")
        assert "WITHOUT WARRANTY" in license_text

    def test_security_policy_exists(self) -> None:
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        assert "authorized" in security.lower()
        assert "scope.json" in security
        assert "Report a vulnerability" in security

    def test_changelog_has_hard_fork_entry(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "Pentest-Only Hard Fork" in changelog
        assert "Readiness and Safety Hardening" in changelog
        for section in ("### Added", "### Changed", "### Removed"):
            assert section in changelog

    def test_scope_files_are_valid_json(self) -> None:
        for name in ("scope.json", "scope.example.json"):
            payload = json.loads((ROOT / name).read_text(encoding="utf-8"))
            assert payload["authorized"] is (name == "scope.json")
            assert payload["targets"]

    def test_example_replay_stream_matches_decision_contract(self) -> None:
        payload = json.loads((ROOT / "examples" / "decisions.json").read_text(encoding="utf-8"))
        from cyberpowerfull.models import Decision

        for entry in payload["decisions"]:
            Decision.model_validate(entry)
        assert payload["decisions"][-1]["tool"] == "terminate"

    def test_example_trace_is_schema_valid(self) -> None:
        from cyberpowerfull.trace import Trace

        trace = Trace.model_validate(
            json.loads((ROOT / "examples" / "trace-example.json").read_text(encoding="utf-8"))
        )
        assert trace.schema_version == "1.0"
        assert trace.steps and trace.findings
        assert all(step.result is not None for step in trace.steps if step.tool)
        assert trace.scope_fingerprint


class TestTooling:
    def test_pytest_coverage_gate_configured(self) -> None:
        # The gate lives in `make test` and CI, not in addopts: a plain `pytest`
        # must work with only pytest installed (no pytest-cov plugin required).
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        addopts = next(line for line in pyproject.splitlines() if "addopts" in line)
        assert "--cov" not in addopts
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        assert "--cov=cyberpowerfull" in makefile
        assert "--cov-fail-under=70" in makefile

    def test_ruff_and_black_configured(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "[tool.ruff]" in pyproject
        assert "[tool.black]" in pyproject

    def test_ci_runs_lint_format_and_tests(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        assert "ruff check ." in workflow
        assert "black --check ." in workflow
        assert "pytest --cov" in workflow
        assert "replay:examples/decisions.json" in workflow

    def test_pre_commit_hooks(self) -> None:
        config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        assert "ruff" in config
        assert "black" in config
        assert "trailing-whitespace" in config

    def test_gitignore_excludes_run_artifacts(self) -> None:
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for entry in ("artifacts/", "traces/", "*.sqlite3", ".venv/"):
            assert entry in ignore
