"""Repository hygiene: the docs, templates, and workflows a maintainer relies on.

These tests exist because a professional repository is part of the product: a broken
link or a release workflow that cannot build is a defect, not cosmetics.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "AGENTS.md",
    "LICENSE",
    "Makefile",
    "pyproject.toml",
    "docs/README.md",
    "docs/GUIDE.md",
    "docs/HANDOFF.md",
    "docs/ROADMAP.md",
    "docs/KALI.md",
    "docs/INTEGRATIONS.md",
    "docs/readiness-audit.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/dependabot.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/codeql.yml",
    "scripts/install.sh",
    "scripts/release_check.py",
    ".editorconfig",
    ".github/CODEOWNERS",
]

#: Documents whose relative links must resolve. Templates are excluded because they
#: use placeholders; issue forms contain no markdown links.
LINKED_DOCS = [
    "README.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "Makefile".replace("Makefile", "docs/README.md"),
    "docs/GUIDE.md",
    "docs/HANDOFF.md",
    "docs/ROADMAP.md",
    "docs/KALI.md",
    "docs/INTEGRATIONS.md",
]

_MD_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _anchor(text: str) -> str:
    """GitHub-style heading slug: strip punctuation, spaces become single dashes."""
    cleaned = re.sub(r"[^\w\s-]", "", text.strip().lower())
    return re.sub(r"\s", "-", cleaned)


GUIDE = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")


def _load_yaml(path: Path):
    yaml = pytest.importorskip("yaml", reason="PyYAML is not installed")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class TestCommunityFiles:
    @pytest.mark.parametrize("name", REQUIRED_FILES)
    def test_file_exists(self, name: str) -> None:
        assert (ROOT / name).is_file(), f"{name} is missing"

    def test_issue_forms_are_valid_yaml_with_required_fields(self) -> None:
        for name in ("bug_report.yml", "feature_request.yml"):
            data = _load_yaml(ROOT / ".github" / "ISSUE_TEMPLATE" / name)
            assert data["name"] and data["description"], name
            ids = [item.get("id") for item in data["body"] if item.get("id")]
            assert len(ids) == len(set(ids)), f"{name}: duplicate field ids"
            assert any(item.get("validations", {}).get("required") for item in data["body"])

    def test_issue_config_points_at_real_docs(self) -> None:
        data = _load_yaml(ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml")
        assert data["blank_issues_enabled"] is False
        assert data["contact_links"]
        for link in data["contact_links"]:
            assert link["url"].startswith("https://")
            assert link["about"]

    def test_pr_template_states_the_safety_checklist(self) -> None:
        body = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
        assert "scope gate" in body
        assert "capability gate" in body
        assert "make lint" in body and "make test" in body

    def test_dependabot_covers_pip_and_actions(self) -> None:
        data = _load_yaml(ROOT / ".github" / "dependabot.yml")
        ecosystems = {entry["package-ecosystem"] for entry in data["updates"]}
        assert ecosystems == {"pip", "github-actions"}
        assert all(entry.get("schedule", {}).get("interval") for entry in data["updates"])


class TestWorkflows:
    def test_release_workflow_builds_and_publishes_on_tags(self) -> None:
        data = _load_yaml(ROOT / ".github" / "workflows" / "release.yml")
        triggers = data[True] if True in data else data["on"]
        assert triggers["push"]["tags"] == ["v*"]
        script = "\n".join(
            step.get("run", "") for job in data["jobs"].values() for step in job["steps"]
        )
        assert "python -m build" in script
        assert "sha256sum" in script
        assert "gh release create" in script
        assert "does not match package version" in script
        assert data["permissions"]["contents"] == "write"

    def test_release_workflow_jobs_are_ordered(self) -> None:
        data = _load_yaml(ROOT / ".github" / "workflows" / "release.yml")
        assert data["jobs"]["publish"]["needs"] == "build"

    def test_codeql_workflow_scans_python(self) -> None:
        data = _load_yaml(ROOT / ".github" / "workflows" / "codeql.yml")
        assert data["permissions"]["security-events"] == "write"
        script = "\n".join(str(step) for job in data["jobs"].values() for step in job["steps"])
        assert "codeql-action/init" in script and "codeql-action/analyze" in script
        assert "python" in script

    def test_release_check_script_is_wired_everywhere(self) -> None:
        script = ROOT / "scripts" / "release_check.py"
        assert script.is_file() and script.stat().st_mode & 0o111
        makefile = (ROOT / "Makefile").read_text()
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        assert "scripts/release_check.py" in makefile
        assert "scripts/release_check.py" in release

    def test_codeowners_covers_the_guardrails(self) -> None:
        owners = (ROOT / ".github" / "CODEOWNERS").read_text()
        for path in ("/src/cyberpowerfull/scope.py", "/.github/workflows/", "/SECURITY.md"):
            assert path in owners, path

    def test_ci_keeps_the_quality_gates(self) -> None:
        body = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for needle in ("ruff check .", "black --check .", "--cov-fail-under=70", "--lab"):
            assert needle in body, needle


class TestDocsLinks:
    @pytest.mark.parametrize("doc", LINKED_DOCS)
    def test_relative_links_resolve(self, doc: str) -> None:
        path = ROOT / doc
        text = path.read_text(encoding="utf-8")
        broken: list[str] = []
        for target in _MD_LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            clean = target.split("#", 1)[0].strip()
            if not clean:
                continue
            resolved = (path.parent / clean).resolve()
            if not resolved.exists():
                broken.append(target)
        assert not broken, f"{doc} has broken links: {broken}"

    @pytest.mark.parametrize("doc", LINKED_DOCS)
    def test_heading_anchors_resolve(self, doc: str) -> None:
        path = ROOT / doc
        text = path.read_text(encoding="utf-8")
        broken: list[str] = []
        for target in _MD_LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")) or "#" not in target:
                continue
            relative, _, anchor = target.partition("#")
            if not anchor:
                continue
            destination = (path.parent / relative).resolve() if relative else path
            if not destination.is_file():
                broken.append(target)
                continue
            headings = {
                _anchor(line.lstrip("#"))
                for line in destination.read_text(encoding="utf-8").splitlines()
                if line.startswith("#")
            }
            if anchor not in headings:
                broken.append(target)
        assert not broken, f"{doc} has broken anchors: {broken}"

    def test_readme_links_the_documentation_set(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for target in (
            "docs/GUIDE.md",
            "docs/HANDOFF.md",
            "docs/ROADMAP.md",
            "CONTRIBUTING.md",
            "AGENTS.md",
            "docs/README.md",
        ):
            assert target in readme, target

    def test_docs_index_lists_every_document(self) -> None:
        index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
        for name in ("GUIDE.md", "HANDOFF.md", "ROADMAP.md", "KALI.md", "INTEGRATIONS.md"):
            assert name in index, name


class TestHandoffAndRoadmap:
    def test_handoff_records_the_invariants_and_gotchas(self) -> None:
        text = (ROOT / "docs" / "HANDOFF.md").read_text(encoding="utf-8")
        for needle in (
            "No scope, no run",
            "Per-call scope re-validation",
            "Capability gate before argv",
            "Loopback-only inference",
            "Append-only memory",
            "Exit-code contract",
            "SQLite is thread-bound",
            "Release checklist",
        ):
            assert needle in text, needle

    def test_handoff_module_map_matches_the_source_tree(self) -> None:
        text = (ROOT / "docs" / "HANDOFF.md").read_text(encoding="utf-8")
        package = ROOT / "src" / "cyberpowerfull"
        for module in ("cli.py", "lab.py", "playbook.py", "inventory.py", "scope.py", "trace.py"):
            assert (package / module).is_file()
            assert module in text, f"{module} missing from the handoff map"

    def test_roadmap_has_shipped_and_next_sections(self) -> None:
        text = (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8")
        assert "## Shipped" in text
        assert "## Next" in text
        assert "Acceptance" in text or "acceptance" in text
        assert "3.1.0" in text, "the roadmap must record what already shipped"
        assert "out of scope" in text.lower()

    def test_agents_file_points_at_the_three_documents(self) -> None:
        text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        assert "docs/HANDOFF.md" in text
        assert "docs/ROADMAP.md" in text
        assert "docs/GUIDE.md" in text
        assert "make lab" in text
        assert "invariants" in text.lower()


class TestUserGuide:
    @pytest.mark.parametrize(
        "command",
        [
            "make setup",
            "make lab",
            "make doctor",
            "make tools",
            "--init-scope",
            "--playbook",
            "--toolchain",
            "--replay",
            "--dry-run",
            "--render-prompt",
            "--agents",
        ],
    )
    def test_guide_documents_every_user_facing_command(self, command: str) -> None:
        assert command in GUIDE, command

    def test_guide_covers_exit_codes_and_troubleshooting(self) -> None:
        assert "## 10. Troubleshooting" in GUIDE
        for code in ("3", "4", "5", "6", "7", "8"):
            assert f"exit `{code}`" in GUIDE, code

    def test_guide_warns_about_artifacts_and_authorization(self) -> None:
        assert "authorized" in GUIDE.lower()
        assert "artifacts/" in GUIDE
        assert "confidential" in GUIDE.lower()
