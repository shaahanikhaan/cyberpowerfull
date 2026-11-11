"""droopescan wrapper: CMS fingerprinting with JSON output.

Flags verified against SamJoan/droopescan (``dscan/plugins/internal/scan.py``,
``dscan/common/enum.py`` and ``dscan/common/output.py`` on main, 2026-11-11):
``scan [cms]`` takes an optional CMS positional (``drupal``, ``joomla``,
``wordpress``, ``moodle``, ``silverstripe``; omitted it runs CMS
identification), ``-u`` the target URL, ``-o`` the output format
(``standard`` or ``json``), ``-e`` the checks (``a`` all, ``p`` plugins,
``t`` themes, ``v`` version, ``i`` interesting urls), ``-t`` threads
(default 4), ``--timeout`` the per-request timeout (default 45), and
``--hide-progressbar`` suppresses the progress bar. JSON mode prints one
object with ``version``/``plugins``/``themes``/``interesting urls``
sections of ``{is_empty, finds}`` — and prints nothing at all when empty
(``JsonOutput.result`` only prints when something was found). Version finds
are strings; plugin/theme finds are ``{url, name}``; interesting-url finds
are ``{url, description}``.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, json_lines, truncate

_CMS_NAMES = ("drupal", "joomla", "wordpress", "moodle", "silverstripe")

CmsName = Literal["drupal", "joomla", "wordpress", "moodle", "silverstripe"]
CheckSet = Literal["a", "p", "t", "v", "i"]


class DroopescanArgs(UrlInput):
    """Validated droopescan invocation arguments."""

    cms: CmsName | None = None
    checks: CheckSet = "a"
    threads: int = Field(default=4, ge=1, le=32)
    max_findings: int = Field(default=100, ge=1, le=500)


class DroopescanTool(BaseTool):
    name = "droopescan"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "droopescan"
    description = (
        "CMS fingerprinting (version, plugins, themes, interesting URLs) with JSON output."
    )
    input_model = DroopescanArgs

    def build_argv(self, args: DroopescanArgs, out_file: str | None = None) -> list[str]:
        argv = ["droopescan", "scan"]
        if args.cms:
            argv.append(args.cms)
        argv.extend(
            [
                "-u",
                args.target,
                "-o",
                "json",
                "-e",
                args.checks,
                "-t",
                str(args.threads),
                "--timeout",
                "45",
                "--hide-progressbar",
            ]
        )
        return argv

    def parse(
        self, args: DroopescanArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        document = _load_document(output)
        if document is None:
            return []
        host = str(document.get("host") or document.get("cms_name") or args.target)
        findings: list[Finding] = []
        versions = [str(item) for item in _finds(document, "version") if str(item).strip()]
        if versions:
            findings.append(
                self.finding(
                    title=truncate(f"CMS version identified: {', '.join(versions)}", 200),
                    severity=Severity.INFO,
                    confidence=0.8,
                    target=args.target,
                    endpoint=host,
                    evidence=truncate(f"droopescan versions={','.join(versions)}"),
                )
            )
        for section, singular in (("plugins", "plugin"), ("themes", "theme")):
            for item in _finds(document, section):
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                url = str(item.get("url") or "").strip()
                if not name and not url:
                    continue
                findings.append(
                    self.finding(
                        title=truncate(f"CMS {singular} detected: {name or url}", 200),
                        severity=Severity.INFO,
                        confidence=0.75,
                        target=args.target,
                        endpoint=url or host,
                        evidence=truncate(f"droopescan {singular}={name or '?'} url={url or '-'}"),
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings
        for item in _finds(document, "interesting urls"):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            description = str(item.get("description") or "").strip()
            findings.append(
                self.finding(
                    title=truncate(f"Interesting URL exposed: {url}", 200),
                    severity=Severity.LOW,
                    confidence=0.75,
                    target=args.target,
                    endpoint=url,
                    evidence=truncate(f"droopescan interesting_url={url} {description}".rstrip()),
                    remediation=(
                        "Remove the exposed file or restrict access to the admin interface."
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                return findings
        return findings

    def observations(self, args: DroopescanArgs, output: str) -> list[str]:
        if not output.strip():
            return ["droopescan: nothing found (empty output)"]
        if "not identified as a supported CMS" in output:
            return ["droopescan: host not identified as a supported CMS"]
        document = _load_document(output)
        if document is None:
            return ["droopescan: no machine-readable output (scan error or fatal)"]
        counts = {section: len(_finds(document, section)) for section in _SECTIONS}
        detail = ", ".join(f"{section}={counts[section]}" for section in _SECTIONS)
        note = f"droopescan: {detail}"
        cms_name = document.get("cms_name")
        if cms_name:
            note += f" cms={cms_name}"
        return [note]


_SECTIONS = ("version", "plugins", "themes", "interesting urls")


def _load_document(output: str) -> dict[str, Any] | None:
    text = output.strip()
    if not text:
        return None
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        document = None
    if isinstance(document, dict):
        return document
    for record in json_lines(text):
        return record
    return None


def _finds(document: dict[str, Any], section: str) -> list[Any]:
    block = document.get(section)
    if not isinstance(block, dict):
        return []
    finds = block.get("finds")
    if not isinstance(finds, list):
        return []
    return finds


__all__ = ["DroopescanArgs", "DroopescanTool"]
