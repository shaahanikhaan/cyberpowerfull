"""sherlock wrapper: username presence checks across social sites (CSV output).

Flags verified against sherlock-project/sherlock
(``sherlock_project/sherlock.py`` on main, 2026-11-11): note ``--json`` is
an INPUT (site data), not results output. Results land in
``{username}.csv`` (forced filename; ``--folderoutput`` picks the
directory) with header ``username,name,url_main,url_user,exists,
http_status,response_time_s``; ``exists`` is a ``QueryStatus`` value
(``Claimed/Available/Unknown/Illegal/WAF``) and ``--print-found`` filters
the CSV to claimed rows. ``--local`` uses the bundled site list instead
of fetching it (deterministic), ``--nsfw`` includes NSFW sites,
``--timeout`` bounds each request (default 60s). All checks hit
third-party sites: the worker requires ``allow_passive_sources``.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

from pydantic import Field, field_validator

from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, ToolInput, truncate

#: Usernames sherlock accepts; no slashes, no leading dash (argv + filename safety).
_USERNAME = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.\-]{0,38}$")


class SherlockArgs(ToolInput):
    """Validated sherlock invocation arguments (target is a username)."""

    timeout: int = Field(default=60, ge=5, le=300)
    local_data: bool = True
    include_nsfw: bool = False
    max_findings: int = Field(default=100, ge=1, le=500)

    @field_validator("target")
    @classmethod
    def _check_username(cls, value: str) -> str:
        cleaned = value.strip()
        if not _USERNAME.match(cleaned):
            raise ValueError("sherlock target must be a plain username")
        return cleaned


class SherlockTool(BaseTool):
    name = "sherlock"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = "sherlock"
    passive_lookup = True
    writes_output_file = True
    timeout_s = 600
    description = (
        "Username presence checks across social and dev sites. "
        "Third-party queries: needs allow_passive_sources."
    )
    input_model = SherlockArgs

    def build_argv(self, args: SherlockArgs, out_file: str | None = None) -> list[str]:
        if out_file is None:
            raise InvalidToolArguments("sherlock needs an output file to locate its results folder")
        folder = str(Path(out_file).parent)
        argv = [
            "sherlock",
            args.target,
            "--csv",
            "--print-found",
            "--no-color",
            "--timeout",
            str(args.timeout),
            "--folderoutput",
            folder,
        ]
        if args.local_data:
            argv.append("--local")
        if args.include_nsfw:
            argv.append("--nsfw")
        return argv

    def parse(self, args: SherlockArgs, output: str, out_file: str | None = None) -> list[Finding]:
        text = _csv_text(args, output, out_file)
        findings: list[Finding] = []
        seen: set[str] = set()
        try:
            rows = csv.DictReader(io.StringIO(text))
            for row in rows:
                if (row.get("exists") or "").strip() != "Claimed":
                    continue
                site = (row.get("name") or "").strip()
                url = (row.get("url_user") or "").strip()
                if not site or not url or site in seen:
                    continue
                seen.add(site)
                findings.append(
                    self.finding(
                        title=f"Username found: {site}",
                        severity=Severity.INFO,
                        confidence=0.75,
                        target=args.target,
                        endpoint=url,
                        evidence=truncate(
                            f"sherlock site={site} url={url} "
                            f"http_status={row.get('http_status', '?')} "
                            f"response_time_s={row.get('response_time_s', '?')}"
                        ),
                    )
                )
                if len(findings) >= args.max_findings:
                    break
        except (csv.Error, ValueError):
            return findings
        return findings

    def observations(self, args: SherlockArgs, output: str) -> list[str]:
        # Live runs hand console text here (the CSV sibling is only visible
        # to parse(), which receives out_file); count rows only for an actual
        # report, identified by its fixed header.
        if not output.lstrip().startswith("username,"):
            return ["sherlock: results written to the run folder"]
        try:
            rows = list(csv.DictReader(io.StringIO(output)))
        except (csv.Error, ValueError):
            return ["sherlock: output was not a CSV report"]
        claimed = sum(1 for row in rows if (row.get("exists") or "").strip() == "Claimed")
        return [f"sherlock: {claimed} claimed site(s) out of {len(rows)} row(s)"]


def _csv_text(args: SherlockArgs, output: str, out_file: str | None) -> str:
    if out_file:
        sibling = Path(out_file).parent / f"{args.target}.csv"
        try:
            if sibling.is_file():
                return sibling.read_text(encoding="utf-8")
        except OSError:
            pass
    return output


__all__ = ["SherlockArgs", "SherlockTool"]
