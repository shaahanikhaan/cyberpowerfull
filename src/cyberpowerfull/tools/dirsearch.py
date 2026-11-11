"""dirsearch wrapper: web path discovery with a JSON report.

Flags verified against maurosoria/dirsearch (``docs/options.md``,
``lib/parse/cmdline.py`` and ``lib/report/json_report.py`` on main,
2026-11-11): ``-u`` is the target URL, ``-w`` the wordlist, ``-e`` comma
separated extensions, ``-t`` threads (config default 25), ``-x`` comma
separated status codes/ranges to exclude (``301,500-599``), ``-r`` enables
recursion with ``--max-recursion-depth``, ``--timeout`` is the per-request
connection timeout, ``-O json -o FILE`` writes ``{info, results[]}`` where
each result carries ``url/status/contentLength/contentType/redirect``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import Field, field_validator, model_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_EXTENSION = re.compile(r"^[a-z0-9]{1,10}$")
_STATUS_CODE = re.compile(r"^(\d{3})(?:-(\d{3}))?$")

#: Response-body extensions that turn a hit from INFO into LOW.
_SENSITIVE_EXTENSIONS = frozenset(
    {
        "bak",
        "backup",
        "bkp",
        "conf",
        "config",
        "db",
        "dump",
        "env",
        "git",
        "gz",
        "inc",
        "key",
        "log",
        "old",
        "orig",
        "pem",
        "rar",
        "save",
        "sql",
        "sqlite",
        "swp",
        "tar",
        "tmp",
        "zip",
        "7z",
    }
)


class DirsearchArgs(UrlInput):
    """Validated dirsearch invocation arguments."""

    wordlist: str = Field(min_length=1, max_length=500)
    extensions: list[str] = Field(default_factory=list, max_length=10)
    threads: int = Field(default=25, ge=1, le=100)
    exclude_status: list[str] = Field(default_factory=list, max_length=10)
    request_timeout: float = Field(default=7.5, ge=0.5, le=120.0)
    recursive: bool = False
    max_recursion_depth: int = Field(default=3, ge=1, le=5)
    max_findings: int = Field(default=100, ge=1, le=500)

    @field_validator("extensions")
    @classmethod
    def _check_extensions(cls, values: list[str]) -> list[str]:
        lowered = [value.strip().lower().lstrip(".") for value in values]
        for value in lowered:
            if not _EXTENSION.match(value):
                raise ValueError(f"unsupported extension: {value!r}")
        return lowered

    @field_validator("exclude_status")
    @classmethod
    def _check_status(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            match = _STATUS_CODE.match(value.strip())
            if match is None:
                raise ValueError(f"unsupported status code or range: {value!r}")
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else start
            if not 100 <= start <= end <= 599:
                raise ValueError(f"unsupported status code or range: {value!r}")
            cleaned.append(value.strip())
        return cleaned

    @model_validator(mode="after")
    def _check_recursion(self) -> DirsearchArgs:
        if not self.recursive and self.max_recursion_depth != 3:
            raise ValueError("max_recursion_depth is only used with recursive=True")
        return self


class DirsearchTool(BaseTool):
    name = "dirsearch"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "dirsearch"
    writes_output_file = True
    description = (
        "Web path brute-forcing with JSON report. "
        "Sensitive backup/config/database hits are raised above INFO."
    )
    input_model = DirsearchArgs

    def build_argv(self, args: DirsearchArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "dirsearch",
            "-u",
            args.target,
            "-w",
            args.wordlist,
            "-t",
            str(args.threads),
            "--timeout",
            str(args.request_timeout),
            "--no-color",
            "-q",
        ]
        if args.extensions:
            argv.extend(["-e", ",".join(args.extensions)])
        if args.exclude_status:
            argv.extend(["-x", ",".join(args.exclude_status)])
        if args.recursive:
            argv.extend(["-r", "--max-recursion-depth", str(args.max_recursion_depth)])
        if out_file:
            argv.extend(["-O", "json", "-o", out_file])
        return argv

    def parse(self, args: DirsearchArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for result in _load_results(output):
            url = str(result.get("url") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            status = result.get("status", "?")
            sensitive = _path_extension(url) in _SENSITIVE_EXTENSIONS
            severity = Severity.LOW if sensitive else Severity.INFO
            findings.append(
                self.finding(
                    title=truncate(
                        f"{'Sensitive file exposure' if sensitive else 'Discovered path'}: {url}",
                        200,
                    ),
                    severity=severity,
                    confidence=0.8 if sensitive else 0.7,
                    target=args.target,
                    endpoint=url,
                    evidence=truncate(
                        f"dirsearch status={status} "
                        f"length={result.get('contentLength', '?')} "
                        f"type={result.get('contentType', '?')} "
                        f"redirect={result.get('redirect') or '-'}"
                    ),
                    remediation=(
                        "Remove the backup/config copy from the web root or " "deny access to it."
                        if sensitive
                        else None
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: DirsearchArgs, output: str) -> list[str]:
        results = _load_results(output)
        statuses: dict[str, int] = {}
        for result in results:
            key = str(result.get("status", "?"))
            statuses[key] = statuses.get(key, 0) + 1
        detail = ", ".join(f"{key}={statuses[key]}" for key in sorted(statuses))
        return [f"dirsearch: {len(results)} hit(s) ({detail or 'none'})"]


def _load_results(output: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(output.strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(document, dict):
        return []
    results = document.get("results")
    if not isinstance(results, list):
        return []
    return [item for item in results if isinstance(item, dict)]


def _path_extension(url: str) -> str:
    path = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    if "." not in path:
        return ""
    return path.rsplit(".", 1)[-1].lower()


__all__ = ["DirsearchArgs", "DirsearchTool"]
