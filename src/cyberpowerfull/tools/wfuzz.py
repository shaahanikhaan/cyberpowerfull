"""wfuzz wrapper: web fuzzing with a JSON report.

Flags verified against xmendez/wfuzz (``ui/console/common.py`` usage text
and ``plugins/printers/printers.py`` on main, 2026-11-11): the URL carries
the ``FUZZ`` keyword (or ``-u``), ``-w`` is an alias for ``-z file,``
(wordlist payload), ``-t`` sets concurrent connections (default 10),
``-X`` the HTTP method, ``-H`` a header (repeatable), ``-d`` post data,
``-b`` a cookie, ``--hc/hl/hw/hh`` hide and ``--sc/sl/sw/sh`` show
responses by code/lines/words/chars, and ``-f FILE,json`` writes a JSON
array of ``{chars, code, payload, lines, location, method, post_data,
server, url, words}`` (the printer defaults to ``raw`` when omitted, so
``json`` is always passed explicitly). The wordlist must be allowlisted
via ``scope.allowed_wordlists``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import Field, field_validator, model_validator

from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_METHOD = re.compile(r"^[A-Z]{3,8}$")
_HEADER = re.compile(r"^[^:\s][^:]*:\s*\S[^\r\n]*$")

#: Response-path extensions that turn a hit from INFO into LOW.
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


class WfuzzArgs(UrlInput):
    """Validated wfuzz invocation arguments."""

    wordlist: str = Field(min_length=1, max_length=500)
    method: str = Field(default="GET", max_length=8)
    headers: list[str] = Field(default_factory=list, max_length=8)
    hide_codes: list[int] = Field(default_factory=lambda: [404], max_length=20)
    show_codes: list[int] = Field(default_factory=list, max_length=20)
    threads: int = Field(default=10, ge=1, le=50)
    max_findings: int = Field(default=100, ge=1, le=500)

    @field_validator("method")
    @classmethod
    def _check_method(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not _METHOD.match(cleaned):
            raise ValueError(f"unsupported HTTP method: {value!r}")
        return cleaned

    @field_validator("headers")
    @classmethod
    def _check_headers(cls, values: list[str]) -> list[str]:
        for value in values:
            if len(value) > 300 or not _HEADER.match(value.strip()):
                raise ValueError(f"unsupported header (want 'Name: value'): {value!r}")
        return [value.strip() for value in values]

    @field_validator("hide_codes", "show_codes")
    @classmethod
    def _check_codes(cls, values: list[int]) -> list[int]:
        for code in values:
            if not 100 <= code <= 599:
                raise ValueError(f"unsupported status code: {code!r}")
        return values

    @model_validator(mode="after")
    def _check_fuzz_keyword(self) -> WfuzzArgs:
        if "FUZZ" not in self.target:
            raise ValueError("wfuzz target URL must contain the FUZZ keyword")
        return self


class WfuzzTool(BaseTool):
    name = "wfuzz"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "wfuzz"
    writes_output_file = True
    description = (
        "Web content fuzzing with JSON report. "
        "Sensitive backup/config/database hits are raised above INFO."
    )
    input_model = WfuzzArgs

    def build_argv(self, args: WfuzzArgs, out_file: str | None = None) -> list[str]:
        if out_file is None:
            raise InvalidToolArguments("wfuzz needs an output file for its JSON report")
        argv = [
            "wfuzz",
            "-w",
            args.wordlist,
            "-t",
            str(args.threads),
            "-X",
            args.method,
        ]
        for header in args.headers:
            argv.extend(["-H", header])
        if args.hide_codes:
            argv.extend(["--hc", ",".join(str(code) for code in args.hide_codes)])
        if args.show_codes:
            argv.extend(["--sc", ",".join(str(code) for code in args.show_codes)])
        argv.extend(["-f", f"{out_file},json", args.target])
        return argv

    def parse(self, args: WfuzzArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for result in _load_results(output):
            url = str(result.get("url") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
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
                        f"wfuzz code={result.get('code', '?')} "
                        f"payload={result.get('payload', '?')} "
                        f"chars={result.get('chars', '?')} "
                        f"words={result.get('words', '?')} "
                        f"lines={result.get('lines', '?')} "
                        f"location={result.get('location') or '-'} "
                        f"server={result.get('server') or '-'} "
                        f"method={result.get('method', '?')}"
                    ),
                    remediation=(
                        "Remove the backup/config copy from the web root or deny access to it."
                        if sensitive
                        else None
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: WfuzzArgs, output: str) -> list[str]:
        results = _load_results(output)
        codes: dict[str, int] = {}
        for result in results:
            key = str(result.get("code", "?"))
            codes[key] = codes.get(key, 0) + 1
        detail = ", ".join(f"{key}={codes[key]}" for key in sorted(codes))
        return [f"wfuzz: {len(results)} result(s) ({detail or 'none'})"]


def _load_results(output: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(output.strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(document, list):
        return []
    return [item for item in document if isinstance(item, dict)]


def _path_extension(url: str) -> str:
    path = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    if "." not in path:
        return ""
    return path.rsplit(".", 1)[-1].lower()


__all__ = ["WfuzzArgs", "WfuzzTool"]
