"""ffuf wrapper: content and path discovery with JSON file output."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_WORDLIST_RE = re.compile(r"^[A-Za-z0-9_\-./~]{1,400}$")
_EXT_RE = re.compile(r"^[A-Za-z0-9]{1,10}$")


class FfufArgs(UrlInput):
    """Validated ffuf invocation arguments. ``target`` must contain ``FUZZ``."""

    wordlist: str
    method: Literal["GET", "POST", "HEAD"] = "GET"
    extensions: list[str] = Field(default_factory=list, max_length=10)
    match_codes: list[int] = Field(default_factory=lambda: [200, 204, 301, 302, 401, 403])
    threads: int = Field(default=40, ge=1, le=100)
    max_results: int = Field(default=100, ge=1, le=1000)

    @field_validator("wordlist")
    @classmethod
    def _check_wordlist(cls, value: str) -> str:
        if not _WORDLIST_RE.match(value) or ".." in value:
            raise ValueError("wordlist must be a plain filesystem path")
        return value

    @field_validator("extensions")
    @classmethod
    def _check_extensions(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _EXT_RE.match(value):
                raise ValueError(f"invalid extension: {value!r}")
        return values


class FfufTool(BaseTool):
    name = "ffuf"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "ffuf"
    writes_output_file = True
    success_codes = (0, 1)
    description = (
        "Content discovery: fuzzes a URL containing the FUZZ keyword against a local "
        "wordlist and reports discovered paths with status codes."
    )
    input_model = FfufArgs

    def build_argv(self, args: FfufArgs, out_file: str | None = None) -> list[str]:
        if "FUZZ" not in args.target:
            raise InvalidToolArguments("ffuf target must contain the FUZZ keyword")
        if not Path(args.wordlist).is_file():
            raise InvalidToolArguments(f"wordlist not found: {args.wordlist}")
        argv = [
            "ffuf",
            "-u",
            args.target,
            "-w",
            args.wordlist,
            "-of",
            "json",
            "-o",
            out_file or "-",
            "-mc",
            ",".join(str(code) for code in args.match_codes),
            "-t",
            str(args.threads),
            "-s",
            "-X",
            args.method,
        ]
        if args.extensions:
            argv.extend(["-e", ",".join(f".{ext.lstrip('.')}" for ext in args.extensions)])
        return argv

    def parse(self, args: FfufArgs, output: str, out_file: str | None = None) -> list[Finding]:
        if not output.strip():
            return []
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return []
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list):
            return []
        findings: list[Finding] = []
        for item in results[: args.max_results]:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "")
            status = item.get("status")
            length = item.get("length")
            words = item.get("words")
            if status in (401, 403):
                severity = Severity.LOW
                title = f"Access-controlled path discovered (HTTP {status})"
            elif status in (200, 204):
                severity = Severity.INFO
                title = f"Discovered content (HTTP {status})"
            else:
                severity = Severity.INFO
                title = f"Discovered redirect or alternate response (HTTP {status})"
            findings.append(
                self.finding(
                    title=title,
                    severity=severity,
                    confidence=0.7,
                    target=args.target,
                    endpoint=url,
                    evidence=truncate(
                        f"url={url} status={status} length={length} words={words} "
                        f"input={item.get('input')}"
                    ),
                )
            )
        return findings

    def observations(self, args: FfufArgs, output: str) -> list[str]:
        try:
            payload = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return ["ffuf output was not valid JSON"]
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list):
            return ["ffuf: no results"]
        return [f"ffuf: {len(results)} result(s) for {args.target}"]


__all__ = ["FfufArgs", "FfufTool"]
