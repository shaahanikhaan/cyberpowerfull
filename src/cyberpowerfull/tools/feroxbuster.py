"""feroxbuster wrapper: recursive content discovery with JSONL output."""

from __future__ import annotations

import re

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, json_lines, truncate

_INTERESTING = re.compile(
    r"(\.git|\.env|admin|api|backup|config|debug|internal|private|swagger|graphql|actuator)",
    re.IGNORECASE,
)
_WORDLIST_RE = re.compile(r"^[A-Za-z0-9_\-./~]{1,400}$")


class FeroxbusterArgs(UrlInput):
    """Validated feroxbuster invocation arguments."""

    wordlist: str | None = Field(default=None, max_length=400)
    depth: int = Field(default=2, ge=1, le=4)
    threads: int = Field(default=25, ge=1, le=50)
    extensions: list[str] = Field(default_factory=list, max_length=8)
    max_findings: int = Field(default=120, ge=1, le=500)

    @field_validator("wordlist")
    @classmethod
    def _check_wordlist(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _WORDLIST_RE.match(value) or ".." in value:
            raise ValueError("wordlist must be a plain filesystem path")
        return value


class FeroxbusterTool(BaseTool):
    name = "feroxbuster"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "feroxbuster"
    success_codes = (0,)
    timeout_s = 900
    description = (
        "Recursive content discovery. Auto-tunes to avoid wildcard responses and "
        "reports discovered paths with status and length in JSONL."
    )
    input_model = FeroxbusterArgs

    def _wordlist(self, args: FeroxbusterArgs) -> str | None:
        from cyberpowerfull.inventory import pick_wordlist

        return args.wordlist or pick_wordlist("discovery")

    def build_argv(self, args: FeroxbusterArgs, out_file: str | None = None) -> list[str]:
        from cyberpowerfull.errors import InvalidToolArguments

        wordlist = self._wordlist(args)
        if not wordlist:
            raise InvalidToolArguments(
                "feroxbuster needs a discovery wordlist; none found on this host - "
                "pass 'wordlist' or install seclists"
            )
        argv = [
            "feroxbuster",
            "-u",
            args.target,
            "-w",
            wordlist,
            "--json",
            "-q",
            "-d",
            str(args.depth),
            "-t",
            str(args.threads),
            "--no-state",
            "--auto-tune",
            "-n",
        ]
        if args.extensions:
            argv.extend(["-x", ",".join(ext.lstrip(".") for ext in args.extensions)])
        return argv

    def parse(
        self, args: FeroxbusterArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        for record in json_lines(output):
            if str(record.get("type") or "response") != "response":
                continue
            if record.get("wildcard"):
                continue
            url = str(record.get("url") or "")
            status = record.get("status")
            if not url:
                continue
            interesting = bool(_INTERESTING.search(url))
            if status in (401, 403) or (interesting and status in (200, 204)):
                severity = Severity.LOW
            else:
                severity = Severity.INFO
            findings.append(
                self.finding(
                    title=truncate(f"Discovered path (HTTP {status}): {url}", 220),
                    severity=severity,
                    confidence=0.7,
                    target=args.target,
                    endpoint=url,
                    evidence=truncate(
                        f"feroxbuster url={url} status={status} "
                        f"length={record.get('content_length')} "
                        f"words={record.get('word_count')}"
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: FeroxbusterArgs, output: str) -> list[str]:
        count = sum(1 for _ in json_lines(output))
        return [f"feroxbuster: {count} JSONL record(s)"]


__all__ = ["FeroxbusterArgs", "FeroxbusterTool"]
