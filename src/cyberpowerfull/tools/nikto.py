"""nikto wrapper: web server misconfiguration scanner (plain-text output)."""

from __future__ import annotations

import re

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, severity_from_text, truncate

_TUNING_RE = re.compile(r"^[0-9a-x]{1,10}$")
_ITEM = re.compile(r"^\+\s+(?P<body>.+)$", re.MULTILINE)
_NOISE = (
    "target ip:",
    "target hostname:",
    "target port:",
    "start time:",
    "end time:",
    "server:",
    "no web server found",
    "host(s) tested",
)
_PATH_PREFIX = re.compile(r"^(?P<path>/\S*?):?")


class NiktoArgs(HostInput):
    """Validated nikto invocation arguments."""

    port: int = Field(default=80, ge=1, le=65535)
    ssl: bool = False
    tuning: str = "123b"
    max_findings: int = Field(default=50, ge=1, le=200)

    @field_validator("tuning")
    @classmethod
    def _check_tuning(cls, value: str) -> str:
        if not _TUNING_RE.match(value):
            raise ValueError("tuning must be nikto tuning characters")
        return value


class NiktoTool(BaseTool):
    name = "nikto"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "nikto"
    success_codes = (0, 1)
    description = (
        "Web server misconfiguration and default-file scanner. Good second pass after "
        "httpx confirms a live HTTP service."
    )
    input_model = NiktoArgs

    def build_argv(self, args: NiktoArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "nikto",
            "-h",
            args.target,
            "-p",
            str(args.port),
            "-nointeractive",
            "-ask",
            "no",
            "-Tuning",
            args.tuning,
        ]
        if args.ssl:
            argv.append("-ssl")
        return argv

    def parse(self, args: NiktoArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for match in _ITEM.finditer(output):
            body = match.group("body").strip()
            if not body or body.lower().startswith(_NOISE):
                continue
            severity = severity_from_text(body)
            path_match = _PATH_PREFIX.match(body)
            endpoint = None
            if path_match:
                endpoint = f"{args.target}:{args.port}{path_match.group('path')}"
            findings.append(
                self.finding(
                    title=truncate(body.rstrip("."), 200),
                    severity=severity,
                    confidence=0.55 if severity is Severity.INFO else 0.7,
                    target=args.target,
                    endpoint=endpoint,
                    evidence=truncate(body),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: NiktoArgs, output: str) -> list[str]:
        count = len(self.parse(args, output))
        return [f"nikto: {count} item(s) reported"]


__all__ = ["NiktoArgs", "NiktoTool"]
