"""sqlmap wrapper: confirmation-only SQL injection validation.

The wrapper runs sqlmap in batch mode against a single URL. Exploitation
features (OS shell, file read/write, data dump) are never exposed to the model.
"""

from __future__ import annotations

import re

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_TECHNIQUE_RE = re.compile(r"^[BEUSTQ]{1,6}$")
_PARAM_RE = re.compile(r"^[A-Za-z0-9_\[\]\-.]{1,80}$")
_DBMS_RE = re.compile(r"^[A-Za-z0-9_ \-]{1,40}$")

_PARAMETER_LINE = re.compile(r"^Parameter:\s*(?P<param>.+?)\s*\((?P<where>[^)]+)\)", re.MULTILINE)
_TYPE_LINE = re.compile(r"^Type:\s*(?P<type>.+)$", re.MULTILINE)
_TITLE_LINE = re.compile(r"^Title:\s*(?P<title>.+)$", re.MULTILINE)
_PAYLOAD_LINE = re.compile(r"^Payload:\s*(?P<payload>.+)$", re.MULTILINE)


class SqlmapArgs(UrlInput):
    """Validated sqlmap invocation arguments."""

    data: str | None = Field(default=None, max_length=2000)
    parameter: str | None = None
    level: int = Field(default=2, ge=1, le=5)
    risk: int = Field(default=1, ge=1, le=3)
    technique: str = "BEUSTQ"
    dbms: str | None = None
    timeout_s: int = Field(default=120, ge=10, le=900)

    @field_validator("technique")
    @classmethod
    def _check_technique(cls, value: str) -> str:
        value = value.upper()
        if not _TECHNIQUE_RE.match(value):
            raise ValueError("technique must be a subset of BEUSTQ")
        return value

    @field_validator("parameter")
    @classmethod
    def _check_parameter(cls, value: str | None) -> str | None:
        if value is not None and not _PARAM_RE.match(value):
            raise ValueError("parameter name contains unsupported characters")
        return value

    @field_validator("dbms")
    @classmethod
    def _check_dbms(cls, value: str | None) -> str | None:
        if value is not None and not _DBMS_RE.match(value):
            raise ValueError("dbms value contains unsupported characters")
        return value

    @field_validator("data")
    @classmethod
    def _check_data(cls, value: str | None) -> str | None:
        if value is not None and ("\n" in value or "\x00" in value):
            raise ValueError("POST data must be a single line")
        return value


class SqlmapTool(BaseTool):
    name = "sqlmap"
    phase = Phase.VALIDATION
    skill = "sql_injection"
    binary = "sqlmap"
    success_codes = (0, 1)
    description = (
        "Confirms SQL injection in a single HTTP parameter. Batch mode, no data "
        "extraction, no OS shell. Produces a verified finding when a parameter is injectable."
    )
    input_model = SqlmapArgs

    def build_argv(self, args: SqlmapArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "sqlmap",
            "-u",
            args.target,
            "--batch",
            "--disable-coloring",
            "--flush-session",
            f"--level={args.level}",
            f"--risk={args.risk}",
            f"--technique={args.technique}",
            f"--timeout={min(args.timeout_s, 60)}",
        ]
        if args.data:
            argv.extend(["--data", args.data])
        if args.parameter:
            argv.extend(["-p", args.parameter])
        if args.dbms:
            argv.extend(["--dbms", args.dbms])
        return argv

    def parse(self, args: SqlmapArgs, output: str, out_file: str | None = None) -> list[Finding]:
        lower = output.lower()
        confirmed = (
            "sqlmap identified the following injection point" in lower
            or "is vulnerable" in lower
            or "parameter appears to be injectable" in lower
        )
        if not confirmed:
            return []
        findings: list[Finding] = []
        params = _PARAMETER_LINE.findall(output)
        types = [value.strip() for value in _TYPE_LINE.findall(output)]
        titles = [value.strip() for value in _TITLE_LINE.findall(output)]
        payloads = [value.strip() for value in _PAYLOAD_LINE.findall(output)]
        evidence = truncate(
            "sqlmap confirmed injection; "
            + "; ".join(
                part
                for part in (
                    f"types={','.join(types[:4])}" if types else "",
                    f"titles={','.join(titles[:3])}" if titles else "",
                    f"payload={payloads[0] if payloads else ''}",
                )
                if part
            )
        )
        if not params:
            findings.append(
                self.finding(
                    title="SQL injection confirmed (parameter unspecified)",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    target=args.target,
                    endpoint=args.target,
                    evidence=evidence,
                    cwe="CWE-89",
                    cvss=8.6,
                    verified=True,
                    remediation="Use parameterised queries; validate and escape all input.",
                )
            )
            return findings
        for param, where in params[:5]:
            findings.append(
                self.finding(
                    title=f"SQL injection in parameter {param.strip()} ({where.strip()})",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    target=args.target,
                    endpoint=args.target,
                    evidence=evidence,
                    cwe="CWE-89",
                    cvss=8.6,
                    verified=True,
                    remediation="Use parameterised queries; validate and escape all input.",
                )
            )
        return findings

    def observations(self, args: SqlmapArgs, output: str) -> list[str]:
        if "do not appear to be injectable" in output.lower():
            return ["sqlmap: no injectable parameter found"]
        if not self.parse(args, output):
            return ["sqlmap: inconclusive output"]
        return ["sqlmap: injection confirmed"]


__all__ = ["SqlmapArgs", "SqlmapTool"]
