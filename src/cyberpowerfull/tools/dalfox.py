"""dalfox wrapper: reflected XSS validation with JSON file output."""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_COOKIE_RE = re.compile(r"^[A-Za-z0-9_\-=.%:; ]{1,1000}$")


class DalfoxArgs(UrlInput):
    """Validated dalfox invocation arguments."""

    method: Literal["GET", "POST"] = "GET"
    data: str | None = Field(default=None, max_length=2000)
    cookie: str | None = None
    workers: int = Field(default=5, ge=1, le=30)
    max_findings: int = Field(default=30, ge=1, le=100)

    @field_validator("cookie")
    @classmethod
    def _check_cookie(cls, value: str | None) -> str | None:
        if value is not None and not _COOKIE_RE.match(value):
            raise ValueError("cookie value contains unsupported characters")
        return value


class DalfoxTool(BaseTool):
    name = "dalfox"
    phase = Phase.VALIDATION
    skill = "xss"
    binary = "dalfox"
    writes_output_file = True
    success_codes = (0, 1)
    description = (
        "Reflected/stored XSS validation. Confirms parameters that reflect executable "
        "payloads and reports the exact payload used."
    )
    input_model = DalfoxArgs

    def build_argv(self, args: DalfoxArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "dalfox",
            "url",
            args.target,
            "--silence",
            "--no-color",
            "--format",
            "json",
            "--output",
            out_file or "-",
            "--worker",
            str(args.workers),
            "--method",
            args.method,
        ]
        if args.data:
            argv.extend(["--data", args.data])
        if args.cookie:
            argv.extend(["--cookie", args.cookie])
        return argv

    def parse(self, args: DalfoxArgs, output: str, out_file: str | None = None) -> list[Finding]:
        if not output.strip():
            return []
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return []
        items = payload if isinstance(payload, list) else payload.get("results", [])
        if not isinstance(items, list):
            return []
        findings: list[Finding] = []
        for item in items[: args.max_findings]:
            if not isinstance(item, dict):
                continue
            param = str(item.get("param") or "unknown")
            inject_type = str(item.get("inject_type") or "")
            kind = str(item.get("type") or "")
            evidence_text = str(
                item.get("evidence") or item.get("payload") or item.get("poc") or ""
            )
            verified = kind.upper() == "V"
            kind_label = inject_type or "reflected"
            findings.append(
                self.finding(
                    title=f"Cross-site scripting in parameter {param} ({kind_label})",
                    severity=Severity.MEDIUM if verified else Severity.LOW,
                    confidence=0.85 if verified else 0.5,
                    target=args.target,
                    endpoint=str(item.get("url") or args.target),
                    evidence=truncate(f"inject_type={inject_type} payload={evidence_text}"),
                    cwe="CWE-79",
                    verified=verified,
                    remediation=(
                        "Context-aware output encoding and a restrictive Content-Security-Policy."
                    ),
                )
            )
        return findings

    def observations(self, args: DalfoxArgs, output: str) -> list[str]:
        return [f"dalfox: {len(self.parse(args, output))} candidate(s)"]


__all__ = ["DalfoxArgs", "DalfoxTool"]
