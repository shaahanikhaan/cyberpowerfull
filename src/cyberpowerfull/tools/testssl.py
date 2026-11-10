"""testssl.sh wrapper: TLS/SSL configuration assessment (JSON output)."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_SKIP_GRADES = {"ok", "info", "debug"}


class TestsslArgs(UrlInput):
    """Validated testssl.sh invocation arguments."""

    severity_floor: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    protocol: Literal["-t", "-p"] = "-t"
    max_findings: int = Field(default=60, ge=1, le=200)


class TestsslTool(BaseTool):
    name = "testssl"
    phase = Phase.SCANNING
    skill = "tls_hardening"
    binary = "testssl.sh"
    binary_alternatives = ("testssl",)
    writes_output_file = True
    success_codes = (0, 1, 2)
    timeout_s = 900
    description = (
        "TLS configuration assessment: protocol versions, cipher suites, "
        "certificate validity and known TLS vulnerabilities, parsed from JSON."
    )
    input_model = TestsslArgs

    def build_argv(self, args: TestsslArgs, out_file: str | None = None) -> list[str]:
        return [
            "testssl.sh",
            "--jsonfile",
            out_file or "-",
            "--quiet",
            "--color",
            "0",
            "--severity",
            args.severity_floor,
            "--warnings",
            "batch",
            args.protocol,
            args.target,
        ]

    def parse(self, args: TestsslArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for record in _load(output):
            grade = str(record.get("severity") or record.get("finding") or "").upper()
            if not grade:
                continue
            if grade.lower() in _SKIP_GRADES:
                continue
            finding_id = str(record.get("id") or "TLS")
            detail = str(record.get("finding") or record.get("severity") or "").strip()
            if grade.upper() in {"OK", "INFO"}:
                continue
            severity = Severity.coerce(record.get("severity"))
            findings.append(
                self.finding(
                    title=truncate(f"TLS issue {finding_id}: {detail}", 220),
                    severity=severity,
                    confidence=0.85,
                    target=args.target,
                    endpoint=str(record.get("ip") or args.target),
                    evidence=truncate(
                        f"testssl id={finding_id} severity={record.get('severity')} "
                        f"finding={detail} cve={record.get('cve')} cwe={record.get('cwe')}"
                    ),
                    cve=str(record["cve"]) if record.get("cve") else None,
                    cwe=str(record["cwe"]) if record.get("cwe") else None,
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: TestsslArgs, output: str) -> list[str]:
        records = _load(output)
        return [f"testssl: {len(records)} check(s) parsed for {args.target}"]


def _load(output: str) -> list[dict[str, Any]]:
    text = output.strip()
    if not text:
        return []
    candidates = [text]
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            payload = payload.get("scanResult") or [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
    return []


__all__ = ["TestsslArgs", "TestsslTool"]
