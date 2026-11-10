"""nuclei wrapper: template-driven vulnerability validation (JSONL output).

The wrapper requests Interactsh to be disabled, but templates and the scanner
are not sandboxed and can still contact other destinations.
"""

from __future__ import annotations

import re

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, json_lines, truncate

_TEMPLATE_RE = re.compile(r"^[A-Za-z0-9_\-/.]{1,200}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
_ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")


class NucleiArgs(UrlInput):
    """Validated nuclei invocation arguments."""

    severity: list[str] = Field(default_factory=lambda: ["low", "medium", "high", "critical"])
    tags: list[str] = Field(default_factory=list, max_length=20)
    templates: list[str] = Field(default_factory=list, max_length=20)
    rate_limit: int = Field(default=20, ge=1, le=150)
    concurrency: int = Field(default=10, ge=1, le=50)

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one severity is required")
        for value in values:
            if value.lower() not in _ALLOWED_SEVERITIES:
                raise ValueError(f"unsupported severity: {value!r}")
        return [value.lower() for value in values]

    @field_validator("tags")
    @classmethod
    def _check_tags(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _TAG_RE.match(value):
                raise ValueError(f"invalid tag: {value!r}")
        return values

    @field_validator("templates")
    @classmethod
    def _check_templates(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _TEMPLATE_RE.match(value) or ".." in value:
                raise ValueError(f"invalid template path: {value!r}")
        return values


class NucleiTool(BaseTool):
    name = "nuclei"
    phase = Phase.VALIDATION
    skill = "information_disclosure"
    binary = "nuclei"
    success_codes = (0,)
    description = (
        "Template-based vulnerability validation against a single URL. Returns matched "
        "templates with severity, CVE/CWE metadata and matcher evidence."
    )
    input_model = NucleiArgs

    def build_argv(self, args: NucleiArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "nuclei",
            "-u",
            args.target,
            "-jsonl",
            "-silent",
            "-nc",
            "-no-interactsh",
            "-disable-update-check",
            "-disable-redirects",
            "-rl",
            str(args.rate_limit),
            "-c",
            str(args.concurrency),
            "-severity",
            ",".join(args.severity),
        ]
        if args.tags:
            argv.extend(["-tags", ",".join(args.tags)])
        for template in args.templates:
            argv.extend(["-t", template])
        return argv

    def parse(self, args: NucleiArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for record in json_lines(output):
            info = record.get("info") or {}
            if not isinstance(info, dict):
                continue
            severity = Severity.coerce(str(info.get("severity", "info")))
            template_id = str(record.get("template-id") or "unknown-template")
            name = str(info.get("name") or template_id)
            classification = info.get("classification") or {}
            if not isinstance(classification, dict):
                classification = {}
            cwe_ids = json_id_list(classification.get("cwe-id"))
            cve_ids = json_id_list(classification.get("cve-id"))
            cwe = cwe_ids[0].upper() if cwe_ids else None
            if cwe and cwe.isdigit():
                cwe = f"CWE-{cwe}"
            if cwe and not re.fullmatch(r"CWE-\d+", cwe):
                cwe = None
            cve = cve_ids[0].upper() if cve_ids else None
            if cve and not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
                cve = None
            try:
                cvss = float(classification.get("cvss-score"))
                if not 0 <= cvss <= 10:
                    cvss = None
            except (TypeError, ValueError):
                cvss = None
            matcher = record.get("matcher-name")
            matched_at = str(record.get("matched-at") or record.get("host") or args.target)
            extracted = json_id_list(record.get("extracted-results"))
            evidence = truncate(
                f"template={template_id} matcher={matcher or '-'} matched_at={matched_at}"
                + (f" extracted={', '.join(extracted[:3])}" if extracted else "")
            )
            findings.append(
                self.finding(
                    title=f"{name} ({template_id})",
                    severity=severity,
                    confidence=0.9 if matcher else 0.65,
                    target=args.target,
                    endpoint=matched_at,
                    evidence=evidence,
                    cwe=cwe,
                    cve=cve,
                    cvss=cvss,
                    # A template match is evidence, not independent verification.
                    verified=False,
                )
            )
        return findings

    def observations(self, args: NucleiArgs, output: str) -> list[str]:
        count = sum(1 for _ in json_lines(output))
        return [f"nuclei matched {count} template(s)"] if count else ["nuclei: no template matched"]


def json_id_list(value: object) -> list[str]:
    """Normalise nucleus ``extracted-results`` values into a list of strings."""
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


__all__ = ["NucleiArgs", "NucleiTool"]
