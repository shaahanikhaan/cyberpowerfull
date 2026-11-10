"""nuclei wrapper: template-driven vulnerability validation (JSONL output).

Flags and output keys are verified against projectdiscovery/nuclei v3.11.1
(``cmd/nuclei/main.go``, ``pkg/output/output.go``, ``pkg/model/model.go``).
The wrapper requests Interactsh to be disabled, but templates and the scanner
are not sandboxed and can still contact other destinations.
"""

from __future__ import annotations

import dataclasses
import re

from pydantic import Field, field_validator

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import (
    BaseTool,
    ToolInput,
    ToolStatus,
    UrlInput,
    json_lines,
    truncate,
)

_TEMPLATE_RE = re.compile(r"^[A-Za-z0-9_\-/.]{1,200}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
_ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")

#: stderr fragments that mean the template store is missing, not that the
#: target is clean. Surfaced as an actionable error instead of a bare exit code.
_TEMPLATE_ERROR_MARKERS = (
    "update-templates",
    "no templates found",
    "could not find nuclei-templates",
    "template directory",
)


class NucleiArgs(UrlInput):
    """Validated nuclei invocation arguments."""

    severity: list[str] = Field(default_factory=lambda: ["low", "medium", "high", "critical"])
    tags: list[str] = Field(default_factory=list, max_length=20)
    templates: list[str] = Field(default_factory=list, max_length=20)
    rate_limit: int = Field(default=20, ge=1, le=150)
    concurrency: int = Field(default=10, ge=1, le=50)
    bulk_size: int = Field(default=25, ge=1, le=100)
    max_host_error: int = Field(default=30, ge=1, le=200)
    timeout: int = Field(default=10, ge=1, le=120)
    retries: int = Field(default=1, ge=0, le=5)

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
    # A full template-store run (no tags) sends thousands of requests; the
    # default 300s tool budget would kill it mid-scan on any real target.
    timeout_s = 1800
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
            "-bs",
            str(args.bulk_size),
            "-mhe",
            str(args.max_host_error),
            "-timeout",
            str(args.timeout),
            "-retries",
            str(args.retries),
            "-severity",
            ",".join(args.severity),
        ]
        if args.tags:
            argv.extend(["-tags", ",".join(args.tags)])
        for template in args.templates:
            argv.extend(["-t", template])
        return argv

    def _execute(self, args: ToolInput, argv: list[str], policy: ToolPolicy):
        result = super()._execute(args, argv, policy)
        if result.status is ToolStatus.OK:
            return result
        lowered = result.stderr.lower()
        if any(marker in lowered for marker in _TEMPLATE_ERROR_MARKERS):
            return dataclasses.replace(
                result,
                error=(
                    "nuclei has no template store on this host (a scan without templates "
                    "proves nothing); run 'nuclei -update-templates' (or './run.sh "
                    "--install-tools') and retry"
                ),
            )
        return result

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
            description = str(info.get("description") or "").strip()
            references = json_id_list(info.get("reference"))
            replay = str(record.get("curl-command") or "").strip()
            evidence_parts = [
                f"template={template_id}",
                f"matcher={matcher or '-'}",
                f"matched_at={matched_at}",
            ]
            if extracted:
                evidence_parts.append(f"extracted={', '.join(extracted[:3])}")
            if description:
                evidence_parts.append(f"about={truncate(description, 300)}")
            if references:
                evidence_parts.append(f"ref={references[0]}")
            if replay:
                evidence_parts.append(f"replay={truncate(replay, 300)}")
            findings.append(
                self.finding(
                    title=f"{name} ({template_id})",
                    severity=severity,
                    confidence=0.9 if matcher else 0.65,
                    target=args.target,
                    endpoint=matched_at,
                    evidence=truncate(" ".join(evidence_parts), 2000),
                    cwe=cwe,
                    cve=cve,
                    cvss=cvss,
                    remediation=truncate(str(info.get("remediation") or "").strip(), 1000) or None,
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
