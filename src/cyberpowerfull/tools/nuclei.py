"""nuclei wrapper: template-driven vulnerability validation (JSONL output).

Flags and output keys are verified against projectdiscovery/nuclei v3.11.1
(``cmd/nuclei/main.go``, ``pkg/output/output.go``, ``pkg/model/model.go``),
including the OAST controls (``-interactsh-server`` / ``-interactsh-token`` /
``-no-interactsh``) and the DAST controls (``-dast`` / ``-fuzz-scope`` /
``-fuzz-out-scope`` / ``-fuzz-aggression``).

OAST stays disabled by default: stock nuclei phones a third-party interactsh
server, which discloses engagement activity outside the scope. An operator may
point at a self-hosted server or explicitly opt into the public one. DAST
fuzzing defaults to a scope pattern covering exactly the validated target host.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator

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
    interactsh_server: str | None = Field(default=None, max_length=200)
    interactsh_token: str | None = Field(default=None, max_length=200)
    enable_public_oast: bool = False
    dast: bool = False
    dast_scope: list[str] = Field(default_factory=list, max_length=10)
    dast_out_of_scope: list[str] = Field(default_factory=list, max_length=10)
    fuzz_aggression: Literal["low", "medium", "high"] = "low"
    kev_only: bool = False

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

    @field_validator("interactsh_server")
    @classmethod
    def _check_interactsh_server(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().rstrip("/")
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("interactsh_server must be an http(s) URL with a host")
        return cleaned

    @field_validator("dast_scope", "dast_out_of_scope")
    @classmethod
    def _check_scope_patterns(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 300 or any(char in value for char in "\n\r\0"):
                raise ValueError("fuzz scope patterns must be 1-300 chars with no newlines")
        return values

    @model_validator(mode="after")
    def _check_oast_and_dast(self) -> NucleiArgs:
        if self.interactsh_token and not self.interactsh_server:
            raise ValueError("interactsh_token needs interactsh_server")
        if self.interactsh_server and self.enable_public_oast:
            raise ValueError("choose one OAST destination: interactsh_server or public")
        dast_tuned = bool(self.dast_scope or self.dast_out_of_scope) or (
            self.fuzz_aggression != "low"
        )
        if dast_tuned and not self.dast:
            raise ValueError("fuzz scope/aggression need dast=True")
        return self


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
        if args.interactsh_server:
            argv.extend(["-interactsh-server", args.interactsh_server])
            if args.interactsh_token:
                argv.extend(["-interactsh-token", args.interactsh_token])
        elif not args.enable_public_oast:
            argv.append("-no-interactsh")
        # KEV-first: templates tagged kev cover CISA Known Exploited
        # Vulnerabilities (2280+ in nuclei-templates v10.5.1). kev_only
        # replaces tags: mixing would silently dilute the exploited-in-the-wild
        # focus with thousands of unexploited checks.
        tags = ["kev"] if args.kev_only else args.tags
        if tags:
            argv.extend(["-tags", ",".join(tags)])
        for template in args.templates:
            argv.extend(["-t", template])
        if args.dast:
            argv.append("-dast")
            argv.extend(["-fuzz-aggression", args.fuzz_aggression])
            for pattern in args.dast_scope or [_default_scope_pattern(args.target)]:
                argv.extend(["-fuzz-scope", pattern])
            for pattern in args.dast_out_of_scope:
                argv.extend(["-fuzz-out-scope", pattern])
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
        notes = (
            [f"nuclei matched {count} template(s)"] if count else ["nuclei: no template matched"]
        )
        if args.interactsh_server:
            notes.append("oast via self-hosted interactsh (no public callbacks)")
        elif args.enable_public_oast:
            notes.append(
                "WARNING: public OAST enabled: target-derived callbacks reach "
                "third-party interactsh infrastructure"
            )
        else:
            notes.append("oast disabled (-no-interactsh)")
        if args.dast:
            patterns = len(args.dast_scope) or 1
            notes.append(
                f"dast fuzzing on ({patterns} scope pattern(s), "
                f"aggression {args.fuzz_aggression})"
            )
        return notes


def _default_scope_pattern(target: str) -> str:
    """A ``-fuzz-scope`` regex covering exactly the validated target host.

    Builders only see Facts, never the scope, so the safe default is the one
    host the runner already validated — never discovered URLs or subdomains,
    which ``_accept`` does not scope-check.
    """
    candidate = target if "://" in target else f"https://{target}"
    host = urlparse(candidate).hostname or target
    return f"^https?://{re.escape(host)}(:[0-9]+)?/"


def json_id_list(value: object) -> list[str]:
    """Normalise nucleus ``extracted-results`` values into a list of strings."""
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


__all__ = ["NucleiArgs", "NucleiTool"]
