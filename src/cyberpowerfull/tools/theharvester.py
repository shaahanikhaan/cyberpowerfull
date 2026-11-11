"""theHarvester wrapper: OSINT host/email/IP harvesting (JSONL output).

Flags verified against laramies/theHarvester (``theHarvester/__main__.py``
on main, 2026-11-11): ``-d`` is the domain, ``-b`` takes named sources or
capability selectors (``subdomains, emails, ips, asns, urls, people,
breaches, all``), ``-l`` bounds per-source results (default 500), ``-q``
quiets missing-key warnings, ``-r`` resolves with given resolvers, ``-t``
checks provider-gated takeover indicators, and ``-f NAME`` writes
``NAME.json`` (legacy report: ``cmd/hosts/emails/ips/urls/asns/...``),
``NAME.xml`` and ``NAME.jsonl`` (typed findings: ``{type, value, sources,
actions}`` plus a leading ``summary`` record; kinds in
``lib/evidence_types.py`` ``ResultKind``). The JSONL sibling is parsed when
present, with the legacy JSON report as fallback.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, json_lines, truncate

#: Stable -b capability selectors (named sources drift; capabilities do not).
_CAPABILITIES = (
    "subdomains",
    "emails",
    "ips",
    "asns",
    "urls",
    "people",
    "breaches",
    "all",
)

#: JSONL type -> (title template, severity, confidence).
_TYPE_FINDINGS: dict[str, tuple[str, Severity, float]] = {
    "hostname": ("Host discovered: {value}", Severity.INFO, 0.75),
    "email": ("Email address harvested: {value}", Severity.INFO, 0.7),
    "ip": ("IP address harvested: {value}", Severity.INFO, 0.7),
    "url": ("URL harvested: {value}", Severity.INFO, 0.65),
    "asn": ("ASN attribution: {value}", Severity.INFO, 0.7),
    "prefix": ("Network prefix: {value}", Severity.INFO, 0.7),
    "breach": ("Breach correlation: {value}", Severity.MEDIUM, 0.55),
    "infostealer": ("Infostealer log correlation: {value}", Severity.HIGH, 0.5),
    "person": ("Person of interest: {value}", Severity.INFO, 0.6),
    "linkedin-person": ("Person of interest: {value}", Severity.INFO, 0.6),
    "twitter-person": ("Person of interest: {value}", Severity.INFO, 0.6),
    "takeover": ("Possible subdomain takeover: {value}", Severity.MEDIUM, 0.5),
    "shodan-host": ("Shodan host record: {value}", Severity.INFO, 0.6),
    "cms": ("Technology fingerprint: cms={value}", Severity.INFO, 0.6),
    "server": ("Technology fingerprint: server={value}", Severity.INFO, 0.6),
    "framework": ("Technology fingerprint: framework={value}", Severity.INFO, 0.6),
    "language": ("Technology fingerprint: language={value}", Severity.INFO, 0.6),
    "analytics": ("Technology fingerprint: analytics={value}", Severity.INFO, 0.6),
    "dns-recursive-classification": (
        "Recursive DNS classification: {value}",
        Severity.INFO,
        0.6,
    ),
    "dns-recursive-finding": ("Recursive DNS finding: {value}", Severity.INFO, 0.6),
    "dns-recursive-summary": ("Recursive DNS summary: {value}", Severity.INFO, 0.6),
}


class TheharvesterArgs(DomainInput):
    """Validated theHarvester invocation arguments."""

    sources: list[str] = Field(default_factory=lambda: ["subdomains"])
    limit: int = Field(default=100, ge=1, le=500)
    resolvers: list[str] = Field(default_factory=list, max_length=5)
    takeover: bool = False
    max_findings: int = Field(default=50, ge=1, le=500)

    @field_validator("sources")
    @classmethod
    def _check_sources(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one source capability is required")
        lowered = [value.strip().lower() for value in values]
        for value in lowered:
            if value not in _CAPABILITIES:
                raise ValueError(f"unsupported source capability: {value!r}")
        return lowered

    @field_validator("resolvers")
    @classmethod
    def _check_resolvers(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                ipaddress.ip_address(value.strip())
            except ValueError as exc:
                raise ValueError(f"resolver must be an IP address: {value!r}") from exc
        return [value.strip() for value in values]


class TheharvesterTool(BaseTool):
    name = "theharvester"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "theHarvester"
    writes_output_file = True
    timeout_s = 600
    description = (
        "OSINT harvesting of hosts, emails, IPs and URLs from public sources. "
        "Findings are unverified third-party data, never proof."
    )
    input_model = TheharvesterArgs

    def build_argv(self, args: TheharvesterArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "theHarvester",
            "-d",
            args.target,
            "-b",
            ",".join(args.sources),
            "-l",
            str(args.limit),
            "-q",
        ]
        if args.resolvers:
            argv.extend(["-r", ",".join(args.resolvers)])
        if args.takeover:
            argv.append("-t")
        if out_file:
            argv.append("-f")
            argv.append(out_file)
        return argv

    def parse(
        self, args: TheharvesterArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        records = _load_records(output, out_file)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for record in records:
            kind = str(record.get("type") or "").strip()
            value = str(record.get("value") or "").strip()
            if not kind or not value or kind == "summary":
                continue
            key = (kind, value.lower())
            if key in seen:
                continue
            seen.add(key)
            template, severity, confidence = _TYPE_FINDINGS.get(
                kind, (f"OSINT record ({kind}): {{value}}", Severity.INFO, 0.5)
            )
            sources = record.get("sources")
            if isinstance(sources, list):
                provenance = ",".join(str(item) for item in sources[:3] if item)
            else:
                provenance = ""
            findings.append(
                self.finding(
                    title=truncate(template.format(value=value), 200),
                    severity=severity,
                    confidence=confidence,
                    target=args.target,
                    endpoint=value if kind in {"hostname", "ip", "url"} else args.target,
                    evidence=truncate(
                        f"theharvester type={kind} value={value}"
                        + (f" sources={provenance}" if provenance else "")
                    ),
                    remediation=(
                        "Verify the DNS record and the claimed provider before "
                        "treating this as a takeover."
                        if kind == "takeover"
                        else None
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: TheharvesterArgs, output: str) -> list[str]:
        records = _load_records(output, None)
        kinds: dict[str, int] = {}
        for record in records:
            kind = str(record.get("type") or "unknown")
            kinds[kind] = kinds.get(kind, 0) + 1
        detail = ", ".join(f"{key}={kinds[key]}" for key in sorted(kinds))
        return [f"theharvester: {len(records)} record(s) ({detail or 'none'})"]


def _load_records(output: str, out_file: str | None) -> list[dict[str, Any]]:
    """Return typed ``{type, value, sources}`` records, JSONL first."""
    if out_file:
        sibling = Path(out_file).parent / (Path(out_file).stem + ".jsonl")
        try:
            if sibling.is_file():
                records = _records_from_jsonl(sibling.read_text(encoding="utf-8"))
                if records:
                    return records
        except OSError:
            # Sibling unreadable: fall through to the legacy report text.
            pass
    records = _records_from_jsonl(output)
    if records:
        return records
    return _records_from_legacy_json(output)


def _records_from_jsonl(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for record in json_lines(text):
        kind = record.get("type")
        value = record.get("value")
        if isinstance(kind, str) and isinstance(value, str) and value.strip():
            records.append({"type": kind.strip(), "value": value.strip(), "sources": []})
            sources = record.get("sources")
            if isinstance(sources, list):
                records[-1]["sources"] = sources
    return records


def _records_from_legacy_json(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(payload, dict):
        return []
    records: list[dict[str, Any]] = []
    for host in _string_list(payload.get("hosts")):
        records.append({"type": "hostname", "value": _legacy_host(host), "sources": []})
    for key, kind in (
        ("emails", "email"),
        ("ips", "ip"),
        ("urls", "url"),
        ("asns", "asn"),
        ("prefixes", "prefix"),
        ("people", "person"),
        ("linkedin_people", "linkedin-person"),
        ("twitter_people", "twitter-person"),
    ):
        for value in _string_list(payload.get(key)):
            records.append({"type": kind, "value": value, "sources": []})
    for value in _string_list(payload.get("takeover_results")):
        records.append({"type": "takeover", "value": value, "sources": []})
    return records


def _legacy_host(entry: str) -> str:
    """Return the hostname from a legacy ``hosts`` entry (``ip:host`` or plain)."""
    head, separator, tail = entry.partition(":")
    if separator and tail.strip():
        try:
            ipaddress.ip_address(head.strip())
        except ValueError:
            return entry
        return tail.strip()
    return entry


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


__all__ = ["TheharvesterArgs", "TheharvesterTool"]
