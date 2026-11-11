"""whois wrapper: domain registration facts from RDAP/whois servers.

Flags verified against rfc1036/whois, the Debian whois client (``whois.1``
on main, 2026-11-11): the domain is positional, ``-H`` hides the legal
disclaimers registries prepend (leaving cleaner ``Key: value`` lines), and
referrals from registry to registrar are followed by default. Output has
no machine-readable mode: TLD servers use different labels, so this wrapper
matches the common ones (``Registrar``/``Creation Date``/``Registry Expiry
Date``/``Name Server``/``Registrant Organization``/``DNSSEC`` and their
abbreviations) and treats a record with zero parsed fields as "no data".
Queries go to third-party whois servers: the worker requires
``allow_passive_sources`` for this tool.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, truncate

#: (pattern source, canonical key, multi-value). Keys use "^...:" anchoring
#: so that longer labels ("Registrar Abuse Contact Email:") do not collide.
_FIELD_SOURCES: tuple[tuple[str, str, bool], ...] = (
    (r"^(?:sponsoring\s+)?registrar:\s*(.+)$", "registrar", False),
    (
        r"^(?:creation date|created|registered on|registered|commencement date):\s*(.+)$",
        "created",
        False,
    ),
    (
        r"^(?:updated date|last updated|last-modified|lastmod):\s*(.+)$",
        "updated",
        False,
    ),
    (
        r"^(?:registry expiry date|registrar registration expiration date|"
        r"expiration date|expiry date|expire date|expires|paid-till|"
        r"renewal date):\s*(.+)$",
        "expires",
        False,
    ),
    (r"^(?:name server|name servers|nserver|nameserver):\s*(.+)$", "nameservers", True),
    (
        r"^(?:registrant organization|registrant org|org-name|org):\s*(.+)$",
        "registrant_org",
        False,
    ),
    (r"^(?:registrant country|country):\s*(.+)$", "registrant_country", False),
    (r"^dnssec:\s*(.+)$", "dnssec", False),
    (r"^(?:domain status|status):\s*(.+)$", "status", True),
)

_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str, bool], ...] = tuple(
    (re.compile(source, re.IGNORECASE), key, multi) for source, key, multi in _FIELD_SOURCES
)

_PLACEHOLDERS = frozenset(
    {"-", "n/a", "na", "none", "redacted", "not disclosed", "redacted for privacy"}
)

_DATE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(\d{4})-(\d{2})-(\d{2})"), "iso"),
    (re.compile(r"(\d{2})-([A-Za-z]{3})-(\d{4})"), "dmy"),
    (re.compile(r"(\d{4})/(\d{2})/(\d{2})"), "ymd"),
    (re.compile(r"(\d{4})\.(\d{2})\.(\d{2})"), "ymd"),
    (re.compile(r"(\d{2})\s+([A-Za-z]{3})\s+(\d{4})"), "dmy"),
)

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

#: Days before expiry at which the wrapper raises a LOW finding.
_EXPIRY_WARNING_DAYS = 30


class WhoisArgs(DomainInput):
    """Validated whois invocation arguments."""


class WhoisTool(BaseTool):
    name = "whois"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = "whois"
    description = (
        "Domain registration facts (registrar, dates, nameservers, DNSSEC). "
        "Third-party whois servers: needs allow_passive_sources."
    )
    input_model = WhoisArgs

    def build_argv(self, args: WhoisArgs, out_file: str | None = None) -> list[str]:
        return ["whois", "-H", args.target]

    def parse(self, args: WhoisArgs, output: str, out_file: str | None = None) -> list[Finding]:
        record = _parse_record(output)
        if not record:
            return []
        findings = [
            self.finding(
                title=f"Domain registration details: {args.target}",
                severity=Severity.INFO,
                confidence=0.7,
                target=args.target,
                evidence=truncate(_summarize(record)),
            )
        ]
        expiry = _parse_date(record["expires"]) if "expires" in record else None
        if expiry is not None:
            delta = (expiry - date.today()).days
            if delta < 0:
                findings.append(
                    self.finding(
                        title=f"Domain registration expiry date has passed: {args.target}",
                        severity=Severity.LOW,
                        confidence=0.6,
                        target=args.target,
                        evidence=truncate(f"whois expires={record['expires']}"),
                        remediation=(
                            "Confirm the domain is renewed; an expired domain can be hijacked."
                        ),
                    )
                )
            elif delta <= _EXPIRY_WARNING_DAYS:
                findings.append(
                    self.finding(
                        title=f"Domain expires within {_EXPIRY_WARNING_DAYS} days: {args.target}",
                        severity=Severity.LOW,
                        confidence=0.6,
                        target=args.target,
                        evidence=truncate(f"whois expires={record['expires']} ({delta}d left)"),
                        remediation="Renew the domain before the expiry date.",
                    )
                )
        dnssec = str(record.get("dnssec", "")).strip().lower()
        if dnssec.startswith("unsigned"):
            findings.append(
                self.finding(
                    title=f"DNSSEC not enabled: {args.target}",
                    severity=Severity.INFO,
                    confidence=0.6,
                    target=args.target,
                    evidence=truncate(f"whois dnssec={record['dnssec']}"),
                )
            )
        return findings

    def observations(self, args: WhoisArgs, output: str) -> list[str]:
        record = _parse_record(output)
        if not record:
            return [f"whois: no parseable record for {args.target}"]
        return [f"whois: {_summarize(record)}"]


def _parse_record(output: str) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for line in output.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith(("#", "%", ">")):
            continue
        for pattern, key, multi in _FIELD_PATTERNS:
            match = pattern.match(cleaned)
            if match is None:
                continue
            value = match.group(1).strip()
            if not value or value.lower() in _PLACEHOLDERS:
                break
            if multi:
                values = record.setdefault(key, [])
                if value not in values:
                    values.append(value)
            elif key not in record:
                record[key] = value
            break
    return record


def _summarize(record: dict[str, Any]) -> str:
    nameservers = record.get("nameservers", [])
    parts = [
        f"registrar={record.get('registrar', '-')}",
        f"created={record.get('created', '-')}",
        f"expires={record.get('expires', '-')}",
        f"nameservers={len(nameservers)}",
        f"dnssec={record.get('dnssec', '-')}",
    ]
    return " ".join(parts)


def _parse_date(value: Any) -> date | None:
    text = str(value).strip()
    for pattern, kind in _DATE_PATTERNS:
        match = pattern.search(text)
        if match is None:
            continue
        try:
            if kind == "iso":
                return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
            if kind == "ymd":
                return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
            month = _MONTHS.get(match.group(2).lower())
            if month is None:
                continue
            return date(int(match.group(3)), month, int(match.group(1)))
        except ValueError:
            continue
    return None


__all__ = ["WhoisArgs", "WhoisTool"]
