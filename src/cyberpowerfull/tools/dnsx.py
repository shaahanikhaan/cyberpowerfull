"""dnsx wrapper: fast DNS resolution and brute-force (JSONL output).

Flags verified against projectdiscovery/dnsx (README ``Usage`` plus
``internal/runner/options.go`` on main, 2026-11-11; latest release v1.3.1):
``-l`` takes a file, stdin, or a comma-separated host list (proven by
``runner_test.go``), ``-r`` takes resolvers the same way, ``-j`` emits JSONL,
``-d``/``-w`` brute-force a domain from a wordlist.

Record keys come from ``retryabledns`` ``DNSData`` (``host/a/aaaa/cname/mx/
ptr/soa/ns/txt/srv/caa/all/...``) plus dnsx's own ``cdn/cdn-name/asn`` extras.
"""

from __future__ import annotations

import ipaddress
import re

from pydantic import Field, field_validator, model_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, json_lines, truncate

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,24}$")

#: Query flags dnsx accepts (``-a``, ``-mx``, ...); ``-any`` is the server-side
#: ANY query, ``-axfr`` attempts a zone transfer.
_RECORDS = (
    "a",
    "aaaa",
    "cname",
    "ns",
    "txt",
    "srv",
    "ptr",
    "mx",
    "soa",
    "any",
    "caa",
    "axfr",
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class DnsxArgs(HostInput):
    """Validated dnsx invocation arguments."""

    records: list[str] = Field(
        default_factory=lambda: ["a", "aaaa", "cname", "mx", "ns", "txt", "soa"]
    )
    resolvers: list[str] = Field(default_factory=list, max_length=5)
    threads: int = Field(default=100, ge=1, le=500)
    rate_limit: int | None = Field(default=None, ge=1, le=1000)
    asn: bool = False
    cdn: bool = False
    bruteforce: bool = False
    wordlist: str | None = Field(default=None, max_length=500)
    max_findings: int = Field(default=50, ge=1, le=500)

    @field_validator("target")
    @classmethod
    def _check_host(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "://" in cleaned or "/" in cleaned:
            raise ValueError("dnsx requires a bare host or IP, not a URL")
        if not _is_ip(cleaned) and not _HOSTNAME.match(cleaned):
            raise ValueError("dnsx requires a valid DNS name or IP address")
        return cleaned

    @field_validator("records")
    @classmethod
    def _check_records(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one record type is required")
        lowered = [value.lower() for value in values]
        for value in lowered:
            if value not in _RECORDS:
                raise ValueError(f"unsupported record type: {value!r}")
        return lowered

    @field_validator("resolvers")
    @classmethod
    def _check_resolvers(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _is_ip(value.strip()):
                raise ValueError(f"resolver must be an IP address: {value!r}")
        return [value.strip() for value in values]

    @model_validator(mode="after")
    def _check_bruteforce(self) -> DnsxArgs:
        if self.bruteforce and _is_ip(self.target):
            raise ValueError("dnsx bruteforce needs a domain name, not an IP address")
        if self.bruteforce and not self.wordlist:
            raise ValueError("dnsx bruteforce needs a wordlist")
        if self.wordlist and not self.bruteforce:
            raise ValueError("wordlist is only used with bruteforce=True")
        return self


class DnsxTool(BaseTool):
    name = "dnsx"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "dnsx"
    description = (
        "Fast DNS record collection (A/AAAA/MX/TXT/...) and subdomain brute-force. "
        "Brute-force hits are re-validated against scope before any further action."
    )
    input_model = DnsxArgs

    def build_argv(self, args: DnsxArgs, out_file: str | None = None) -> list[str]:
        argv = ["dnsx"]
        if args.bruteforce:
            argv.extend(["-d", args.target, "-w", args.wordlist or ""])
        else:
            argv.extend(["-l", args.target])
        argv.extend(["-j", "-silent", "-nc", "-duc", "-threads", str(args.threads)])
        for record in args.records:
            argv.append(f"-{record}")
        if args.resolvers:
            argv.extend(["-r", ",".join(args.resolvers)])
        if args.rate_limit:
            argv.extend(["-rl", str(args.rate_limit)])
        if args.asn:
            argv.append("-asn")
        if args.cdn:
            argv.append("-cdn")
        return argv

    def parse(self, args: DnsxArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for record in json_lines(output):
            host = str(record.get("host") or "").strip().lower()
            if not host or host in seen:
                continue
            seen.add(host)
            if args.bruteforce and host != args.target and host.endswith("." + args.target):
                findings.append(
                    self.finding(
                        title=f"Subdomain discovered: {host}",
                        severity=Severity.INFO,
                        confidence=0.85,
                        target=args.target,
                        endpoint=host,
                        evidence=truncate(f"dnsx bruteforce resolved {host}"),
                    )
                )
            else:
                summary = _record_summary(record)
                findings.append(
                    self.finding(
                        title=f"DNS records for {host}",
                        severity=Severity.INFO,
                        confidence=0.9,
                        target=args.target,
                        endpoint=host,
                        evidence=truncate(summary or f"dnsx resolved {host}"),
                    )
                )
            internal = [str(ip) for ip in (record.get("internal_ips") or []) if str(ip)]
            if record.get("has_internal_ips") or internal:
                findings.append(
                    self.finding(
                        title=f"DNS exposes internal addresses for {host}",
                        severity=Severity.LOW,
                        confidence=0.8,
                        target=args.target,
                        endpoint=host,
                        evidence=truncate(f"internal_ips={','.join(internal[:8]) or 'yes'}"),
                    )
                )
            if record.get("axfr"):
                findings.append(
                    self.finding(
                        title=f"DNS zone transfer (AXFR) succeeded for {host}",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        target=args.target,
                        endpoint=host,
                        evidence=truncate(f"axfr={truncate(str(record.get('axfr')), 400)}"),
                    )
                )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: DnsxArgs, output: str) -> list[str]:
        count = sum(1 for _ in json_lines(output))
        mode = "bruteforce" if args.bruteforce else "resolve"
        return [f"dnsx ({mode}): {count} host record(s)"]


def _record_summary(record: dict) -> str:
    parts: list[str] = []
    for key in ("a", "aaaa", "cname", "mx", "ns", "txt", "soa", "srv", "ptr", "caa"):
        values = record.get(key)
        if isinstance(values, list) and values:
            shown = ",".join(str(item) for item in values[:6])
            parts.append(f"{key.upper()}={shown}")
        elif isinstance(values, str) and values:
            parts.append(f"{key.upper()}={values}")
    status = record.get("status_code")
    if status:
        parts.append(f"rcode={status}")
    cdn = record.get("cdn-name")
    if cdn:
        parts.append(f"cdn={cdn}")
    return " ".join(parts)


__all__ = ["DnsxArgs", "DnsxTool"]
