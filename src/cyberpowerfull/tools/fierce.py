"""fierce wrapper: DNS recon (subdomain brute-force, zone transfer, wildcard).

Flags verified against mschwager/fierce (``fierce/fierce.py`` on main,
2026-11-11): ``--domain`` is the target, ``--subdomain-file`` selects the
wordlist (mutually exclusive with ``--subdomains``), ``--traverse`` scans
IPs near hits (default 5, used unless ``--wide``), ``--delay`` waits
between lookups (default none), ``--tcp`` uses TCP instead of UDP.
Stdout lines are ``NS:``/``SOA:``/``Zone: success|failure``/``Wildcard:``
plus one ``Found: <fqdn>. (<ip>)`` per hit (absolute name with trailing
dot). ``fatal()`` exits with code 255 when NS/SOA lookup fails. The
wordlist must be allowlisted via ``scope.allowed_wordlists``.
"""

from __future__ import annotations

import re

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, truncate

_FOUND = re.compile(r"^Found:\s+(\S+)\s+\(([^)]+)\)\s*$")
_ZONE = re.compile(r"^Zone:\s+(success|failure)\s*$")
_LABELED = re.compile(r"^(NS|SOA|Wildcard):\s+(.*?)\s*$")


class FierceArgs(DomainInput):
    """Validated fierce invocation arguments."""

    wordlist: str = Field(min_length=1, max_length=500)
    traverse: int = Field(default=5, ge=0, le=50)
    delay: float = Field(default=0.0, ge=0.0, le=60.0)
    tcp: bool = False
    max_findings: int = Field(default=100, ge=1, le=500)


class FierceTool(BaseTool):
    name = "fierce"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "fierce"
    description = (
        "DNS reconnaissance: subdomain brute-force, AXFR attempt and wildcard "
        "detection. Needs an allowlisted subdomain wordlist."
    )
    input_model = FierceArgs

    def build_argv(self, args: FierceArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "fierce",
            "--domain",
            args.target,
            "--subdomain-file",
            args.wordlist,
            "--traverse",
            str(args.traverse),
        ]
        if args.delay > 0:
            argv.extend(["--delay", str(args.delay)])
        if args.tcp:
            argv.append("--tcp")
        return argv

    def parse(self, args: FierceArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if _zone_status(output) == "success":
            findings.append(
                self.finding(
                    title=f"DNS zone transfer allowed: {args.target}",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    target=args.target,
                    evidence=truncate("fierce Zone: success"),
                    remediation=(
                        "Restrict zone transfers to authorized secondaries "
                        "(e.g. allow-transfer) on the authoritative servers."
                    ),
                )
            )
        for name, address in _found_hosts(output, args.target):
            findings.append(
                self.finding(
                    title=f"Subdomain discovered: {name}",
                    severity=Severity.INFO,
                    confidence=0.85,
                    target=args.target,
                    endpoint=name,
                    evidence=truncate(f"fierce Found: {name} ({address})"),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: FierceArgs, output: str) -> list[str]:
        labels = _labeled_lines(output)
        found = len(_found_hosts(output, args.target))
        zone = _zone_status(output) or "unknown"
        if "Failed to lookup NS/SOA" in output:
            return [f"fierce: NS/SOA lookup failed for {args.target} (domain does not exist)"]
        note = f"fierce: {found} subdomain(s), zone={zone}"
        if labels.get("Wildcard"):
            note += f", wildcard={labels['Wildcard']}"
        return [note]


def _found_hosts(output: str, target: str) -> list[tuple[str, str]]:
    suffix = "." + target.lower()
    seen: set[str] = set()
    hosts: list[tuple[str, str]] = []
    for line in output.splitlines():
        match = _FOUND.match(line.strip())
        if match is None:
            continue
        name = match.group(1).lower().rstrip(".")
        if name in seen or name == target.lower() or not name.endswith(suffix):
            continue
        seen.add(name)
        hosts.append((name, match.group(2).strip()))
    return hosts


def _zone_status(output: str) -> str | None:
    for line in output.splitlines():
        match = _ZONE.match(line.strip())
        if match is not None:
            return match.group(1)
    return None


def _labeled_lines(output: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in output.splitlines():
        match = _LABELED.match(line.strip())
        if match is not None and match.group(1) not in labels:
            labels[match.group(1)] = match.group(2)
    return labels


__all__ = ["FierceArgs", "FierceTool"]
