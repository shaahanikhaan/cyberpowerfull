"""dnsenum wrapper: DNS enumeration with brute-force and reverse lookups.

Flags verified against fwaeytens/dnsenum (``dnsenum.pl`` ``GetOptions`` and
``usage()`` on main, 2026-11-11): the domain is positional and last,
``-f`` feeds subdomain brute-forcing (without it dnsenum stops after zone
transfers and Google scraping), ``-s``/``-p`` bound Google scraping,
``-o`` writes MagicTree XML (``<magictree><testdata>`` with ``<host>`` IP
elements wrapping ``<hostname>`` plus ``<fqdn>`` entries, all through
``xml_host`` — including zone-transfer records). AXFR success is not
labelled in the XML, so transfer detection stays with the dnsrecon wrapper.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET

from pydantic import Field, field_validator, model_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, truncate


class DnsenumArgs(DomainInput):
    """Validated dnsenum invocation arguments."""

    threads: int = Field(default=5, ge=1, le=16)
    timeout: int = Field(default=10, ge=1, le=120)
    dnsserver: str | None = Field(default=None, max_length=64)
    bruteforce: bool = False
    wordlist: str | None = Field(default=None, max_length=500)
    recursion: bool = False
    scrap_subdomains: int = Field(default=0, ge=0, le=100)
    scrap_pages: int = Field(default=5, ge=1, le=10)
    whois: bool = False
    noreverse: bool = False
    max_findings: int = Field(default=50, ge=1, le=500)

    @field_validator("dnsserver")
    @classmethod
    def _check_dnsserver(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        try:
            ipaddress.ip_address(cleaned)
        except ValueError as exc:
            raise ValueError(f"dnsserver must be an IP address: {value!r}") from exc
        return cleaned

    @model_validator(mode="after")
    def _check_combinations(self) -> DnsenumArgs:
        if self.bruteforce and not self.wordlist:
            raise ValueError("dnsenum bruteforce needs a wordlist")
        if self.wordlist and not self.bruteforce:
            raise ValueError("wordlist is only used with bruteforce=True")
        if self.recursion and not self.bruteforce:
            raise ValueError(
                "dnsenum recursion needs bruteforce=True (dnsenum exits early without -f)"
            )
        if self.scrap_subdomains == 0 and self.scrap_pages != 5:
            raise ValueError("scrap_pages is only used with scrap_subdomains>0")
        return self


class DnsenumTool(BaseTool):
    name = "dnsenum"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "dnsenum"
    writes_output_file = True
    timeout_s = 600
    description = (
        "DNS enumeration: NS/MX records, zone transfers, Google scraping, "
        "subdomain brute-force and reverse lookups."
    )
    input_model = DnsenumArgs

    def build_argv(self, args: DnsenumArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "dnsenum",
            "--threads",
            str(args.threads),
            "-t",
            str(args.timeout),
            "--nocolor",
        ]
        if out_file:
            argv.extend(["-o", out_file])
        if args.dnsserver:
            argv.extend(["--dnsserver", args.dnsserver])
        if args.bruteforce:
            argv.extend(["-f", args.wordlist or ""])
        if args.scrap_subdomains > 0:
            argv.extend(["-s", str(args.scrap_subdomains), "-p", str(args.scrap_pages)])
        if args.recursion:
            argv.append("-r")
        if args.whois:
            argv.append("-w")
        if args.noreverse:
            argv.append("--noreverse")
        argv.append(args.target)
        return argv

    def parse(self, args: DnsenumArgs, output: str, out_file: str | None = None) -> list[Finding]:
        hosts = _load_hosts(output)
        findings: list[Finding] = []
        seen: set[str] = set()
        for hostname, address in hosts:
            if not hostname or hostname in seen:
                continue
            seen.add(hostname)
            findings.append(
                self.finding(
                    title=f"Subdomain discovered: {hostname}",
                    severity=Severity.INFO,
                    confidence=0.85,
                    target=args.target,
                    endpoint=hostname,
                    evidence=truncate(f"dnsenum host={hostname} ip={address or 'unknown'}"),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: DnsenumArgs, output: str) -> list[str]:
        hosts = _load_hosts(output)
        with_ip = sum(1 for _, address in hosts if address)
        return [
            f"dnsenum: {len(hosts)} hostname(s), {with_ip} with address(es), "
            f"bruteforce={args.bruteforce}"
        ]


def _load_hosts(output: str) -> list[tuple[str, str]]:
    """Return ``(hostname, ip)`` pairs from dnsenum MagicTree XML."""
    try:
        root = ET.fromstring(output.strip())
    except ET.ParseError:
        return []
    hosts: list[tuple[str, str]] = []
    for element in root.iter("host"):
        hostname_element = element.find("hostname")
        hostname = (
            (hostname_element.text or "").strip().lower().rstrip(".")
            if hostname_element is not None
            else ""
        )
        address = "".join(element.itertext()).replace(hostname_element.text or "", "")
        address = address.strip() if hostname_element is not None else ""
        if hostname:
            hosts.append((hostname, address))
    for element in root.iter("fqdn"):
        hostname = (element.text or "").strip().lower().rstrip(".")
        if hostname:
            hosts.append((hostname, ""))
    return hosts


__all__ = ["DnsenumArgs", "DnsenumTool"]
