"""subfinder wrapper: passive subdomain enumeration (one host per line)."""

from __future__ import annotations

import re

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,24}$")


class SubfinderArgs(HostInput):
    """Validated subfinder invocation arguments."""

    all_sources: bool = True
    recursive: bool = False
    max_findings: int = Field(default=50, ge=1, le=500)

    @field_validator("target")
    @classmethod
    def _check_domain(cls, value: str) -> str:
        if not _HOSTNAME.match(value):
            raise ValueError("subfinder requires a domain name, not an IP address")
        return value


class SubfinderTool(BaseTool):
    name = "subfinder"
    phase = Phase.RECON
    skill = "subdomain_takeover"
    binary = "subfinder"
    description = (
        "Passive subdomain enumeration. Feeds the attack tree with additional in-scope "
        "hosts that are re-validated against scope before any further action."
    )
    input_model = SubfinderArgs

    def build_argv(self, args: SubfinderArgs, out_file: str | None = None) -> list[str]:
        argv = ["subfinder", "-d", args.target, "-silent", "-disable-update-check"]
        if args.all_sources:
            argv.append("-all")
        if args.recursive:
            argv.append("-recursive")
        return argv

    def parse(self, args: SubfinderArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in output.splitlines():
            host = line.strip().lower()
            if not host or host in seen or not _HOSTNAME.match(host):
                continue
            if host != args.target and not host.endswith("." + args.target):
                continue
            seen.add(host)
            findings.append(
                self.finding(
                    title=f"Subdomain discovered: {host}",
                    severity=Severity.INFO,
                    confidence=0.8,
                    target=args.target,
                    endpoint=host,
                    evidence=truncate(f"passive source enumeration returned {host}"),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: SubfinderArgs, output: str) -> list[str]:
        return [f"subfinder: {len(self.parse(args, output))} unique host(s)"]


__all__ = ["SubfinderArgs", "SubfinderTool"]
