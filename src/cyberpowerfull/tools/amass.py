"""amass wrapper: passive subdomain enumeration (no active brute force)."""

from __future__ import annotations

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, truncate


class AmassArgs(DomainInput):
    """Validated amass invocation arguments."""

    timeout_minutes: int = Field(default=5, ge=1, le=30)
    max_findings: int = Field(default=200, ge=1, le=2000)


class AmassTool(BaseTool):
    name = "amass"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "amass"
    success_codes = (0,)
    timeout_s = 1900
    description = (
        "Passive subdomain enumeration across certificate transparency and public "
        "DNS datasets. Adds breadth to subfinder's source set."
    )
    input_model = AmassArgs

    def build_argv(self, args: AmassArgs, out_file: str | None = None) -> list[str]:
        return [
            "amass",
            "enum",
            "-d",
            args.target,
            "-passive",
            "-silent",
            "-noalts",
            "-timeout",
            str(args.timeout_minutes),
        ]

    def parse(self, args: AmassArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in output.splitlines():
            host = line.strip().lower()
            if not host or "." not in host or " " in host:
                continue
            if host.endswith("."):
                host = host.rstrip(".")
            if host in seen or host == args.target:
                continue
            seen.add(host)
            findings.append(
                self.finding(
                    title=f"Subdomain discovered: {host}",
                    severity=Severity.INFO,
                    confidence=0.8,
                    target=args.target,
                    endpoint=host,
                    evidence=truncate(f"amass passive enumeration returned {host}"),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: AmassArgs, output: str) -> list[str]:
        count = sum(1 for line in output.splitlines() if "." in line.strip())
        return [f"amass: {count} hostname line(s) returned"]


__all__ = ["AmassArgs", "AmassTool"]
