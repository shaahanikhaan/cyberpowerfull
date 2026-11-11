"""shuffledns wrapper: massdns-backed subdomain brute-force and resolving.

Flags verified against projectdiscovery/shuffledns (README ``Flags`` plus
``pkg/runner/options.go`` on main, 2026-11-11): ``-d`` is the domain,
``-mode`` is ``bruteforce`` (needs ``-w`` wordlist) or ``resolve`` (needs
``-l`` subdomain list), ``-r``/``-tr`` take resolver files, ``-o`` is the
output file, ``-j`` emits ndjson (``{"hostname": ...}`` only, see
``pkg/massdns/process.go`` ``writeOutput``), ``-t`` bounds concurrent
resolves, ``-sw`` strict-checks wildcards. Trusted resolvers re-verify
every hit, so wildcard noise drops when they are provided. ``-r`` accepts
only a file, so this wrapper materialises the validated resolver IPs into
the run-owned output directory next to the output file (never the repo).
Requires the ``massdns`` binary beside ``shuffledns`` at runtime.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, json_lines, truncate


class ShufflednsArgs(DomainInput):
    """Validated shuffledns invocation arguments."""

    mode: Literal["bruteforce", "resolve"] = "bruteforce"
    wordlist: str | None = Field(default=None, max_length=500)
    subdomains_file: str | None = Field(default=None, max_length=500)
    resolvers: list[str] = Field(min_length=1, max_length=10)
    trusted_resolvers: list[str] = Field(default_factory=list, max_length=10)
    resolves: int = Field(default=10000, ge=100, le=20000)
    strict_wildcard: bool = False
    max_findings: int = Field(default=100, ge=1, le=500)

    @field_validator("resolvers", "trusted_resolvers")
    @classmethod
    def _check_ips(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                ipaddress.ip_address(value.strip())
            except ValueError as exc:
                raise ValueError(f"resolver must be an IP address: {value!r}") from exc
        return [value.strip() for value in values]

    @model_validator(mode="after")
    def _check_mode_files(self) -> ShufflednsArgs:
        if self.mode == "bruteforce":
            if not self.wordlist:
                raise ValueError("shuffledns bruteforce needs a wordlist")
            if self.subdomains_file:
                raise ValueError("subdomains_file is only used with mode='resolve'")
        else:
            if not self.subdomains_file:
                raise ValueError("shuffledns resolve needs a subdomains_file")
            if self.wordlist:
                raise ValueError("wordlist is only used with mode='bruteforce'")
        return self


class ShufflednsTool(BaseTool):
    name = "shuffledns"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "shuffledns"
    writes_output_file = True
    timeout_s = 600
    description = (
        "Massdns-backed subdomain brute-force and resolving with wildcard "
        "handling. Hits are re-validated against scope before further action."
    )
    input_model = ShufflednsArgs

    def build_argv(self, args: ShufflednsArgs, out_file: str | None = None) -> list[str]:
        if out_file is None:
            raise InvalidToolArguments(
                "shuffledns needs an output file to stage its resolvers next to"
            )
        directory = Path(out_file).parent
        resolvers_file = directory / "cpf-resolvers.txt"
        resolvers_file.write_text("\n".join(args.resolvers) + "\n", encoding="utf-8")
        argv = ["shuffledns", "-d", args.target, "-mode", args.mode]
        if args.mode == "bruteforce":
            argv.extend(["-w", args.wordlist or ""])
        else:
            argv.extend(["-l", args.subdomains_file or ""])
        argv.extend(["-r", str(resolvers_file)])
        if args.trusted_resolvers:
            trusted_file = directory / "cpf-trusted-resolvers.txt"
            trusted_file.write_text("\n".join(args.trusted_resolvers) + "\n", encoding="utf-8")
            argv.extend(["-tr", str(trusted_file)])
        argv.extend(["-t", str(args.resolves)])
        if args.strict_wildcard:
            argv.append("-sw")
        argv.extend(["-o", out_file, "-j", "-silent", "-nc", "-duc"])
        return argv

    def parse(
        self, args: ShufflednsArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for record in json_lines(output):
            hostname = str(record.get("hostname") or "").strip().lower().rstrip(".")
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
                    evidence=truncate(f"shuffledns mode={args.mode} host={hostname}"),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: ShufflednsArgs, output: str) -> list[str]:
        count = sum(1 for _ in json_lines(output))
        return [f"shuffledns: {count} hostname(s), mode={args.mode}"]


__all__ = ["ShufflednsArgs", "ShufflednsTool"]
