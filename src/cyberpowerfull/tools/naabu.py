"""naabu wrapper: ProjectDiscovery port scanner with JSONL output."""

from __future__ import annotations

from pydantic import Field, field_validator

from cyberpowerfull.models import Capability, Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, json_lines, truncate


class NaabuArgs(HostInput):
    """Validated naabu invocation arguments."""

    top_ports: int = Field(default=1000, ge=1, le=65535)
    ports: list[int] = Field(default_factory=list, max_length=100)
    rate: int = Field(default=300, ge=10, le=1000)
    exclude_cdn: bool = True
    verify: bool = False

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, values: list[int]) -> list[int]:
        for value in values:
            if not 1 <= int(value) <= 65535:
                raise ValueError("ports must be within 1-65535")
        return values


class NaabuTool(BaseTool):
    name = "naabu"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "naabu"
    required_capability = Capability.AGGRESSIVE
    success_codes = (0,)
    timeout_s = 600
    description = (
        "Fast SYN/CONNECT port scanner with CDN exclusion. Use after passive recon "
        "to confirm the reachable port surface. Requires the 'aggressive' capability."
    )
    input_model = NaabuArgs

    def build_argv(self, args: NaabuArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "naabu",
            "-host",
            args.target,
            "-json",
            "-silent",
            "-rate",
            str(args.rate),
            "-disable-update-check",
        ]
        if args.ports:
            argv.extend(["-p", ",".join(str(port) for port in args.ports)])
        else:
            argv.extend(["-top-ports", str(args.top_ports)])
        if args.exclude_cdn:
            argv.append("-exclude-cdn")
        if args.verify:
            argv.append("-verify")
        return argv

    def parse(self, args: NaabuArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for record in json_lines(output):
            port = record.get("port")
            host = str(record.get("host") or record.get("ip") or args.target)
            if port is None:
                continue
            endpoint = f"{host}:{port}"
            if endpoint in seen:
                continue
            seen.add(endpoint)
            findings.append(
                self.finding(
                    title=f"Open TCP port {port} (naabu)",
                    severity=Severity.INFO,
                    confidence=0.85,
                    target=args.target,
                    endpoint=endpoint,
                    evidence=truncate(
                        f"naabu host={host} ip={record.get('ip')} port={port} "
                        f"tls={record.get('tls')}"
                    ),
                )
            )
        return findings

    def observations(self, args: NaabuArgs, output: str) -> list[str]:
        count = sum(1 for _ in json_lines(output))
        return [f"naabu: {count} open port(s) reported"]


__all__ = ["NaabuArgs", "NaabuTool"]
