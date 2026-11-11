"""rustscan wrapper: ultra-fast port sweep, greppable output, no nmap stage.

Flags verified against RustScan/RustScan ``src/input.rs`` on main
(2026-11-11; latest release 2.4.1): ``-a`` addresses, ``-p``/``-r`` ports/range
(mutually exclusive upstream), ``--top``, ``-b`` batch size (default 4500),
``-t`` timeout ms (default 1500), ``--tries``, ``-u`` ulimit, ``--scan-order``,
``--scripts``, ``-g`` greppable, ``-e`` exclude ports, ``-x`` exclude
addresses, ``--udp``, ``--interval``.

The wrapper always passes ``-g --scripts none --no-banner``: discovery only,
no nmap follow-up (that is the ``nmap`` tool's job). Output lines are
``{ip} -> [80,443]`` (comma-separated, no spaces), verified in
``src/main.rs``.
"""

from __future__ import annotations

import re

from pydantic import Field, field_validator, model_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,24}$")
_RANGE_RE = re.compile(r"^\d{1,5}-\d{1,5}(,\d{1,5}-\d{1,5})*$")
#: ``192.0.2.1 -> [22,80,443]`` — ports comma-separated without spaces.
_RESULT_RE = re.compile(r"^(\S+) -> \[([0-9,\s]*)\]\s*$")


class RustscanArgs(HostInput):
    """Validated rustscan invocation arguments."""

    ports: list[int] | None = Field(default=None, max_length=200)
    port_range: str | None = Field(default=None, max_length=100)
    top_1000: bool = False
    batch_size: int = Field(default=4500, ge=1, le=65535)
    timeout_ms: int = Field(default=1500, ge=100, le=60000)
    tries: int = Field(default=1, ge=1, le=10)
    ulimit: int | None = Field(default=None, ge=1024, le=1000000)
    scan_order: str = "serial"
    udp: bool = False
    exclude_ports: list[int] = Field(default_factory=list, max_length=200)
    interval_ms: int = Field(default=0, ge=0, le=60000)
    max_findings: int = Field(default=200, ge=1, le=2000)

    @field_validator("target")
    @classmethod
    def _check_host(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "://" in cleaned or "/" in cleaned or ":" in cleaned:
            raise ValueError("rustscan requires a bare host or IP, not a URL")
        if not _HOSTNAME.match(cleaned):
            import ipaddress

            try:
                ipaddress.ip_address(cleaned)
            except ValueError:
                raise ValueError("rustscan requires a valid DNS name or IP address") from None
        return cleaned

    @field_validator("scan_order")
    @classmethod
    def _check_order(cls, value: str) -> str:
        if value not in {"serial", "random"}:
            raise ValueError("scan_order must be 'serial' or 'random'")
        return value

    @field_validator("ports", "exclude_ports")
    @classmethod
    def _check_ports(cls, values: list[int] | None) -> list[int] | None:
        if values is None:
            return None
        for value in values:
            if not 1 <= value <= 65535:
                raise ValueError(f"invalid port: {value}")
        return sorted(set(values))

    @field_validator("port_range")
    @classmethod
    def _check_range(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not _RANGE_RE.match(cleaned):
            raise ValueError("port_range must look like '1-1000' or '1-500,8000-9000'")
        for token in cleaned.split(","):
            start, _, end = token.partition("-")
            if int(start) > int(end) or int(end) > 65535 or int(start) < 1:
                raise ValueError(f"invalid port range: {token!r}")
        return cleaned

    @model_validator(mode="after")
    def _check_selection(self) -> RustscanArgs:
        chosen = [self.ports is not None, self.port_range is not None, self.top_1000]
        if sum(chosen) > 1:
            raise ValueError("choose one port selection: ports, port_range, or top_1000")
        return self


class RustscanTool(BaseTool):
    name = "rustscan"
    phase = Phase.SCANNING
    skill = "network_services"
    binary = "rustscan"
    # A full-range sweep opens tens of thousands of sockets; give it room.
    timeout_s = 900
    description = (
        "Ultra-fast TCP/UDP port sweep (discovery only, no nmap stage). Open ports "
        "feed later steps as exact port lists."
    )
    input_model = RustscanArgs

    def build_argv(self, args: RustscanArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "rustscan",
            "-a",
            args.target,
            "-g",
            "--scripts",
            "none",
            "--no-banner",
            "-b",
            str(args.batch_size),
            "-t",
            str(args.timeout_ms),
            "--tries",
            str(args.tries),
            "--scan-order",
            args.scan_order,
        ]
        if args.ports:
            argv.extend(["-p", ",".join(str(port) for port in args.ports)])
        if args.port_range:
            argv.extend(["-r", args.port_range])
        if args.top_1000:
            argv.append("--top")
        if args.ulimit is not None:
            argv.extend(["-u", str(args.ulimit)])
        if args.udp:
            argv.append("--udp")
        if args.exclude_ports:
            argv.extend(["-e", ",".join(str(port) for port in args.exclude_ports)])
        if args.interval_ms:
            argv.extend(["--interval", str(args.interval_ms)])
        return argv

    def parse(self, args: RustscanArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        proto = "udp" if args.udp else "tcp"
        for line in output.splitlines():
            match = _RESULT_RE.match(line.strip())
            if not match:
                continue
            ip, ports_text = match.group(1), match.group(2)
            for token in ports_text.split(","):
                token = token.strip()
                if not token.isdigit():
                    continue
                port = int(token)
                if not 1 <= port <= 65535:
                    continue
                findings.append(
                    self.finding(
                        title=f"Open {proto} port: {port}",
                        severity=Severity.INFO,
                        confidence=0.9,
                        target=args.target,
                        endpoint=f"{ip}:{port}",
                        evidence=truncate(f"rustscan open {proto} port={port} state=open"),
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings
        return findings

    def observations(self, args: RustscanArgs, output: str) -> list[str]:
        count = len(self.parse(args, output))
        capped = " (capped)" if count >= args.max_findings else ""
        return [f"rustscan: {count} open port(s){capped}"]


__all__ = ["RustscanArgs", "RustscanTool"]
