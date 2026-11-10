"""Native TCP connect probe.

This tool exists so the agent still produces evidence on a host where no external
scanner binary is installed (unit tests, minimal lab images, CI). It performs a
plain TCP connect - no payloads, no fingerprinting beyond the port number.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from typing import ClassVar

from pydantic import Field, field_validator

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.scope import network_contains
from cyberpowerfull.tools.base import BaseTool, HostInput, ToolStatus, _Exec, host_port, truncate

DEFAULT_PORTS = [22, 80, 443, 3306, 5432, 6379, 8000, 8080, 8443, 27017]

#: Ports whose exposure is worth a stronger signal than plain "open".
SENSITIVE_PORTS = {
    23: "telnet",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


class TcpProbeArgs(HostInput):
    """Validated TCP probe arguments."""

    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS), max_length=64)
    timeout_s: float = Field(default=1.5, ge=0.1, le=10.0)

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, values: list[int]) -> list[int]:
        if not values:
            raise ValueError("at least one port is required")
        for value in values:
            if not 1 <= int(value) <= 65535:
                raise ValueError("ports must be within 1-65535")
        return [int(value) for value in values]


class TcpProbeTool(BaseTool):
    name = "tcp_probe"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary: ClassVar[str | None] = None
    timeout_s = 60
    description = (
        "Native TCP connect scan of an explicit port list. Requires no external binary; "
        "used to confirm reachability and expose sensitive services."
    )
    input_model = TcpProbeArgs

    def build_argv(self, args: TcpProbeArgs, out_file: str | None = None) -> list[str]:
        return [
            "tcp_probe",
            "--host",
            args.target,
            "--ports",
            ",".join(str(port) for port in args.ports),
            "--timeout",
            str(args.timeout_s),
        ]

    def _execute(self, args: TcpProbeArgs, argv: list[str], policy: ToolPolicy) -> _Exec:
        started = time.perf_counter()
        deadline = started + min(self.timeout_s, policy.timeout_s)
        open_ports: list[int] = []
        errors: dict[str, str] = {}
        try:
            addresses = socket.getaddrinfo(args.target, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            return _Exec(status=ToolStatus.ERROR, error=f"tcp_probe DNS lookup failed: {exc}")
        hosts = list(dict.fromkeys(item[4][0] for item in addresses))
        denied = [ipaddress.ip_network(item, strict=False) for item in policy.excluded_networks]

        def denied_address(host: str) -> bool:
            address = ipaddress.ip_address(host.split("%", 1)[0])
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            return any(network_contains(network, address) for network in denied)

        if args.target == "localhost" and any(
            not ipaddress.ip_address(host.split("%", 1)[0]).is_loopback for host in hosts
        ):
            return _Exec(status=ToolStatus.BLOCKED, error="localhost resolved outside loopback")
        if any(denied_address(host) for host in hosts):
            return _Exec(
                status=ToolStatus.BLOCKED,
                error="tcp_probe DNS resolved to an excluded network",
            )
        if not hosts:
            return _Exec(status=ToolStatus.ERROR, error="tcp_probe DNS returned no addresses")

        next_connect = started
        for port in args.ports:
            for host in hosts:
                wait = max(0.0, next_connect - time.perf_counter())
                remaining = deadline - time.perf_counter()
                if wait >= remaining:
                    return _Exec(
                        stdout=json.dumps({"open": open_ports, "errors": errors}),
                        status=ToolStatus.TIMEOUT,
                        error="tcp_probe exceeded its total time budget",
                    )
                if wait:
                    time.sleep(wait)
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return _Exec(
                        stdout=json.dumps({"open": open_ports, "errors": errors}),
                        status=ToolStatus.TIMEOUT,
                        error="tcp_probe exceeded its total time budget",
                    )
                if policy.max_rps:
                    next_connect = time.perf_counter() + 1 / policy.max_rps
                try:
                    # Connect to the checked address rather than resolving again.
                    with socket.create_connection(
                        (host, port), timeout=min(args.timeout_s, remaining)
                    ):
                        open_ports.append(port)
                        errors.pop(str(port), None)
                        break
                except OSError as exc:
                    errors[str(port)] = exc.__class__.__name__
        return _Exec(stdout=json.dumps({"open": open_ports, "errors": errors}))

    def parse(self, args: TcpProbeArgs, output: str, out_file: str | None = None) -> list[Finding]:
        if not output.strip():
            return []
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for port in payload.get("open", []):
            port_int = int(port)
            service = SENSITIVE_PORTS.get(port_int)
            if service:
                findings.append(
                    self.finding(
                        title=f"Open TCP port {port_int} (commonly used by {service})",
                        severity=Severity.INFO,
                        confidence=0.9,
                        target=args.target,
                        endpoint=host_port(args.target, port_int),
                        evidence=truncate(
                            f"tcp connect succeeded on {port_int}; {service} is a common "
                            "port association, not a confirmed service"
                        ),
                        remediation=(
                            "Identify the service, restrict access if needed, "
                            "and require authentication."
                        ),
                    )
                )
            else:
                findings.append(
                    self.finding(
                        title=f"Open TCP port {port_int}",
                        severity=Severity.INFO,
                        confidence=0.9,
                        target=args.target,
                        endpoint=host_port(args.target, port_int),
                        evidence=truncate(f"tcp connect succeeded on {port_int}"),
                    )
                )
        return findings

    def observations(self, args: TcpProbeArgs, output: str) -> list[str]:
        try:
            payload = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return ["tcp_probe produced unparsable output"]
        notes = [f"tcp_probe open={payload.get('open', [])}"]
        errors = payload.get("errors") or {}
        if errors:
            notes.append(f"tcp_probe closed/filtered={sorted(errors)[:10]}")
        return notes


__all__ = ["DEFAULT_PORTS", "SENSITIVE_PORTS", "TcpProbeArgs", "TcpProbeTool"]
