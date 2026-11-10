"""Native TCP connect probe.

This tool exists so the agent still produces evidence on a host where no external
scanner binary is installed (unit tests, minimal lab images, CI). It performs a
plain TCP connect - no payloads, no fingerprinting beyond the port number.
"""

from __future__ import annotations

import json
import socket
import time
from typing import ClassVar

from pydantic import Field, field_validator

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, _Exec, truncate

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
        open_ports: list[int] = []
        errors: dict[str, str] = {}
        for port in args.ports:
            try:
                with socket.create_connection((args.target, port), timeout=args.timeout_s):
                    open_ports.append(port)
            except OSError as exc:
                errors[str(port)] = exc.__class__.__name__
            if time.perf_counter() - started > self.timeout_s:
                return _Exec(
                    stdout=json.dumps({"open": open_ports, "errors": errors}),
                    status=self._status(open_ports),
                    error="tcp_probe exceeded its total time budget",
                )
        return _Exec(stdout=json.dumps({"open": open_ports, "errors": errors}))

    @staticmethod
    def _status(open_ports: list[int]) -> object:
        from cyberpowerfull.tools.base import ToolStatus

        return ToolStatus.OK if open_ports else ToolStatus.ERROR

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
                        title=f"Sensitive service port exposed: {port_int}/tcp ({service})",
                        severity=Severity.LOW,
                        confidence=0.6,
                        target=args.target,
                        endpoint=f"{args.target}:{port_int}",
                        evidence=truncate(
                            f"tcp connect succeeded on {port_int}; service={service}"
                        ),
                        remediation=(
                            f"Restrict network access to {service} and require authentication."
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
                        endpoint=f"{args.target}:{port_int}",
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
