"""masscan wrapper: high-rate TCP port sweep, JSON output on stdout."""

from __future__ import annotations

import json
import re

from pydantic import Field, field_validator

from cyberpowerfull.models import Capability, Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

_PORT_SPEC = re.compile(r"^[0-9][0-9,\-]{0,255}$")


class MasscanArgs(HostInput):
    """Validated masscan invocation arguments."""

    ports: str = Field(default="1-1024", min_length=1, max_length=256)
    rate: int = Field(default=500, ge=10, le=2000)
    wait_s: int = Field(default=3, ge=0, le=30)

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, value: str) -> str:
        if not _PORT_SPEC.match(value):
            raise ValueError("ports must be a comma/dash separated port list")
        return value


class MasscanTool(BaseTool):
    name = "masscan"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "masscan"
    required_capability = Capability.AGGRESSIVE
    success_codes = (0, 1)
    timeout_s = 600
    description = (
        "Asynchronous TCP port sweep for wide ranges (much faster than nmap). "
        "Requires the 'aggressive' scope capability because it generates heavy traffic."
    )
    input_model = MasscanArgs

    def build_argv(self, args: MasscanArgs, out_file: str | None = None) -> list[str]:
        return [
            "masscan",
            args.target,
            "-p",
            args.ports,
            "--rate",
            str(args.rate),
            "--wait",
            str(args.wait_s),
            "-oJ",
            "-",
        ]

    def parse(self, args: MasscanArgs, output: str, out_file: str | None = None) -> list[Finding]:
        payload = _first_json_array(output)
        if payload is None:
            return []
        findings: list[Finding] = []
        for host in payload:
            if not isinstance(host, dict):
                continue
            ip = str(host.get("ip") or args.target)
            for port in host.get("ports") or []:
                if not isinstance(port, dict):
                    continue
                if str(port.get("status", "open")).lower() != "open":
                    continue
                port_id = port.get("port")
                proto = str(port.get("proto") or "tcp")
                service = port.get("service")
                findings.append(
                    self.finding(
                        title=f"Open {proto} port {port_id} (masscan)",
                        severity=Severity.INFO,
                        confidence=0.9,
                        target=args.target,
                        endpoint=f"{ip}:{port_id}",
                        evidence=truncate(
                            f"masscan state=open ip={ip} port={port_id}/{proto} "
                            f"service={service or 'unknown'}"
                        ),
                    )
                )
        return findings

    def observations(self, args: MasscanArgs, output: str) -> list[str]:
        count = len(self.parse(args, output))
        return [f"masscan: {count} open port(s) in {args.ports} at {args.rate} pps"]


def _first_json_array(text: str) -> list | None:
    """Return the first decodable JSON array in ``text``.

    masscan prints progress banners (``[INFO] ...``) before the JSON body, so a
    greedy regex or a single ``json.loads`` would both fail on real output.
    """
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "[":
            continue
        try:
            value, _end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            return value
    return None


__all__ = ["MasscanArgs", "MasscanTool"]
