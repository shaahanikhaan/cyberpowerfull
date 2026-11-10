"""nmap wrapper: port and service discovery parsed from XML on stdout."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

_PORT_SPEC = re.compile(r"^(top-\d{1,5}|[0-9][0-9,\-]{0,255})$")

#: NSE scripts the agent is allowed to request. Anything else is rejected so the
#: model cannot turn nmap into an arbitrary scripting engine.
SAFE_SCRIPTS = frozenset(
    {
        "http-title",
        "http-headers",
        "http-server-header",
        "http-methods",
        "ssl-cert",
        "ssl-enum-ciphers",
        "dns-service-discovery",
        "smb-os-discovery",
        "ssh-auth-methods",
    }
)


class NmapArgs(HostInput):
    """Validated nmap invocation arguments."""

    ports: str = "top-1000"
    service_detection: bool = True
    default_scripts: bool = False
    timing: int = Field(default=3, ge=0, le=5)
    scripts: list[str] = Field(default_factory=list)

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, value: str) -> str:
        if not _PORT_SPEC.match(value):
            raise ValueError("ports must be 'top-N' or a comma/dash separated port list")
        return value

    @field_validator("scripts")
    @classmethod
    def _check_scripts(cls, values: list[str]) -> list[str]:
        for value in values:
            if value not in SAFE_SCRIPTS:
                raise ValueError(f"script not in allowlist: {value!r}")
        return values


class NmapTool(BaseTool):
    name = "nmap"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "nmap"
    description = (
        "TCP port and service discovery. Use first to map the attack surface; "
        "supports top-port scans and safe NSE service scripts."
    )
    input_model = NmapArgs

    def build_argv(self, args: NmapArgs, out_file: str | None = None) -> list[str]:
        argv = ["nmap", "-oX", "-", "-Pn", f"-T{args.timing}"]
        if args.service_detection:
            argv.append("-sV")
        if args.default_scripts:
            argv.append("-sC")
        if args.scripts:
            argv.extend(["--script", ",".join(args.scripts)])
        if args.ports.startswith("top-"):
            argv.extend(["--top-ports", args.ports[4:]])
        else:
            argv.extend(["-p", args.ports])
        argv.append(args.target)
        return argv

    def parse(self, args: NmapArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not output.strip():
            return findings
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return findings
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            endpoint = f"{args.target}:{port_id}"
            evidence = f"nmap -sV state=open port={port_id}/{protocol} service={service_name}"
            findings.append(
                self.finding(
                    title=f"Open TCP port {port_id}/{protocol} ({service_name})",
                    severity=Severity.INFO,
                    confidence=0.95,
                    target=args.target,
                    endpoint=endpoint,
                    evidence=evidence,
                    cwe=None,
                )
            )
            if product or version:
                banner = " ".join(part for part in (product, version) if part)
                findings.append(
                    self.finding(
                        title=f"Service banner disclosure on {port_id}/{protocol}: {banner}",
                        severity=Severity.LOW,
                        confidence=0.8,
                        target=args.target,
                        endpoint=endpoint,
                        evidence=truncate(f"{evidence} banner={banner}"),
                        remediation=(
                            "Suppress server version banners and patch the disclosed version."
                        ),
                    )
                )
        return findings

    def observations(self, args: NmapArgs, output: str) -> list[str]:
        notes: list[str] = []
        try:
            root = ET.fromstring(output) if output.strip() else None
        except ET.ParseError:
            return ["nmap output was not valid XML"]
        if root is None:
            return notes
        for script in root.iter("script"):
            notes.append(
                truncate(f"nse:{script.get('id', 'unknown')} {script.get('output', '')}", 200)
            )
        return notes


def parse_nmap_args(payload: dict[str, Any]) -> NmapArgs:  # pragma: no cover - convenience
    return NmapArgs.model_validate(payload)


__all__ = ["SAFE_SCRIPTS", "NmapArgs", "NmapTool"]
