"""Tool registry: the single source of truth for what the agent can execute."""

from __future__ import annotations

from typing import Any

from cyberpowerfull.errors import ToolNotFound
from cyberpowerfull.tools.amass import AmassTool
from cyberpowerfull.tools.arjun import ArjunTool
from cyberpowerfull.tools.base import BaseTool
from cyberpowerfull.tools.cve_correlate import CveCorrelateTool
from cyberpowerfull.tools.dalfox import DalfoxTool
from cyberpowerfull.tools.dnsrecon import DnsreconTool
from cyberpowerfull.tools.dnsx import DnsxTool
from cyberpowerfull.tools.feroxbuster import FeroxbusterTool
from cyberpowerfull.tools.ffuf import FfufTool
from cyberpowerfull.tools.gitleaks import GitleaksTool
from cyberpowerfull.tools.gobuster import GobusterTool
from cyberpowerfull.tools.http_probe import HttpProbeTool
from cyberpowerfull.tools.httpx_probe import HttpxTool
from cyberpowerfull.tools.hydra import HydraTool
from cyberpowerfull.tools.katana import KatanaTool
from cyberpowerfull.tools.kubebench import KubebenchTool
from cyberpowerfull.tools.kubescape import KubescapeTool
from cyberpowerfull.tools.masscan import MasscanTool
from cyberpowerfull.tools.metasploit import MetasploitTool
from cyberpowerfull.tools.naabu import NaabuTool
from cyberpowerfull.tools.netexec import NetexecTool
from cyberpowerfull.tools.nikto import NiktoTool
from cyberpowerfull.tools.nmap import NmapTool
from cyberpowerfull.tools.nuclei import NucleiTool
from cyberpowerfull.tools.payload import PayloadTool
from cyberpowerfull.tools.pentagi import PentagiTool
from cyberpowerfull.tools.prowler import ProwlerTool
from cyberpowerfull.tools.rustscan import RustscanTool
from cyberpowerfull.tools.searchsploit import SearchsploitTool
from cyberpowerfull.tools.semgrep import SemgrepTool
from cyberpowerfull.tools.sn1per import Sn1perTool
from cyberpowerfull.tools.sqlmap import SqlmapTool
from cyberpowerfull.tools.strix import StrixTool
from cyberpowerfull.tools.subfinder import SubfinderTool
from cyberpowerfull.tools.tcp_probe import TcpProbeTool
from cyberpowerfull.tools.testssl import TestsslTool
from cyberpowerfull.tools.tlsx import TlsxTool
from cyberpowerfull.tools.trivy import TrivyTool
from cyberpowerfull.tools.trufflehog import TrufflehogTool
from cyberpowerfull.tools.uncover import UncoverTool
from cyberpowerfull.tools.wafw00f import Wafw00fTool
from cyberpowerfull.tools.whatweb import WhatwebTool
from cyberpowerfull.tools.wpscan import WpscanTool
from cyberpowerfull.tools.zaproxy import ZapTool

_TOOL_CLASSES: tuple[type[BaseTool], ...] = (
    # native
    TcpProbeTool,
    HttpProbeTool,
    PayloadTool,
    CveCorrelateTool,
    # recon / discovery
    SubfinderTool,
    AmassTool,
    DnsreconTool,
    DnsxTool,
    UncoverTool,
    HttpxTool,
    KatanaTool,
    KubebenchTool,
    KubescapeTool,
    Wafw00fTool,
    # scanning
    NmapTool,
    MasscanTool,
    NaabuTool,
    NetexecTool,
    RustscanTool,
    MetasploitTool,
    WhatwebTool,
    NiktoTool,
    FfufTool,
    GitleaksTool,
    GobusterTool,
    FeroxbusterTool,
    ArjunTool,
    TestsslTool,
    TrivyTool,
    TrufflehogTool,
    TlsxTool,
    WpscanTool,
    ZapTool,
    # validation
    NucleiTool,
    SemgrepTool,
    SqlmapTool,
    DalfoxTool,
    SearchsploitTool,
    HydraTool,
    # external autonomous systems
    StrixTool,
    PentagiTool,
    ProwlerTool,
    Sn1perTool,
)

_TOOLS: dict[str, BaseTool] = {cls.name: cls() for cls in _TOOL_CLASSES}


def all_tools() -> dict[str, BaseTool]:
    """Return a copy of the registry mapping (name -> tool instance)."""
    return dict(_TOOLS)


def tool_names() -> list[str]:
    return sorted(_TOOLS)


def get_tool(name: str) -> BaseTool:
    """Look up a tool by name, raising :class:`ToolNotFound` when absent."""
    try:
        return _TOOLS[name]
    except KeyError as exc:
        raise ToolNotFound(
            f"unknown tool {name!r}; available tools: {', '.join(tool_names())}"
        ) from exc


def catalog() -> list[dict[str, Any]]:
    """Machine-readable catalogue injected into the system prompt."""
    return [tool.describe() for tool in _TOOLS.values()]


def installed_tools() -> list[str]:
    return [name for name, tool in _TOOLS.items() if tool.describe()["installed"]]


def external_tools() -> list[str]:
    return sorted(name for name, tool in _TOOLS.items() if tool.external)


def by_phase(phase: str) -> list[str]:
    return sorted(name for name, tool in _TOOLS.items() if tool.phase.value == phase)


def external_agent_catalog() -> list[dict[str, Any]]:
    """Describe the external autonomous agents this build can drive."""
    from cyberpowerfull.inventory import build_toolchain

    toolchain = build_toolchain(include_wordlists=False)
    rows: list[dict[str, Any]] = []
    for name in external_tools():
        tool = _TOOLS[name]
        agent_key = {"sn1per": "sn1per", "strix": "strix", "pentagi": "pentagi"}.get(name, name)
        info = toolchain.external_agents.get(agent_key, {})
        rows.append(
            {
                "tool": name,
                "phase": tool.phase.value,
                "binary": tool.binary or "http-api",
                "available": (
                    bool(info.get("available")) if info else bool(tool.describe()["installed"])
                ),
                "requires": info.get("requires", []),
                "capability": tool.required_capability.value if tool.required_capability else None,
                "description": tool.description,
            }
        )
    return rows


__all__ = [
    "all_tools",
    "by_phase",
    "catalog",
    "external_agent_catalog",
    "external_tools",
    "get_tool",
    "installed_tools",
    "tool_names",
]
