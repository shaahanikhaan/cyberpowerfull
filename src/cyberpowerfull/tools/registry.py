"""Tool registry: the single source of truth for what the agent can execute."""

from __future__ import annotations

from typing import Any

from cyberpowerfull.errors import ToolNotFound
from cyberpowerfull.tools.base import BaseTool
from cyberpowerfull.tools.dalfox import DalfoxTool
from cyberpowerfull.tools.ffuf import FfufTool
from cyberpowerfull.tools.httpx_probe import HttpxTool
from cyberpowerfull.tools.nikto import NiktoTool
from cyberpowerfull.tools.nmap import NmapTool
from cyberpowerfull.tools.nuclei import NucleiTool
from cyberpowerfull.tools.sqlmap import SqlmapTool
from cyberpowerfull.tools.subfinder import SubfinderTool
from cyberpowerfull.tools.tcp_probe import TcpProbeTool

_TOOL_CLASSES: tuple[type[BaseTool], ...] = (
    NmapTool,
    HttpxTool,
    SubfinderTool,
    NucleiTool,
    NiktoTool,
    FfufTool,
    SqlmapTool,
    DalfoxTool,
    TcpProbeTool,
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


__all__ = ["all_tools", "catalog", "get_tool", "installed_tools", "tool_names"]
