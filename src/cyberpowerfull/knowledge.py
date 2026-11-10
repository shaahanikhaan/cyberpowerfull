"""Read-only access to the local security knowledge base on the host.

Everything here is derived from files that already exist on the machine:
the Exploit-DB mirror queried through ``searchsploit``, the nuclei template
repository, the Nmap NSE script directory, and the installed wordlists. No
network access, no bundled datasets, no placeholder records.

These readers power ``--search-exploits``, ``--templates`` and ``--wordlists``,
and they are used by the planner to decide which checks are even possible on the
current host.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberpowerfull import inventory
from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.errors import CyberpowerfullError
from cyberpowerfull.inventory import (
    Toolchain,
    build_toolchain,
    install_hint,
    pick_wordlist,
)


class KnowledgeUnavailable(CyberpowerfullError):
    """Raised when the local knowledge source is not installed."""

    exit_code = 6


@dataclass(frozen=True)
class ExploitRecord:
    """One local Exploit-DB record."""

    edb_id: str
    title: str
    path: str
    date: str
    exploit_type: str
    platform: str

    def as_dict(self) -> dict[str, str]:
        return {
            "edb_id": self.edb_id,
            "title": self.title,
            "path": self.path,
            "date": self.date,
            "type": self.exploit_type,
            "platform": self.platform,
        }


def search_exploit_db(query: str, *, limit: int = 25) -> list[ExploitRecord]:
    """Query the locally installed Exploit-DB mirror.

    Raises :class:`KnowledgeUnavailable` when ``searchsploit`` is absent, because
    an empty result would be indistinguishable from "no such exploit" and that
    difference matters.
    """
    binary = shutil.which("searchsploit")
    if binary is None:
        hint = install_hint("searchsploit") or "apt install exploitdb"
        raise KnowledgeUnavailable(f"searchsploit is not installed ({hint})")
    try:
        proc = subprocess.run(
            [binary, "--json", query],
            capture_output=True,
            text=True,
            timeout=60,
            env=ToolPolicy().sanitized_env(),
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KnowledgeUnavailable(f"searchsploit failed to start: {exc}") from exc
    text = (proc.stdout or "").strip()
    if not text:
        return []
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return []
    try:
        payload = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return []
    records = payload.get("RESULTS_EXPLOIT") or []
    results: list[ExploitRecord] = []
    for item in records[:limit]:
        if not isinstance(item, dict):
            continue
        results.append(
            ExploitRecord(
                edb_id=str(item.get("EDB-ID") or item.get("EDBID") or "?"),
                title=str(item.get("Title") or ""),
                path=str(item.get("Path") or ""),
                date=str(item.get("Date") or ""),
                exploit_type=str(item.get("Type") or ""),
                platform=str(item.get("Platform") or ""),
            )
        )
    return results


def _template_root() -> Path | None:
    for candidate in inventory.NUCLEI_TEMPLATE_ROOTS:
        path = Path(candidate).expanduser()
        try:
            if path.is_dir():
                return path
        except OSError:
            continue
    return None


def nuclei_template_paths(pattern: str = "", *, limit: int = 200) -> list[str]:
    """Return relative paths of real nuclei templates, filtered by substring."""
    root = _template_root()
    if root is None:
        hint = install_hint("nuclei") or "apt install nuclei"
        raise KnowledgeUnavailable(f"nuclei-templates is not installed ({hint})")
    needle = pattern.strip().lower()
    found: list[str] = []
    for dirpath, _dirnames, filenames in _walk(root):
        for filename in filenames:
            if not filename.endswith((".yaml", ".yml")):
                continue
            full = Path(dirpath) / filename
            relative = str(full.relative_to(root))
            if needle and needle not in relative.lower():
                continue
            found.append(relative)
            if len(found) >= limit:
                return sorted(found)
    return sorted(found)


def _walk(root: Path):
    import os

    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        dirnames[:] = sorted(name for name in dirnames if not name.startswith("."))
        yield dirpath, dirnames, sorted(filenames)


def nmap_script_paths(pattern: str = "", *, limit: int = 200) -> list[str]:
    """Return the NSE scripts installed on this host, filtered by substring."""
    root = Path("/usr/share/nmap/scripts")
    try:
        if not root.is_dir():
            raise KnowledgeUnavailable("nmap NSE scripts are not installed (apt install nmap)")
    except OSError as exc:  # pragma: no cover - permission edge
        raise KnowledgeUnavailable(str(exc)) from exc
    needle = pattern.strip().lower()
    found = sorted(
        path.name for path in root.glob("*.nse") if not needle or needle in path.name.lower()
    )
    return found[:limit]


def wordlist_summary(
    kind: str | None = None, *, toolchain: Toolchain | None = None
) -> list[dict[str, Any]]:
    """List discovered wordlists, optionally filtered by kind."""
    inventory = toolchain or build_toolchain(include_wordlists=True)
    items = inventory.wordlists
    if kind:
        items = [item for item in items if item.kind == kind]
    return [item.as_dict() for item in items]


def recommended_wordlist(kind: str) -> str | None:
    """Resolve the wordlist the playbook would use for ``kind`` on this host."""
    return pick_wordlist(kind)


__all__ = [
    "ExploitRecord",
    "KnowledgeUnavailable",
    "nmap_script_paths",
    "nuclei_template_paths",
    "recommended_wordlist",
    "search_exploit_db",
    "wordlist_summary",
]
