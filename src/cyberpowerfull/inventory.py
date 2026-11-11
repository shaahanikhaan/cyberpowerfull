"""Live inventory of the host's penetration-testing toolchain.

Every value in this module is read from the running machine at call time: PATH
lookups, real version banners, real directory scans, real file sizes. There are
no fixtures, no cached sample data and no optimistic defaults. If a tool is not
installed the honest answer is ``missing``, and the agent plans against that
answer instead of pretending.

The inventory is used by three consumers:

* :mod:`cyberpowerfull.brain.prompt` - the reasoning model is told exactly what
  it can execute, which wordlists exist, and which template sets are present.
* :mod:`cyberpowerfull.playbook` - deterministic playbooks substitute the first
  installed alternative instead of failing on a missing binary.
* :mod:`cyberpowerfull.cli` - ``--toolchain`` and ``--doctor`` report the real
  state of the engagement host.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from cyberpowerfull.config import ToolPolicy

#: ``name -> (alternative executable names, family)``. The first name is the
#: canonical one used in argv; alternatives cover Kali renames such as
#: ``httpx-toolkit`` and ``testssl.sh``.
BINARY_CATALOG: dict[str, tuple[tuple[str, ...], str]] = {
    # discovery / network
    "nmap": (("nmap",), "network"),
    "masscan": (("masscan",), "network"),
    "naabu": (("naabu",), "network"),
    "rustscan": (("rustscan",), "network"),
    "dnsx": (("dnsx",), "dns"),
    "netcat": (("nc", "netcat", "ncat"), "network"),
    "socat": (("socat",), "network"),
    # dns / osint
    "subfinder": (("subfinder",), "dns"),
    "amass": (("amass",), "dns"),
    "dnsrecon": (("dnsrecon",), "dns"),
    "dnsenum": (("dnsenum",), "dns"),
    "shuffledns": (("shuffledns",), "dns"),
    "fierce": (("fierce",), "dns"),
    "whois": (("whois",), "dns"),
    "theHarvester": (("theHarvester",), "osint"),
    "recon-ng": (("recon-ng",), "osint"),
    "sherlock": (("sherlock",), "osint"),
    "uncover": (("uncover",), "osint"),
    # http / web
    "httpx": (("httpx", "httpx-toolkit"), "web"),
    "katana": (("katana",), "web"),
    "gospider": (("gospider",), "web"),
    "hakrawler": (("hakrawler",), "web"),
    "gobuster": (("gobuster",), "web"),
    "feroxbuster": (("feroxbuster",), "web"),
    "ffuf": (("ffuf",), "web"),
    "dirb": (("dirb",), "web"),
    "dirsearch": (("dirsearch",), "web"),
    "wfuzz": (("wfuzz",), "web"),
    "whatweb": (("whatweb",), "web"),
    "wafw00f": (("wafw00f",), "web"),
    "nikto": (("nikto",), "web"),
    "nuclei": (("nuclei",), "web"),
    "arjun": (("arjun",), "web"),
    "wpscan": (("wpscan",), "web"),
    "joomscan": (("joomscan",), "web"),
    "droopescan": (("droopescan",), "web"),
    "dalfox": (("dalfox",), "injection"),
    "sqlmap": (("sqlmap",), "injection"),
    "commix": (("commix",), "injection"),
    "xsstrike": (("xsstrike", "XSStrike"), "injection"),
    "testssl": (("testssl.sh", "testssl"), "tls"),
    "tlsx": (("tlsx",), "tls"),
    "sslyze": (("sslyze",), "tls"),
    "sslscan": (("sslscan",), "tls"),
    # credentials / crypto
    "hydra": (("hydra",), "credentials"),
    "netexec": (("nxc", "netexec"), "credentials"),
    "medusa": (("medusa",), "credentials"),
    "john": (("john",), "credentials"),
    "hashcat": (("hashcat",), "credentials"),
    "hashid": (("hashid",), "credentials"),
    "crackmapexec": (("crackmapexec", "nxc"), "credentials"),
    "responder": (("responder", "Responder.py"), "credentials"),
    # exploitation
    "searchsploit": (("searchsploit",), "exploit"),
    "msfconsole": (("msfconsole",), "exploit"),
    "msfvenom": (("msfvenom",), "exploit"),
    "setoolkit": (("setoolkit",), "exploit"),
    "beef-xss": (("beef-xss", "beef"), "exploit"),
    # infrastructure / automation
    "sniper": (("sniper", "sn1per"), "automation"),
    "strix": (("strix", "strix-agent"), "automation"),
    "pentagi": (("pentagi",), "automation"),
    "docker": (("docker",), "automation"),
    "gau": (("gau",), "web"),
    "waybackurls": (("waybackurls",), "web"),
    "assetfinder": (("assetfinder",), "dns"),
    "metagoofil": (("metagoofil",), "osint"),
    "exiftool": (("exiftool",), "osint"),
    "smbclient": (("smbclient",), "network"),
    "enum4linux": (("enum4linux", "enum4linux-ng"), "network"),
    "ldapsearch": (("ldapsearch",), "network"),
    "rpcclient": (("rpcclient",), "network"),
    "impacket-secretsdump": (("impacket-secretsdump", "secretsdump.py"), "network"),
    "ssh-audit": (("ssh-audit",), "network"),
    "gitleaks": (("gitleaks",), "code"),
    "trufflehog": (("trufflehog",), "code"),
    "semgrep": (("semgrep",), "code"),
    "trivy": (("trivy",), "code"),
    "zap": (("zap.sh", "zap", "zaproxy"), "web"),
    "kube-bench": (("kube-bench",), "cloud"),
    "kubescape": (("kubescape",), "cloud"),
    "prowler": (("prowler",), "cloud"),
}

#: Directories scanned for wordlists, in priority order.
WORDLIST_ROOTS: tuple[str, ...] = (
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/usr/share/wfuzz/wordlist",
    "/usr/share/amass/wordlists",
    "/usr/share/metasploit-framework/data/wordlists",
    "/opt/SecLists",
    "/opt/wordlists",
)

#: Candidate locations for the nuclei template repository.
NUCLEI_TEMPLATE_ROOTS: tuple[str, ...] = (
    "/usr/share/nuclei-templates",
    "/root/nuclei-templates",
    "~/nuclei-templates",
    "~/.local/nuclei-templates",
)

SHARE_DIRS: dict[str, str] = {
    "wordlists": "/usr/share/wordlists",
    "seclists": "/usr/share/seclists",
    "nmap_scripts": "/usr/share/nmap/scripts",
    "metasploit": "/usr/share/metasploit-framework",
    "exploitdb": "/usr/share/exploitdb",
    "sqlmap": "/usr/share/sqlmap",
    "wfuzz": "/usr/share/wfuzz",
    "sn1per_loot": "/usr/share/sniper/loot",
    "sniper": "/usr/share/sniper",
    "responder": "/usr/share/responder",
}

#: Offline installation hints. Static knowledge, not a substitute for detection.
INSTALL_HINTS: dict[str, str] = {
    "nmap": "apt install nmap",
    "masscan": "apt install masscan",
    "naabu": "apt install naabu",
    "rustscan": "apt install rustscan || cargo install rustscan",
    "subfinder": "apt install subfinder",
    "amass": "apt install amass",
    "dnsx": "apt install dnsx || go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "dnsrecon": "apt install dnsrecon",
    "dnsenum": "apt install dnsenum",
    "shuffledns": (
        "apt install shuffledns || go install "
        "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest "
        "(also needs the massdns binary)"
    ),
    "httpx": "apt install httpx-toolkit",
    "katana": "apt install katana",
    "gospider": "go install github.com/jaeles-project/gospider@latest",
    "gobuster": "apt install gobuster",
    "feroxbuster": "apt install feroxbuster",
    "ffuf": "apt install ffuf",
    "whatweb": "apt install whatweb",
    "wafw00f": "apt install wafw00f",
    "nikto": "apt install nikto",
    "nuclei": "apt install nuclei && nuclei -update-templates",
    "arjun": "apt install arjun",
    "wpscan": "apt install wpscan",
    "dalfox": "apt install dalfox",
    "sqlmap": "apt install sqlmap",
    "commix": "apt install commix",
    "testssl": "apt install testssl.sh",
    "tlsx": "apt install tlsx || go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "sslscan": "apt install sslscan",
    "hydra": "apt install hydra",
    "netexec": "apt install netexec || pipx install netexec",
    "hashcat": "apt install hashcat",
    "john": "apt install john",
    "searchsploit": "apt install exploitdb",
    "msfconsole": "apt install metasploit-framework",
    "uncover": (
        "apt install uncover || go install github.com/projectdiscovery/uncover/cmd/uncover@latest"
    ),
    "gitleaks": "apt install gitleaks || go install github.com/zricethezav/gitleaks/v8@latest",
    "trufflehog": (
        "brew install trufflehog || go install github.com/trufflesecurity/trufflehog/v3@latest"
    ),
    "semgrep": "pipx install semgrep",
    "trivy": "apt install trivy (aquasec repo) || brew install trivy",
    "zap": "apt install zaproxy (kali) || download from zaproxy.org",
    "kube-bench": "download from github.com/aquasecurity/kube-bench/releases",
    "kubescape": (
        "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash"
    ),
    "prowler": "pipx install prowler",
    "sniper": "git clone https://github.com/1N3/Sn1per && sudo bash install.sh",
    "strix": "pipx install strix-agent",
    "pentagi": "docker compose up -d (vxcontrol/pentagi) and set PENTAGI_URL / PENTAGI_API_TOKEN",
    "ssh-audit": "apt install ssh-audit || pipx install ssh-audit",
    "theHarvester": "apt install theharvester || pipx install theHarvester",
    "sslyze": "pipx install sslyze",
    "dirsearch": "apt install dirsearch || pipx install dirsearch",
    "enum4linux": "apt install enum4linux-ng",
    "gau": "apt install gau || go install github.com/lc/gau/v2/cmd/gau@latest",
    "exiftool": "apt install libimage-exiftool-perl",
    "sherlock": "apt install sherlock || pipx install sherlock-project",
    "docker": "apt install docker.io",
}

_COMPRESSED_SUFFIXES = (".gz", ".bz2", ".xz", ".zip", ".7z", ".tar")

_KIND_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "passwords",
        ("password", "rockyou", "passwd", "credentials", "common-credentials", "leaked"),
    ),
    ("usernames", ("username", "users", "names", "logins")),
    (
        "discovery",
        ("directory", "directories", "common.txt", "content", "raft", "dirb", "dirbuster"),
    ),
    ("dns", ("subdomain", "dns", "domains", "vhost")),
    ("fuzzing", ("fuzz", "parameters", "params", "payload", "injection", "xss", "sqli")),
)

_VERSION_ARGS = ("--version", "-version", "-V", "--Version")

_SEMVER = re.compile(r"\d+\.\d+(?:\.\d+)?")


@dataclass(frozen=True)
class Wordlist:
    """One real wordlist file found on disk."""

    path: str
    size_bytes: int
    kind: str
    compressed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "kind": self.kind,
            "compressed": self.compressed,
        }


@dataclass(frozen=True)
class BinaryInfo:
    """Detection result for one executable."""

    name: str
    family: str
    path: str | None
    version: str | None = None
    alternative_used: str | None = None

    @property
    def installed(self) -> bool:
        return self.path is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "family": self.family,
            "installed": self.installed,
            "path": self.path,
            "version": self.version,
            "binary": self.alternative_used,
        }


@dataclass
class Toolchain:
    """Point-in-time snapshot of the engagement host."""

    binaries: dict[str, BinaryInfo] = field(default_factory=dict)
    wordlists: list[Wordlist] = field(default_factory=list)
    nuclei_templates: dict[str, Any] = field(default_factory=dict)
    nmap_scripts: int = 0
    seclists_present: bool = False
    exploitdb_present: bool = False
    metasploit_present: bool = False
    sniper_loot: str | None = None
    operating_system: dict[str, str] = field(default_factory=dict)
    external_agents: dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""

    # -- queries -----------------------------------------------------------
    def has(self, name: str) -> bool:
        info = self.binaries.get(name)
        return bool(info and info.installed)

    def binary(self, name: str) -> str | None:
        info = self.binaries.get(name)
        return info.alternative_used if info and info.installed else None

    def version(self, name: str) -> str | None:
        info = self.binaries.get(name)
        return info.version if info else None

    def installed(self) -> list[str]:
        return sorted(name for name, info in self.binaries.items() if info.installed)

    def missing(self) -> list[str]:
        return sorted(name for name, info in self.binaries.items() if not info.installed)

    def families(self) -> dict[str, dict[str, int]]:
        summary: dict[str, dict[str, int]] = {}
        for info in self.binaries.values():
            bucket = summary.setdefault(info.family, {"installed": 0, "missing": 0})
            bucket["installed" if info.installed else "missing"] += 1
        return summary

    def wordlists_of_kind(self, kind: str) -> list[Wordlist]:
        return [item for item in self.wordlists if item.kind == kind and not item.compressed]

    def as_dict(self, *, include_wordlists: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "generated_at": self.generated_at,
            "operating_system": self.operating_system,
            "binaries": {name: info.as_dict() for name, info in self.binaries.items()},
            "installed_count": len(self.installed()),
            "missing_count": len(self.missing()),
            "families": self.families(),
            "nuclei_templates": self.nuclei_templates,
            "nmap_scripts": self.nmap_scripts,
            "seclists_present": self.seclists_present,
            "exploitdb_present": self.exploitdb_present,
            "metasploit_present": self.metasploit_present,
            "sniper_loot": self.sniper_loot,
            "external_agents": self.external_agents,
            "wordlist_count": len(self.wordlists),
        }
        if include_wordlists:
            payload["wordlists"] = [item.as_dict() for item in self.wordlists]
        return payload

    def summary_lines(self, *, limit: int = 24) -> list[str]:
        """Human-readable inventory used by the prompt and ``--toolchain``."""
        installed = self.installed()
        missing = self.missing()
        lines = [
            "host_os: "
            + (
                f"{self.operating_system.get('name', 'unknown')} "
                f"{self.operating_system.get('version', '')}".strip()
            ),
            f"installed_binaries ({len(installed)}): "
            + (", ".join(installed[:limit]) + (" ..." if len(installed) > limit else "") or "none"),
            f"missing_binaries ({len(missing)}): "
            + (", ".join(missing[:limit]) + (" ..." if len(missing) > limit else "") or "none"),
            "nuclei_templates: "
            + (
                f"{self.nuclei_templates.get('count', 0)} template(s) in "
                f"{self.nuclei_templates.get('path')}"
                if self.nuclei_templates.get("path")
                else "not installed"
            ),
            f"nmap_scripts: {self.nmap_scripts}",
            "seclists: " + ("present" if self.seclists_present else "not installed"),
            "exploitdb: " + ("present" if self.exploitdb_present else "not installed"),
            "wordlists_available: "
            + (
                ", ".join(item.path for item in self.wordlists[:6])
                + (" ..." if len(self.wordlists) > 6 else "")
                or "none found"
            ),
        ]
        agents = [
            f"{name}={'ready' if info.get('available') else 'unavailable'}"
            for name, info in sorted(self.external_agents.items())
        ]
        if agents:
            lines.append("external_agents: " + ", ".join(agents))
        return lines


# ---------------------------------------------------------------------------
# discovery helpers
# ---------------------------------------------------------------------------


def _read_version(path: str, *, timeout: int = 3) -> str | None:
    """Return a short, cleaned version banner from ``--version`` output."""
    env = ToolPolicy().sanitized_env()
    for flag in _VERSION_ARGS:
        try:
            proc = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        first = next(
            (line.strip() for line in output.splitlines() if line.strip() and _SEMVER.search(line)),
            None,
        )
        if first:
            return first[:120]
    return None


def _probe_one(name: str, versions: bool) -> BinaryInfo:
    alternatives, family = BINARY_CATALOG.get(name, ((name,), "other"))
    for candidate in alternatives:
        path = shutil.which(candidate)
        if path:
            return BinaryInfo(
                name=name,
                family=family,
                path=path,
                version=_read_version(path) if versions else None,
                alternative_used=candidate,
            )
    return BinaryInfo(name=name, family=family, path=None)


@lru_cache(maxsize=8)
def probe_binaries(versions: bool = True) -> dict[str, BinaryInfo]:
    """Detect every catalogued executable on this host (cached)."""
    return {name: _probe_one(name, versions) for name in BINARY_CATALOG}


def clear_cache() -> None:
    """Drop cached probes (used by tests and by ``--doctor`` refreshes)."""
    probe_binaries.cache_clear()
    _count_files.cache_clear()


def _classify_wordlist(path: str) -> str:
    lowered = path.lower()
    for kind, tokens in _KIND_PATTERNS:
        if any(token in lowered for token in tokens):
            return kind
    return "generic"


def discover_wordlists(
    roots: Iterable[str] = WORDLIST_ROOTS,
    *,
    limit: int = 400,
    max_depth: int = 3,
    min_size: int = 512,
    max_size: int = 2_000_000_000,
) -> list[Wordlist]:
    """Walk the real wordlist directories and return usable files.

    Compressed lists are reported but flagged, because fuzzers cannot read them
    without decompression and the agent must not assume otherwise.
    """
    found: list[Wordlist] = []
    seen: set[str] = set()
    for root in roots:
        base = Path(root).expanduser()
        try:
            if not base.is_dir():
                continue
        except OSError:
            continue
        base_depth = len(base.parts)
        for dirpath, dirnames, filenames in os.walk(
            base, followlinks=True, onerror=lambda _err: None
        ):
            current = Path(dirpath)
            depth = len(current.parts) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = sorted(name for name in dirnames if not name.startswith("."))
            for filename in sorted(filenames):
                if filename.startswith("."):
                    continue
                full = str(current / filename)
                if full in seen:
                    continue
                try:
                    real = os.path.realpath(full)
                    size = os.path.getsize(real)
                except OSError:
                    continue
                if size < min_size or size > max_size:
                    continue
                compressed = filename.lower().endswith(_COMPRESSED_SUFFIXES)
                seen.add(full)
                found.append(
                    Wordlist(
                        path=full,
                        size_bytes=size,
                        kind=_classify_wordlist(full),
                        compressed=compressed,
                    )
                )
                if len(found) >= limit:
                    return sorted(found, key=lambda item: (item.kind, -item.size_bytes))
    return sorted(found, key=lambda item: (item.kind, -item.size_bytes))


def pick_wordlist(kind: str, *, toolchain: Toolchain | None = None) -> str | None:
    """Return a real, uncompressed wordlist for ``kind`` or ``None``.

    Preference order is deterministic: explicit SecLists path for the kind,
    then the largest matching uncompressed file. ``None`` is a valid answer and
    callers must handle it instead of inventing a path.
    """
    inventory = toolchain or build_toolchain(include_wordlists=True)
    candidates = inventory.wordlists_of_kind(kind)
    if not candidates:
        return None
    preferred_tokens = {
        "discovery": ("raft-medium-directories", "common.txt", "directory-list-2.3-medium"),
        "passwords": ("rockyou", "10k-most-common", "top-passwords"),
        "usernames": ("top-usernames", "names"),
        "dns": ("subdomains-top1million-5000", "namelist", "dns-Jhaddix"),
        "fuzzing": ("burp-parameter-names", "fuzz", "payload"),
    }.get(kind, ())
    for token in preferred_tokens:
        for candidate in candidates:
            if token in candidate.path.lower():
                return candidate.path
    best = max(candidates, key=lambda item: item.size_bytes)
    return best.path


@lru_cache(maxsize=16)
def _count_files(root: str, suffixes: tuple[str, ...] = (), *, max_entries: int = 200_000) -> int:
    """Count real files under ``root`` (bounded walk, symlinks not followed)."""
    base = Path(root)
    if not base.exists():
        return 0
    count = 0
    for _dirpath, _dirnames, filenames in os.walk(
        base, followlinks=False, onerror=lambda _err: None
    ):
        for filename in filenames:
            if count >= max_entries:
                return count
            if not suffixes or Path(filename).suffix in suffixes:
                count += 1
    return count


def _first_existing(paths: Iterable[str]) -> str | None:
    for candidate in paths:
        try:
            resolved = Path(candidate).expanduser()
            if resolved.exists():
                return str(resolved)
        except OSError:
            continue
    return None


def _is_dir(path: str | None) -> bool:
    if not path:
        return False
    try:
        return Path(path).is_dir()
    except OSError:
        return False


def _os_release() -> dict[str, str]:
    payload: dict[str, str] = {}
    release = Path("/etc/os-release")
    if release.is_file():
        try:
            for line in release.read_text(encoding="utf-8", errors="replace").splitlines():
                if "=" not in line or line.strip().startswith("#"):
                    continue
                key, _, value = line.partition("=")
                payload[key.strip().lower()] = value.strip().strip('"')
        except OSError:  # pragma: no cover - unreadable /etc
            payload = {}
    return {
        "name": payload.get("pretty_name") or payload.get("name") or platform.system(),
        "version": payload.get("version_id", ""),
        "id": payload.get("id", platform.system().lower()),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
    }


def _external_agents(binaries: dict[str, BinaryInfo]) -> dict[str, Any]:
    """Describe the external autonomous systems reachable from this host.

    ``available`` means runnable here and now, not just present: strix needs
    the docker CLI (it sandboxes in Docker), PentAGI needs a token with its
    URL (calls fail 401 without one), and sniper refuses non-root outright.
    """
    strix = binaries.get("strix")
    docker = binaries.get("docker")
    sniper = binaries.get("sniper")
    pentagi_url = os.environ.get("PENTAGI_URL") or os.environ.get("PENTAGI_BASE_URL")
    pentagi_token = os.environ.get("PENTAGI_API_TOKEN")
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    return {
        "strix": {
            "available": bool(strix and strix.installed and docker and docker.installed),
            "binary": strix.alternative_used if strix else None,
            "docker_present": bool(docker and docker.installed),
            "requires": ["docker", "STRIX_LLM", "LLM_API_KEY"],
            "capability": "external_agents",
        },
        "pentagi": {
            "available": bool(pentagi_url and pentagi_token),
            "endpoint": pentagi_url,
            "token_configured": bool(pentagi_token),
            "requires": ["PENTAGI_URL", "PENTAGI_API_TOKEN"],
            "capability": "external_agents",
        },
        "sn1per": {
            "available": bool(sniper and sniper.installed and is_root),
            "binary": sniper.alternative_used if sniper else None,
            "running_as_root": is_root,
            "requires": ["root", "sniper"],
            "capability": "external_agents",
        },
    }


def build_toolchain(
    *,
    versions: bool = True,
    include_wordlists: bool = True,
    wordlist_roots: Iterable[str] = WORDLIST_ROOTS,
    share_dirs: dict[str, str] | None = None,
) -> Toolchain:
    """Build a complete, live snapshot of the engagement host."""
    from cyberpowerfull.models import utcnow

    binaries = dict(probe_binaries(versions))
    dirs = dict(SHARE_DIRS if share_dirs is None else share_dirs)

    nuclei_path = _first_existing(NUCLEI_TEMPLATE_ROOTS)
    nuclei_info: dict[str, Any] = {"path": nuclei_path, "count": 0}
    if nuclei_path:
        nuclei_info["count"] = _count_files(nuclei_path, (".yaml", ".yml"))

    nmap_scripts = 0
    if dirs.get("nmap_scripts"):
        nmap_scripts = _count_files(dirs["nmap_scripts"], (".nse",))
    wordlists = discover_wordlists(wordlist_roots) if include_wordlists else []

    return Toolchain(
        binaries=binaries,
        wordlists=wordlists,
        nuclei_templates=nuclei_info,
        nmap_scripts=nmap_scripts,
        seclists_present=_is_dir(dirs.get("seclists")),
        exploitdb_present=_is_dir(dirs.get("exploitdb"))
        or bool(binaries.get("searchsploit") and binaries["searchsploit"].installed),
        metasploit_present=_is_dir(dirs.get("metasploit"))
        or bool(binaries.get("msfconsole") and binaries["msfconsole"].installed),
        sniper_loot=dirs.get("sn1per_loot"),
        operating_system=_os_release(),
        external_agents=_external_agents(binaries),
        generated_at=utcnow().isoformat(),
    )


def install_hint(name: str) -> str | None:
    """Return the documented installation command for a missing tool."""
    return INSTALL_HINTS.get(name)


def family_members(family: str) -> list[str]:
    """Names of every catalogued tool in ``family``."""
    return sorted(name for name, (_, fam) in BINARY_CATALOG.items() if fam == family)


__all__ = [
    "BINARY_CATALOG",
    "INSTALL_HINTS",
    "NUCLEI_TEMPLATE_ROOTS",
    "SHARE_DIRS",
    "WORDLIST_ROOTS",
    "BinaryInfo",
    "Toolchain",
    "Wordlist",
    "build_toolchain",
    "clear_cache",
    "discover_wordlists",
    "family_members",
    "install_hint",
    "pick_wordlist",
    "probe_binaries",
]
