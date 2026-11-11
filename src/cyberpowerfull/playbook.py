"""Deterministic multi-tool playbooks (the automation engine).

A playbook is an ordered set of tool steps that run in parallel groups and adapt
to what earlier steps discovered: open ports become nikto/testssl targets, live
URLs become crawl and fuzz targets, fingerprinted technology becomes an
Exploit-DB lookup. This is the sn1per-style automation path and it needs no
model at all - which makes it the reliable fallback when local inference is
unavailable or too slow.

Every execution still passes through :class:`~cyberpowerfull.brain.orchestrator.WorkerAgent`,
so scope validation, phase permission, capability gates, argv construction,
output parsing and memory writes are the same code path used by the reasoning
agent. A playbook cannot bypass a guardrail.
"""

from __future__ import annotations

import difflib
import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from cyberpowerfull.brain.orchestrator import WORKER_TOOL_ALLOWLIST, DelegationRequest, WorkerAgent
from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.errors import PlaybookNotFound
from cyberpowerfull.inventory import Toolchain, build_toolchain, pick_wordlist
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.models import BudgetState, Finding, Phase, new_id, utcnow
from cyberpowerfull.scope import Scope
from cyberpowerfull.tools.base import ToolStatus
from cyberpowerfull.tools.registry import all_tools
from cyberpowerfull.trace import StepRecord, Trace, TraceRecorder

# ---------------------------------------------------------------------------
# facts learned during a run
# ---------------------------------------------------------------------------

_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443}
_TLS_PORTS = {443, 8443, 9443}


@dataclass
class Facts:
    """Everything the playbook has learned so far, from real tool output."""

    target: str
    domain: str | None = None
    open_ports: dict[int, str] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    vhosts: list[str] = field(default_factory=list)
    tech: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    #: kind -> real wordlist path (or None). Populated by the runner from the
    #: live inventory before the first step is scheduled.
    wordlists: dict[str, str | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        target = self.target.strip()
        if "://" in target:
            # A URL target ("cpf https://app:8443/x") must not poison host-only
            # fields: tools get the host, web builders keep the full URL.
            scheme, _, _rest = target.partition("://")
            if scheme.lower() in {"http", "https"}:
                self.add_url(target)
            self.target = urlparse(target).hostname or target
            target = self.target
        elif "/" in target:
            self.target = target.split("/", 1)[0]
            target = self.target
        if self.domain is None and not _is_ip(target):
            self.domain = target

    # -- derived views -----------------------------------------------------
    @property
    def primary_url(self) -> str:
        for url in self.urls:
            if url.startswith("https://"):
                return url.rstrip("/")
        if self.urls:
            return self.urls[0].rstrip("/")
        return f"https://{self.target}"

    @property
    def http_url(self) -> str:
        for url in self.urls:
            if url.startswith("http://"):
                return url.rstrip("/")
        return f"http://{self.target}"

    def web_ports(self) -> list[int]:
        ports = [port for port in self.open_ports if port in _WEB_PORTS]
        return sorted(ports) or [80, 443]

    def tls_ports(self) -> list[int]:
        return sorted(port for port in self.open_ports if port in _TLS_PORTS)

    def add_url(self, url: str) -> None:
        cleaned = url.strip()
        if cleaned and cleaned not in self.urls and len(self.urls) < 200:
            self.urls.append(cleaned)

    def add_subdomain(self, host: str) -> None:
        cleaned = host.strip().lower()
        if cleaned and cleaned not in self.subdomains and len(self.subdomains) < 500:
            self.subdomains.append(cleaned)

    def add_port(self, port: int, service: str = "") -> None:
        if 0 < port < 65536:
            self.open_ports.setdefault(port, service)

    def add_tech(self, name: str) -> None:
        cleaned = name.strip()
        if cleaned and cleaned not in self.tech and len(self.tech) < 40:
            self.tech.append(cleaned)

    def absorb(self, tool: str, findings: list[Finding], observations: list[str]) -> None:
        """Fold one tool result into the fact base (deterministic, no guessing)."""
        for finding in findings:
            self.findings.append(finding)
            endpoint = finding.endpoint or ""
            if endpoint.startswith(("http://", "https://")):
                self.add_url(endpoint)
            elif ":" in endpoint and endpoint.count(":") == 1:
                host_part, _, port_text = endpoint.rpartition(":")
                # Code findings use file:line endpoints (/repo/app.py:42): those
                # are line numbers, never ports.
                if "/" not in host_part and port_text.isdigit():
                    self.add_port(int(port_text))
            if finding.title.startswith("Subdomain discovered"):
                self.add_subdomain(endpoint or finding.title.split(":")[-1].strip())
            if "vhost" in finding.title.lower() and endpoint:
                self.add_subdomain(endpoint)
            lowered = finding.evidence.lower()
            if "tech=" in lowered:
                for token in finding.evidence.split("tech=", 1)[1].split(",")[:6]:
                    self.add_tech(token.strip())
            if finding.title.startswith("Technology fingerprint:"):
                for token in finding.title.split(":", 1)[1].split(","):
                    self.add_tech(token.strip())
            if finding.title.startswith("Technology version disclosed:"):
                self.add_tech(finding.title.split(":", 1)[1].strip())
            if "port=" in lowered and "state=open" in lowered:
                port_text = lowered.split("port=", 1)[1].split("/")[0].split()[0]
                if port_text.isdigit():
                    self.add_port(int(port_text))
        for note in observations:
            if note.startswith("http ") and "://" in note:
                url = note.split(" ", 2)[2].split(" ")[0]
                self.add_url(url)


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _port_of(url: str, default: int = 443) -> int:
    parsed = urlparse(url)
    if parsed.port:
        return parsed.port
    return 80 if parsed.scheme == "http" else default


# ---------------------------------------------------------------------------
# playbook definition
# ---------------------------------------------------------------------------

FactsBuilder = Callable[[Facts], dict[str, Any] | None]


@dataclass(frozen=True)
class PlaybookStep:
    """One tool invocation inside a playbook."""

    id: str
    tool: str
    group: int
    args: FactsBuilder
    purpose: str
    optional: bool = True
    phase: Phase | None = None
    requires_passive_sources: bool = False


@dataclass(frozen=True)
class Playbook:
    """Named, ordered set of steps."""

    name: str
    title: str
    description: str
    steps: tuple[PlaybookStep, ...]
    default_parallel: int = 4

    @property
    def groups(self) -> list[int]:
        return sorted({step.group for step in self.steps})

    def steps_in(self, group: int) -> list[PlaybookStep]:
        return [step for step in self.steps if step.group == group]


# ---------------------------------------------------------------------------
# step argument builders
# ---------------------------------------------------------------------------


def _domain(args: Facts) -> dict[str, Any] | None:
    return {"target": args.domain} if args.domain else None


def _subfinder(args: Facts) -> dict[str, Any] | None:
    return {"target": args.domain, "all_sources": True} if args.domain else None


def _amass(args: Facts) -> dict[str, Any] | None:
    return {"target": args.domain, "timeout_minutes": 3} if args.domain else None


def _dnsrecon(args: Facts) -> dict[str, Any] | None:
    return {"target": args.domain, "scan_type": "std"} if args.domain else None


#: Ports probed by the native TCP connector. This is the one step that needs no
#: external binary, so a bare host still produces real, evidence-linked output.
COMMON_TCP_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1723,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    9200,
    27017,
)


def _tcp_probe(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "ports": list(COMMON_TCP_PORTS), "timeout_s": 1.0}


def _nmap_top(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "ports": "top-1000", "service_detection": True, "timing": 4}


def _nmap_services(args: Facts) -> dict[str, Any] | None:
    if not args.open_ports:
        return None
    ports = ",".join(str(port) for port in sorted(args.open_ports)[:150])
    return {
        "target": args.target,
        "ports": ports,
        "service_detection": True,
        "timing": 4,
        "scripts": ["http-title", "http-headers", "ssl-cert"],
    }


def _naabu(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "top_ports": 1000, "rate": 300}


def _masscan(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "ports": "1-65535", "rate": 800}


def _httpx_tls(args: Facts) -> dict[str, Any]:
    return {
        "target": f"https://{args.target}",
        "tech_detect": True,
        "follow_redirects": True,
        "threads": 10,
    }


def _httpx_plain(args: Facts) -> dict[str, Any]:
    return {
        "target": f"http://{args.target}",
        "tech_detect": True,
        "follow_redirects": True,
        "threads": 10,
    }


def _httpx_web_port(args: Facts) -> dict[str, Any] | None:
    ports = [port for port in args.web_ports() if port not in {80, 443}]
    if not ports:
        return None
    scheme = "https" if any(port in _TLS_PORTS for port in ports) else "http"
    return {
        "target": f"{scheme}://{args.target}:{ports[0]}",
        "tech_detect": True,
        "follow_redirects": True,
    }


def _whatweb(args: Facts) -> dict[str, Any]:
    return {"target": args.primary_url, "aggression": 1}


def _wafw00f(args: Facts) -> dict[str, Any]:
    return {"target": args.primary_url, "find_all": True}


def _katana(args: Facts) -> dict[str, Any]:
    return {
        "target": args.primary_url,
        "depth": 2,
        "concurrency": 8,
        "rate_limit": 40,
        "known_files": True,
    }


def _nikto(args: Facts) -> dict[str, Any]:
    url = args.primary_url
    port = _port_of(url)
    return {"target": args.target, "port": port, "ssl": url.startswith("https")}


def _nikto_web_port(args: Facts) -> dict[str, Any] | None:
    ports = [port for port in args.web_ports() if port not in {80, 443}]
    if not ports:
        return None
    return {"target": args.target, "port": ports[0], "ssl": ports[0] in _TLS_PORTS}


def _nuclei(args: Facts) -> dict[str, Any]:
    # Focused high-signal tags: the full template store (no tags) takes far
    # longer than a deterministic playbook step may spend. Full-store runs
    # belong to dedicated nuclei invocations (timeout_s=1800 there).
    return {
        "target": args.primary_url,
        "severity": ["low", "medium", "high", "critical"],
        "tags": ["cve", "exposure", "misconfig", "xss", "sqli", "rce", "lfi", "ssrf"],
        "rate_limit": 20,
        "concurrency": 10,
    }


def _nuclei_stealth(args: Facts) -> dict[str, Any]:
    return {
        "target": args.primary_url,
        "severity": ["medium", "high", "critical"],
        "rate_limit": 8,
        "concurrency": 4,
        "tags": ["cve", "exposure", "misconfig"],
    }


def _nuclei_api(args: Facts) -> dict[str, Any]:
    return {
        "target": args.primary_url,
        "severity": ["low", "medium", "high", "critical"],
        "tags": ["api", "graphql", "swagger", "exposure", "cors"],
        "rate_limit": 15,
        "concurrency": 8,
    }


def _dnsx(args: Facts) -> dict[str, Any] | None:
    return {"target": args.domain} if args.domain else None


def _dnsx_bruteforce(args: Facts) -> dict[str, Any] | None:
    wordlist = args.wordlists.get("dns")
    if not args.domain or not wordlist:
        return None
    return {"target": args.domain, "bruteforce": True, "wordlist": wordlist}


def _uncover(args: Facts) -> dict[str, Any]:
    return {"target": args.domain or args.target}


def _rustscan(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "top_1000": True}


def _tlsx(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "ports": args.tls_ports() or args.web_ports()}


def _nuclei_dast(args: Facts) -> dict[str, Any]:
    # DAST crawls and fuzzes by itself, so gentler budgets than template scans.
    # The fuzz-scope pattern defaults to the validated target host only: builders
    # never see the scope, and findings are not scope-checked.
    return {
        "target": args.primary_url,
        "severity": ["low", "medium", "high", "critical"],
        "rate_limit": 10,
        "concurrency": 5,
        "dast": True,
    }


def _netexec(args: Facts) -> dict[str, Any] | None:
    if 445 not in args.open_ports:
        return None
    return {"target": args.target, "enumerate": ["shares", "pass_pol"]}


def _code_path(args: Facts) -> dict[str, Any]:
    return {"target": args.target}


def _code_semgrep(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "config": "p/default"}


def _code_trivy(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "scanners": ["vuln", "secret", "misconfig"]}


def _nuclei_kev(args: Facts) -> dict[str, Any]:
    return {
        "target": args.primary_url,
        "severity": ["high", "critical"],
        "kev_only": True,
        "rate_limit": 15,
        "concurrency": 8,
    }


def _zap(args: Facts) -> dict[str, Any]:
    return {"target": args.primary_url}


def _cloud_target(args: Facts) -> dict[str, Any]:
    return {"target": args.target}


def _cloud_prowler(args: Facts) -> dict[str, Any]:
    return {"target": args.target, "provider": "aws"}


def _gobuster(args: Facts) -> dict[str, Any] | None:
    if not args.wordlists.get("discovery"):
        return None
    return {"target": args.primary_url, "mode": "dir", "threads": 20}


def _gobuster_vhost(args: Facts) -> dict[str, Any] | None:
    if not args.domain or not args.wordlists.get("dns"):
        return None
    return {"target": args.domain, "mode": "dns", "threads": 20}


def _feroxbuster(args: Facts) -> dict[str, Any] | None:
    if not args.wordlists.get("discovery"):
        return None
    return {"target": args.primary_url, "depth": 2, "threads": 20}


def _ffuf(args: Facts) -> dict[str, Any] | None:
    wordlist = args.wordlists.get("discovery")
    if not wordlist:
        return None
    return {
        "target": f"{args.primary_url}/FUZZ",
        "wordlist": wordlist,
        "threads": 30,
        "extensions": ["php", "bak", "txt"],
    }


def _arjun(args: Facts) -> dict[str, Any]:
    return {"target": args.primary_url, "method": "GET", "threads": 6}


def _testssl(args: Facts) -> dict[str, Any] | None:
    if not args.primary_url.startswith("https"):
        return None
    return {"target": args.primary_url, "severity_floor": "LOW"}


def _wpscan(args: Facts) -> dict[str, Any] | None:
    if not any("wordpress" in tech.lower() for tech in args.tech):
        return None
    return {"target": args.primary_url, "enumerate": ["vp", "vt", "u"]}


def _searchsploit(args: Facts) -> dict[str, Any] | None:
    if not args.tech:
        return None
    query = args.tech[0].split("/")[0].split()[0][:60]
    if len(query) < 2:
        return None
    return {"target": args.target, "query": query}


def _searchsploit_services(args: Facts) -> dict[str, Any] | None:
    for service in args.open_ports.values():
        if service and len(service) >= 3:
            return {"target": args.target, "query": service.split()[0][:60]}
    return None


# ---------------------------------------------------------------------------
# the playbooks
# ---------------------------------------------------------------------------

_RECON_STEPS: tuple[PlaybookStep, ...] = (
    PlaybookStep("recon-tcp", "tcp_probe", 0, _tcp_probe, "native TCP connect sweep"),
    PlaybookStep("recon-subfinder", "subfinder", 1, _subfinder, "passive subdomain enumeration"),
    PlaybookStep("recon-amass", "amass", 1, _amass, "secondary passive enumeration"),
    PlaybookStep(
        "recon-uncover",
        "uncover",
        1,
        _uncover,
        "search-engine exposure lookup",
        requires_passive_sources=True,
    ),
    PlaybookStep("recon-nmap", "nmap", 1, _nmap_top, "top-1000 TCP sweep with service detection"),
    PlaybookStep("recon-http", "httpx", 2, _httpx_tls, "confirm HTTPS endpoints"),
    PlaybookStep("recon-http-plain", "httpx", 2, _httpx_plain, "confirm HTTP endpoints"),
    PlaybookStep("recon-waf", "wafw00f", 2, _wafw00f, "fingerprint the WAF"),
    PlaybookStep("recon-whatweb", "whatweb", 2, _whatweb, "technology fingerprint"),
    PlaybookStep("recon-dns", "dnsrecon", 2, _dnsrecon, "DNS records and AXFR check"),
    PlaybookStep("recon-dnsx", "dnsx", 2, _dnsx, "fast DNS record collection"),
    PlaybookStep("recon-dnsx-brute", "dnsx", 2, _dnsx_bruteforce, "subdomain brute-force"),
    PlaybookStep("recon-katana", "katana", 3, _katana, "crawl endpoints and parameters"),
    PlaybookStep("recon-nikto", "nikto", 3, _nikto, "server misconfiguration pass"),
)

_WEB_STEPS: tuple[PlaybookStep, ...] = (
    PlaybookStep("web-http", "httpx", 1, _httpx_tls, "confirm the web endpoint"),
    PlaybookStep("web-http-plain", "httpx", 1, _httpx_plain, "confirm the plain endpoint"),
    PlaybookStep("web-whatweb", "whatweb", 1, _whatweb, "fingerprint the stack"),
    PlaybookStep("web-waf", "wafw00f", 1, _wafw00f, "detect WAF"),
    PlaybookStep("web-katana", "katana", 2, _katana, "crawl endpoints"),
    PlaybookStep("web-nikto", "nikto", 2, _nikto, "misconfiguration scan"),
    PlaybookStep("web-gobuster", "gobuster", 2, _gobuster, "directory brute force"),
    PlaybookStep("web-nuclei", "nuclei", 3, _nuclei, "template validation"),
    PlaybookStep("web-zap", "zap", 3, _zap, "ZAP spider + passive baseline"),
    PlaybookStep("web-nuclei-kev", "nuclei", 2, _nuclei_kev, "known-exploited CVEs first"),
    PlaybookStep("web-ferox", "feroxbuster", 3, _feroxbuster, "recursive discovery"),
    PlaybookStep("web-arjun", "arjun", 3, _arjun, "hidden parameter discovery"),
    PlaybookStep("web-testssl", "testssl", 3, _testssl, "TLS configuration review"),
    PlaybookStep("web-wpscan", "wpscan", 4, _wpscan, "WordPress enumeration (conditional)"),
    PlaybookStep("web-searchsploit", "searchsploit", 4, _searchsploit, "public exploit lookup"),
    PlaybookStep("web-nuclei-api", "nuclei", 4, _nuclei_api, "API-focused templates"),
    PlaybookStep("web-nuclei-dast", "nuclei", 5, _nuclei_dast, "scoped DAST fuzzing"),
)

_NETWORK_STEPS: tuple[PlaybookStep, ...] = (
    PlaybookStep("net-tcp", "tcp_probe", 0, _tcp_probe, "native TCP connect sweep"),
    PlaybookStep("net-nmap", "nmap", 1, _nmap_top, "top-1000 TCP sweep"),
    PlaybookStep("net-naabu", "naabu", 1, _naabu, "fast port confirmation"),
    PlaybookStep("net-rustscan", "rustscan", 1, _rustscan, "top-1000 sweep in seconds"),
    PlaybookStep("net-masscan", "masscan", 2, _masscan, "full-range sweep (aggressive only)"),
    PlaybookStep(
        "net-services", "nmap", 3, _nmap_services, "service detection on discovered ports"
    ),
    PlaybookStep("net-web-port", "httpx", 4, _httpx_web_port, "probe non-standard web ports"),
    PlaybookStep("net-nikto", "nikto", 4, _nikto_web_port, "misconfiguration on web port"),
    PlaybookStep("net-testssl", "testssl", 4, _testssl, "TLS review on web ports"),
    PlaybookStep("net-tlsx", "tlsx", 4, _tlsx, "fast certificate grab"),
    PlaybookStep(
        "net-netexec",
        "netexec",
        4,
        _netexec,
        "SMB null-session enumeration (credential_testing only)",
    ),
    PlaybookStep(
        "net-exploit-lookup",
        "searchsploit",
        5,
        _searchsploit_services,
        "service exploit lookup",
    ),
)

_STEALTH_STEPS: tuple[PlaybookStep, ...] = (
    PlaybookStep("stealth-tcp", "tcp_probe", 0, _tcp_probe, "native TCP connect sweep"),
    PlaybookStep("stealth-subfinder", "subfinder", 1, _subfinder, "passive enumeration"),
    PlaybookStep("stealth-http", "httpx", 2, _httpx_tls, "single polite HTTP probe"),
    PlaybookStep("stealth-whatweb", "whatweb", 2, _whatweb, "fingerprint with low aggression"),
    PlaybookStep("stealth-katana", "katana", 3, _katana, "limited crawl"),
    PlaybookStep("stealth-nuclei", "nuclei", 3, _nuclei_stealth, "medium+ templates only"),
)

_API_STEPS: tuple[PlaybookStep, ...] = (
    PlaybookStep("api-http", "httpx", 1, _httpx_tls, "confirm the API endpoint"),
    PlaybookStep("api-katana", "katana", 1, _katana, "harvest API routes from JS"),
    PlaybookStep("api-arjun", "arjun", 2, _arjun, "hidden parameter discovery"),
    PlaybookStep("api-nuclei", "nuclei", 2, _nuclei_api, "API/exposure templates"),
    PlaybookStep("api-ffuf", "ffuf", 3, _ffuf, "API path discovery"),
    PlaybookStep("api-searchsploit", "searchsploit", 3, _searchsploit, "exploit lookup"),
    PlaybookStep("api-nuclei-dast", "nuclei", 4, _nuclei_dast, "scoped DAST fuzzing"),
)


_CODE_STEPS: tuple[PlaybookStep, ...] = (
    PlaybookStep("code-gitleaks", "gitleaks", 1, _code_path, "secret scan of the worktree"),
    PlaybookStep("code-trufflehog", "trufflehog", 1, _code_path, "detector-based secret scan"),
    PlaybookStep("code-semgrep", "semgrep", 2, _code_semgrep, "static analysis (p/default)"),
    PlaybookStep("code-trivy", "trivy", 2, _code_trivy, "deps, secrets, and misconfigs"),
)


_CLOUD_STEPS: tuple[PlaybookStep, ...] = (
    PlaybookStep("cloud-kubebench", "kubebench", 1, _cloud_target, "CIS benchmark (on-node)"),
    PlaybookStep("cloud-kubescape", "kubescape", 1, _cloud_target, "posture across frameworks"),
    PlaybookStep("cloud-prowler", "prowler", 2, _cloud_prowler, "AWS posture (credential-gated)"),
)


PLAYBOOKS: dict[str, Playbook] = {
    playbook.name: playbook
    for playbook in (
        Playbook(
            "recon",
            "Recon",
            "Passive and low-noise surface mapping: subdomains, ports, HTTP, WAF, crawl.",
            _RECON_STEPS,
        ),
        Playbook(
            "web",
            "Web application",
            "Full web assessment: fingerprint, crawl, content discovery, templates, TLS.",
            _WEB_STEPS,
        ),
        Playbook(
            "network",
            "Network services",
            "Port surface, service detection, exploit availability for discovered services.",
            _NETWORK_STEPS,
        ),
        Playbook(
            "stealth",
            "Stealth",
            "Low request volume pass that avoids brute force and high-rate scans.",
            _STEALTH_STEPS,
            default_parallel=2,
        ),
        Playbook(
            "api",
            "API",
            "API-focused pass: route harvesting, parameter discovery, API templates.",
            _API_STEPS,
            default_parallel=3,
        ),
        Playbook(
            "code",
            "Code audit",
            "Local repository audit: secrets, SAST, dependencies. Needs scope.allowed_paths.",
            _CODE_STEPS,
            default_parallel=2,
        ),
        Playbook(
            "cloud",
            "Cloud & Kubernetes posture",
            "CIS benchmarks, cluster posture, cloud audit. Needs node access / credentials.",
            _CLOUD_STEPS,
            default_parallel=2,
        ),
        Playbook(
            "full",
            "Full",
            "Recon + web + network in one run, ordered by dependency group.",
            _RECON_STEPS + _WEB_STEPS + _NETWORK_STEPS,
            default_parallel=4,
        ),
    )
}


def playbook_names() -> list[str]:
    return sorted(PLAYBOOKS)


def get_playbook(name: str) -> Playbook:
    try:
        return PLAYBOOKS[name]
    except KeyError as exc:
        names = playbook_names()
        guess = difflib.get_close_matches(name, names, n=1, cutoff=0.6)
        hint = f"; did you mean {guess[0]!r}?" if guess else ""
        raise PlaybookNotFound(
            f"unknown playbook {name!r}; available: {', '.join(names)}{hint}"
        ) from exc


def describe_playbooks() -> list[dict[str, Any]]:
    return [
        {
            "name": playbook.name,
            "title": playbook.title,
            "description": playbook.description,
            "steps": len(playbook.steps),
            "tools": sorted({step.tool for step in playbook.steps}),
        }
        for playbook in PLAYBOOKS.values()
    ]


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------


@dataclass
class PlaybookResult:
    """Outcome of one playbook execution."""

    trace: Trace
    findings: list[Finding]
    stop_reason: str
    executed: list[str]
    skipped: list[str]


def _worker_for(tool: str) -> str | None:
    for worker, allowed in WORKER_TOOL_ALLOWLIST.items():
        if tool in allowed:
            return worker
    return None


_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _top_severity(findings: list[Finding] | None) -> str | None:
    """Highest severity in a step's findings (for traces and live display)."""
    best: str | None = None
    for finding in findings or []:
        level = getattr(finding.severity, "value", None)
        if level not in _SEVERITY_ORDER:
            continue
        if best is None or _SEVERITY_ORDER.index(level) > _SEVERITY_ORDER.index(best):
            best = level
    return best


class PlaybookRunner:
    """Executes a playbook with the same guardrails as the reasoning loop."""

    def __init__(
        self,
        *,
        scope: Scope,
        target: str,
        memory: MemoryStore,
        toolchain: Toolchain | None = None,
        policy: ToolPolicy | None = None,
        dry_run: bool = False,
        max_seconds: int = 1800,
        max_steps: int = 80,
        parallel: int | None = None,
        run_id: str | None = None,
        tools: dict[str, Any] | None = None,
    ) -> None:
        self.scope = scope
        self.target = target
        self.memory = memory
        self.policy = policy or ToolPolicy()
        self.toolchain = toolchain or build_toolchain(include_wordlists=True)
        self.dry_run = dry_run
        self.max_seconds = max_seconds
        self.max_steps = max_steps
        self.parallel = parallel
        self.run_id = run_id or new_id("play-")
        merged = all_tools()
        if tools:
            merged.update(tools)
        self.tools = merged
        self.facts = Facts(
            target=target,
            wordlists={
                "discovery": pick_wordlist("discovery", toolchain=self.toolchain),
                "dns": pick_wordlist("dns", toolchain=self.toolchain),
                "fuzzing": pick_wordlist("fuzzing", toolchain=self.toolchain),
            },
        )
        self._seen: set[tuple[str, str | None]] = {
            (finding.title, finding.endpoint) for finding in memory.findings()
        }
        # Per-run caches: tool metadata never changes mid-run, step arguments
        # are frozen within a group, and an identical invocation is never
        # worth running twice (the 'full' playbook schedules several).
        self._describes: dict[str, dict[str, Any]] = {}
        self._args_cache: dict[str, dict[str, Any] | None] = {}
        self._invocations: dict[str, str] = {}
        self._workers = {
            name: WorkerAgent(name, scope=scope, policy=self.policy, tools=self.tools)
            for name in WORKER_TOOL_ALLOWLIST
        }

    # -- capability / availability -----------------------------------------
    def _blocked_reason(self, step: PlaybookStep) -> str | None:
        tool = self.tools.get(step.tool)
        if tool is None:
            return f"tool {step.tool!r} is not registered"
        worker = _worker_for(step.tool)
        if worker is None:
            return f"tool {step.tool!r} is not delegable to any worker"
        if worker == "external":
            return "external agent steps are opt-in; run them through the reasoning agent"
        capability = getattr(tool, "required_capability", None)
        if capability is not None and not self.scope.allows(capability):
            return f"requires capability {capability.value!r} (not granted by scope.json)"
        if tool.phase not in self.scope.allowed_phases:
            return f"phase {tool.phase.value!r} is not permitted by scope.json"
        if step.requires_passive_sources and not self.scope.allow_passive_sources:
            return "passive sources not permitted (set allow_passive_sources in scope.json)"
        describe = self._describe(step.tool)
        if not describe["installed"]:
            return f"binary not installed: {describe['binary']}"
        return None

    def _describe(self, tool_name: str) -> dict[str, Any]:
        """Tool metadata, resolved once per run (binaries do not change mid-run)."""
        cached = self._describes.get(tool_name)
        if cached is None:
            cached = self.tools[tool_name].describe()
            self._describes[tool_name] = cached
        return cached

    def _step_args(self, step: PlaybookStep) -> dict[str, Any] | None:
        """Step arguments, derived once per group (facts freeze during a group)."""
        if step.id not in self._args_cache:
            self._args_cache[step.id] = step.args(self.facts)
        return self._args_cache[step.id]

    def _duplicate_of(self, step: PlaybookStep, args: dict[str, Any]) -> str | None:
        """Id of the first step with an identical invocation, if one ran already."""
        key = f"{step.tool}:{json.dumps(args, sort_keys=True, default=str)}"
        origin = self._invocations.get(key)
        if origin is None:
            self._invocations[key] = step.id
            return None
        return origin

    # -- execution ---------------------------------------------------------
    def run(
        self,
        playbook: Playbook,
        *,
        progress: Callable[[StepRecord], None] | None = None,
        step_start: Callable[[dict[str, Any]], None] | None = None,
    ) -> PlaybookResult:
        started = time.monotonic()
        recorder = TraceRecorder(
            target=self.target,
            engagement=self.scope.engagement,
            model="none",
            backend=f"playbook:{playbook.name}",
            scope_fingerprint=self.scope.fingerprint(),
            run_id=self.run_id,
        )
        executed: list[str] = []
        skipped: list[str] = []
        stop_reason = "playbook_complete"
        step_index = 0
        budget = BudgetState(max_iterations=self.max_steps, max_seconds=self.max_seconds)

        for group in playbook.groups:
            self._args_cache.clear()
            candidates: list[PlaybookStep] = []
            for step in playbook.steps_in(group):
                reason = self._blocked_reason(step)
                if reason:
                    skipped.append(f"{step.id}: {reason}")
                    continue
                try:
                    args = self._step_args(step)
                except Exception as exc:  # pragma: no cover - defensive
                    skipped.append(f"{step.id}: argument derivation failed: {exc}")
                    continue
                if args is None:
                    skipped.append(f"{step.id}: precondition not met (no discovered fact)")
                    continue
                duplicate_of = self._duplicate_of(step, args)
                if duplicate_of is not None:
                    skipped.append(
                        f"{step.id}: duplicate of {duplicate_of} "
                        "(same tool and arguments already ran)"
                    )
                    continue
                cached = self.memory.negative_cache_hit(step.tool, args)
                if cached and not self.dry_run:
                    skipped.append(f"{step.id}: negative cache: {cached}")
                    continue
                candidates.append(step)
            if not candidates:
                continue
            if budget.exhausted() or len(executed) + len(candidates) > self.max_steps:
                stop_reason = "budget_exhausted:steps"
                break
            if step_start is not None:
                for step in candidates:
                    phase = step.phase or self.tools[step.tool].phase
                    step_start(
                        {
                            "tool": step.tool,
                            "purpose": step.purpose,
                            "id": step.id,
                            "phase": phase.value if isinstance(phase, Phase) else str(phase),
                        }
                    )

            parallel = self.parallel or playbook.default_parallel
            if parallel <= 1 or len(candidates) == 1:
                results = [self._run_step(step) for step in candidates]
            else:
                with ThreadPoolExecutor(max_workers=min(parallel, len(candidates))) as pool:
                    results = list(pool.map(self._run_step, candidates))

            for step, record, payload in results:
                step_index += 1
                budget.iterations = step_index
                budget.seconds_used = round(time.monotonic() - started, 3)
                if payload is not None:
                    record.index = step_index
                    blocked = payload["status"] == ToolStatus.BLOCKED.value
                    new_findings = (
                        []
                        if blocked
                        else [finding for finding in payload["findings"] if self._accept(finding)]
                    )
                    payload["findings"] = new_findings
                    record.finding_ids = [finding.id for finding in new_findings]
                    recorder.add_step(record)
                    if blocked:
                        skipped.append(f"{step.id}: {payload['error']}")
                        continue
                    executed.append(step.id)
                    findings = new_findings
                    self.facts.absorb(payload["tool"], findings, payload["observations"])
                    recorder.add_findings(findings)
                    self._persist(record, payload)
                    if progress is not None:
                        progress(record)
                else:
                    skipped.append(f"{step.id}: {record.error or 'skipped by guardrail'}")
                if budget.seconds_used >= self.max_seconds:
                    stop_reason = "budget_exhausted:seconds"
                    break
            if stop_reason == "budget_exhausted:seconds":
                break

        budget.seconds_used = round(time.monotonic() - started, 3)
        recorder.set_budget(budget)
        trace = recorder.finish(
            stop_reason=stop_reason,
            tree={},
            memory_stats=self.memory.stats(),
        )
        trace.skipped = list(skipped)
        return PlaybookResult(
            trace=trace,
            findings=recorder.findings,
            stop_reason=stop_reason,
            executed=executed,
            skipped=skipped,
        )

    def _run_step(
        self, step: PlaybookStep
    ) -> tuple[PlaybookStep, StepRecord, dict[str, Any] | None]:
        """Execute one step. Never raises: a failure becomes a recorded step."""
        worker_name = _worker_for(step.tool) or "scan"
        worker = self._workers[worker_name]
        args = self._step_args(step) or {}
        step_started = utcnow()
        t0 = time.monotonic()

        request = DelegationRequest(
            agent=worker_name,  # type: ignore[arg-type]
            tool=step.tool,
            args=args,
        )
        result = worker.execute(request, dry_run=self.dry_run)
        payload: dict[str, Any] | None = {
            "tool": result.tool,
            "status": result.status,
            "exit_code": result.exit_code,
            "argv": result.argv,
            "observations": result.observations,
            "error": result.error,
            "findings": list(result.findings),
            "duration_ms": result.duration_ms,
            "args": args,
            "purpose": step.purpose,
        }
        record = self._record(
            step,
            status=result.status.value,
            argv=result.argv,
            observations=result.observations,
            error=result.error,
            step_started=step_started,
            t0=t0,
            args=args,
            result=result,
            findings=list(result.findings),
        )
        return step, record, payload

    def _accept(self, finding: Finding) -> bool:
        key = (finding.title, finding.endpoint)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def _record(
        self,
        step: PlaybookStep,
        *,
        status: str,
        argv: list[str],
        observations: list[str],
        error: str | None,
        step_started: Any,
        t0: float,
        args: dict[str, Any],
        result: Any = None,
        findings: list[Finding] | None = None,
    ) -> StepRecord:
        return StepRecord(
            index=0,  # assigned in run() in deterministic order
            action="playbook",
            phase=step.phase or self.tools[step.tool].phase,
            tool=step.tool,
            args=args,
            reason=step.purpose,
            thought=f"playbook step {step.id}",
            node=step.id,
            tda={},
            result={
                "status": status,
                "exit_code": getattr(result, "exit_code", None),
                "duration_ms": getattr(result, "duration_ms", int((time.monotonic() - t0) * 1000)),
                "argv": argv,
                "stdout_excerpt": getattr(result, "stdout", "")[:500],
                "observations": observations[:10],
                "error": error,
                "finding_titles": [finding.title for finding in (findings or [])[:5]],
                "top_severity": _top_severity(findings),
            },
            finding_ids=[finding.id for finding in findings or []],
            started_at=step_started.isoformat(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            error=error,
        )

    def _persist(self, record: StepRecord, payload: dict[str, Any]) -> None:
        self.memory.record_attempt(
            tool=payload["tool"],
            args=payload["args"],
            target=str(payload["args"].get("target", self.target)),
            ok=payload["status"] in {ToolStatus.OK.value, ToolStatus.SKIPPED.value},
            error=payload["error"],
        )
        for finding in payload["findings"]:
            self.memory.append_finding(finding)
        self.memory.append_step(
            step=record.index,
            phase=record.phase,
            tool=record.tool or record.action,
            args=record.args,
            ok=payload["status"] in {ToolStatus.OK.value, ToolStatus.SKIPPED.value},
            reason=record.reason,
            payload={
                "node": record.node,
                "tool": record.tool,
                "action": record.action,
                "finding_ids": record.finding_ids,
                "error": payload["error"],
                "playbook": True,
            },
        )


def run_playbook(
    name: str,
    *,
    scope: Scope,
    target: str,
    memory: MemoryStore,
    **kwargs: Any,
) -> PlaybookResult:
    """Convenience wrapper: look up a playbook and execute it."""
    playbook = get_playbook(name)
    return PlaybookRunner(scope=scope, target=target, memory=memory, **kwargs).run(playbook)


__all__ = [
    "PLAYBOOKS",
    "Facts",
    "Playbook",
    "PlaybookResult",
    "PlaybookRunner",
    "PlaybookStep",
    "describe_playbooks",
    "get_playbook",
    "playbook_names",
    "run_playbook",
]
