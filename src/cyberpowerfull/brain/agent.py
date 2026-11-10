"""Built-in autonomous agent: the ``auto`` decision backend.

:class:`AutoAgent` implements the :class:`~cyberpowerfull.brain.llm.LLMClient`
protocol, so it plugs into the reasoning loop exactly where a local model used
to sit -- but it decides deterministically, in microseconds, from live facts:

* a journal parsed out of every tool result (open ports, URLs, technologies,
  subdomains, CVEs, failures),
* the shared :class:`~cyberpowerfull.playbook.Facts` fact base,
* the live toolchain inventory (never schedules a missing binary),
* the scope (never schedules a phase or capability the engagement did not
  grant), and
* the append-only memory (never repeats an invocation the negative cache
  already condemned).

The strategy is a pentester's standard operating procedure in code: map the
surface (TCP sweep, HTTP confirmation, DNS), fingerprint the stack, crawl and
enumerate, validate with templates, then escalate on evidence -- a CVE name
becomes an Exploit-DB lookup, a ``?id=`` URL becomes a sqlmap/dalfox probe, an
open SSH port on a credential-testing engagement becomes a bounded hydra run.
Slow tools (amass, feroxbuster, masscan) only join the plan when the iteration
budget shows the operator asked for a deep pass.

Workers still enforce every guardrail (scope, phase, capability, allowlist),
so an agent mistake degrades to one recorded ``blocked``/``error`` step that
the journal learns from -- never to an out-of-scope action.
"""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING, Any, ClassVar

from cyberpowerfull.brain.orchestrator import WORKER_TOOL_ALLOWLIST
from cyberpowerfull.inventory import Toolchain, build_toolchain, pick_wordlist
from cyberpowerfull.models import Decision, Phase
from cyberpowerfull.playbook import COMMON_TCP_PORTS, Facts

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cyberpowerfull.memory.store import MemoryStore
    from cyberpowerfull.scope import Scope

#: Iteration budget at or above which the slow sweepers (amass, feroxbuster,
#: masscan) become eligible. Below it the agent stays fast on purpose.
DEEP_BUDGET_ITERATIONS = 25

#: A tool that fails this many times in a row is retired for the run. This
#: mirrors the orchestrator's own two-strike retry rule.
MAX_CONSECUTIVE_FAILURES = 2

_PORT_TITLE_RE = re.compile(r"open (?:tcp )?port (\d{1,5})/\w*(?: \(([^)]*)\))?", re.IGNORECASE)
_PORT_KV_RE = re.compile(r"port[=: ](\d{1,5})\b", re.IGNORECASE)
_TCP_OPEN_RE = re.compile(r"tcp_probe open=\[([0-9,\s]*)\]")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_BANNER_PORT_RE = re.compile(r"on (\d{1,5})/\w+:\s*(.{1,80})", re.IGNORECASE)
_VERSION_RE = re.compile(r"^([\w\-.+]+)[/\s]+v?(\d[\w.\-]*)$")

#: Open port -> (hydra service, default login). Only services with a
#: meaningful default account are mapped; anything else stays manual.
_LOGIN_PORTS: dict[int, tuple[str, str]] = {
    21: ("ftp", "anonymous"),
    22: ("ssh", "root"),
    23: ("telnet", "root"),
    1433: ("mssql", "sa"),
    3306: ("mysql", "root"),
    3389: ("rdp", "administrator"),
    5432: ("postgres", "postgres"),
}

#: Worker preference per phase; the agent always double-checks the worker
#: allowlist and falls back to any worker that may run the tool.
_WORKER_BY_PHASE = {
    Phase.RECON: "recon",
    Phase.SCANNING: "scan",
    Phase.VALIDATION: "validate",
}


def _parse_state(step_prompt: str) -> dict[str, Any]:
    """Extract the STATE JSON object from a step prompt, tolerantly."""
    text = step_prompt or ""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return {}
    try:
        payload = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _canonical(args: dict[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, default=str)


class AutoAgent:
    """Deterministic expert agent. No model server, no weights, no latency."""

    backend: ClassVar[str] = "auto"
    model: ClassVar[str] = "auto-1"
    #: The orchestrator skips (fake) token accounting for this backend.
    uses_tokens: ClassVar[bool] = False

    def __init__(self) -> None:
        self._memory: MemoryStore | None = None
        self._scope: Scope | None = None
        self._toolchain: Toolchain | None = None
        self._facts: Facts | None = None
        self._raw_target = ""
        self._deadline: float | None = None
        self._tools: dict[str, Any] | None = None
        self._installed: dict[str, bool] = {}
        self._tried: set[tuple[str, str]] = set()
        self._ok_tools: set[str] = set()
        self._dead_tools: dict[str, str] = {}
        self._failures: dict[str, int] = {}
        self._cves: set[str] = set()
        self._started = time.monotonic()

    # -- wiring --------------------------------------------------------
    def attach_context(
        self,
        *,
        memory: MemoryStore | None = None,
        scope: Scope | None = None,
        target: str | None = None,
        toolchain: Toolchain | None = None,
    ) -> None:
        """Receive the live run context from the orchestrator (best effort).

        Every argument is optional so the agent also works standalone in
        tests. Missing context only costs precision: the workers still
        enforce scope, phase and capability on every delegation.
        """
        if memory is not None:
            self._memory = memory
        if scope is not None:
            self._scope = scope
        if toolchain is not None:
            self._toolchain = toolchain
        if target:
            self._raw_target = target
            self._facts = None

    def set_deadline(self, deadline: float) -> None:
        self._deadline = deadline

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "backend": self.backend,
            "model": self.model,
            "endpoint": "in-process",
            "detail": "deterministic built-in agent (no model server required)",
        }

    # -- LLMClient protocol --------------------------------------------
    def decide(self, system_prompt: str, step_prompt: str, *, step: int = 0) -> Decision:
        try:
            return self._decide(step_prompt, step=step)
        except Exception as exc:  # never crash a run; record why we stopped
            return Decision(
                step=step,
                tool="terminate",
                reason=f"agent halted on internal error: {exc}"[:2000],
                done=True,
            )

    def _decide(self, step_prompt: str, *, step: int) -> Decision:
        state = _parse_state(step_prompt)
        step_n = step or int(state.get("step") or 0)
        target = str(state.get("target") or self._raw_target or "").strip()
        if target and target != self._raw_target:
            self._raw_target = target
            self._facts = None
        self._journal(state.get("last_tool_result"))

        budget = state.get("budget") or {}
        try:
            max_iterations = int(budget.get("max_iterations") or 0)
        except (TypeError, ValueError):
            max_iterations = 0
        if self._deadline is not None and time.monotonic() >= self._deadline:
            return self._terminate(step_n, "wall-clock budget exhausted")
        if max_iterations and step_n >= max_iterations:
            return self._terminate(step_n, "iteration budget exhausted")

        planned = self._plan(deep=max_iterations >= DEEP_BUDGET_ITERATIONS)
        if planned is None:
            return self._terminate(step_n, self._summary())
        tool, args, reason, thought = planned
        self._tried.add((tool, _canonical(args)))
        worker = self._worker_for(tool)
        delegation = {
            "agent": worker,
            "tool": tool,
            "args": args,
            "reason": reason[:400],
        }
        phase = self._tool_phase(tool)
        return Decision(
            step=step_n,
            tool="delegate",
            args=delegation,
            reason=reason[:2000],
            thought=thought[:4000] if thought else None,
            phase=phase,
        )

    # -- journal ---------------------------------------------------------
    def _facts_for(self) -> Facts:
        if self._facts is None:
            host = self._raw_target.strip()
            if "://" in host:
                from urllib.parse import urlsplit

                try:
                    host = urlsplit(host).hostname or host
                except ValueError:
                    pass
            facts = Facts(target=host or self._raw_target)
            if self._raw_target.startswith(("http://", "https://")):
                facts.add_url(self._raw_target)
            toolchain = self._toolchain_for()
            facts.wordlists = {
                "discovery": pick_wordlist("discovery", toolchain=toolchain),
                "passwords": pick_wordlist("passwords", toolchain=toolchain),
                "dns": pick_wordlist("dns", toolchain=toolchain),
                "fuzzing": pick_wordlist("fuzzing", toolchain=toolchain),
            }
            self._facts = facts
        return self._facts

    def _toolchain_for(self) -> Toolchain:
        if self._toolchain is None:
            self._toolchain = build_toolchain(versions=False, include_wordlists=True)
        return self._toolchain

    def _journal(self, last: Any) -> None:
        """Fold the previous tool result into facts, CVEs and failure counts."""
        if not isinstance(last, dict):
            return
        tool = str(last.get("tool") or "")
        status = str(last.get("status") or "")
        texts: list[str] = []
        observations = last.get("observations") or []
        if isinstance(observations, list):
            texts.extend(str(note) for note in observations)
        titles = last.get("finding_titles") or []
        if isinstance(titles, list):
            texts.extend(str(title) for title in titles)
        if last.get("error"):
            texts.append(str(last["error"]))
        if tool:
            if status in {"ok", "skipped"}:
                self._ok_tools.add(tool)
                self._failures[tool] = 0
            elif status in {"blocked", "missing"}:
                self._dead_tools.setdefault(tool, status)
            elif status in {"error", "timeout"}:
                self._failures[tool] = self._failures.get(tool, 0) + 1
                if self._failures[tool] >= MAX_CONSECUTIVE_FAILURES:
                    self._dead_tools.setdefault(tool, f"failed {status} twice in a row")
        facts = self._facts_for()
        for text in texts:
            self._mine_text(facts, text)

    def _mine_text(self, facts: Facts, text: str) -> None:
        for url in _URL_RE.findall(text):
            facts.add_url(url.rstrip(".,;)"))
        for cve in _CVE_RE.findall(text):
            self._cves.add(cve.upper())
        tcp_open = _TCP_OPEN_RE.search(text)
        if tcp_open:
            for chunk in tcp_open.group(1).split(","):
                if chunk.strip().isdigit():
                    facts.add_port(int(chunk.strip()))
        for match in _PORT_TITLE_RE.finditer(text):
            facts.add_port(int(match.group(1)), (match.group(2) or "").strip())
        for match in _PORT_KV_RE.finditer(text):
            facts.add_port(int(match.group(1)))
        banner = _BANNER_PORT_RE.search(text)
        if banner:
            facts.add_port(int(banner.group(1)), banner.group(2).strip())
        lowered = text.lower()
        if "wordpress" in lowered:
            facts.add_tech("wordpress")
        if text.startswith("Technology fingerprint:"):
            for token in text.split(":", 1)[1].split(","):
                facts.add_tech(token.strip())
        elif text.startswith("Technology version disclosed:"):
            facts.add_tech(text.split(":", 1)[1].strip())
        if "tech=" in lowered:
            for token in text.split("tech=", 1)[1].split(",")[:6]:
                facts.add_tech(token.strip())
        if text.startswith("Subdomain discovered:"):
            facts.add_subdomain(text.split(":", 1)[1].strip())
        elif "vhost" in lowered and text.startswith("Subdomain/vhost discovered:"):
            facts.add_subdomain(text.split(":", 1)[1].strip())

    # -- planning --------------------------------------------------------
    def _plan(self, *, deep: bool) -> tuple[str, dict[str, Any], str, str] | None:
        facts = self._facts_for()
        for candidate in self._escalations(facts):
            built = self._consider(*candidate)
            if built is not None:
                return built
        for candidate in self._ladder(facts, deep=deep):
            built = self._consider(*candidate)
            if built is not None:
                return built
        return None

    def _consider(
        self, tool: str, args: dict[str, Any] | None, reason: str, thought: str
    ) -> tuple[str, dict[str, Any], str, str] | None:
        if args is None or tool in self._dead_tools:
            return None
        if (tool, _canonical(args)) in self._tried:
            return None
        if not self._installed_ok(tool):
            self._dead_tools.setdefault(tool, "binary not installed")
            return None
        if not self._capable(tool):
            self._dead_tools.setdefault(tool, "capability not granted by scope")
            return None
        if not self._phase_ok(tool):
            self._dead_tools.setdefault(tool, "phase not permitted by scope")
            return None
        if self._memory is not None:
            try:
                if self._memory.negative_cache_hit(tool, args):
                    return None
            except Exception as exc:
                # Memory negative-cache lookup is best-effort: do not block
                # planning if the backing store is unavailable or misbehaves.
                self._dead_tools.setdefault(
                    tool, f"negative-cache lookup failed: {exc.__class__.__name__}"
                )
        return (tool, args, reason, thought)

    def _escalations(self, facts: Facts) -> list[tuple[str, dict[str, Any] | None, str, str]]:
        """Evidence-driven follow-ups, highest value first."""
        host = facts.target
        out: list[tuple[str, dict[str, Any] | None, str, str]] = []
        for cve in sorted(self._cves):
            out.append(
                (
                    "searchsploit",
                    {"target": host, "query": cve},
                    f"template evidence named {cve}; look up public exploits locally",
                    f"escalation: {cve} -> searchsploit",
                )
            )
        if any("wordpress" in tech.lower() for tech in facts.tech):
            out.append(
                (
                    "wpscan",
                    {"target": facts.primary_url, "enumerate": ["vp", "vt", "u"]},
                    "fingerprint says WordPress; enumerate core/plugins/users passively",
                    "escalation: wordpress -> wpscan",
                )
            )
        param_urls = [url for url in facts.urls if "?" in url]
        if param_urls:
            out.append(
                (
                    "sqlmap",
                    {"target": param_urls[0]},
                    f"crawl found parameters at {param_urls[0][:80]}; test for SQL injection",
                    "escalation: parameters -> sqlmap",
                )
            )
            out.append(
                (
                    "dalfox",
                    {"target": param_urls[0]},
                    f"crawl found parameters at {param_urls[0][:80]}; test for XSS",
                    "escalation: parameters -> dalfox",
                )
            )
        login = self._login_service(facts)
        if login is not None:
            port, service, username = login
            wordlist = facts.wordlists.get("passwords")
            out.append(
                (
                    "hydra",
                    (
                        {
                            "target": host,
                            "service": service,
                            "port": port,
                            "username": username,
                            "password_list": wordlist,
                        }
                        if wordlist
                        else None
                    ),
                    f"{service} is open on {port}; bounded credential check as {username}",
                    "escalation: login service -> hydra",
                )
            )
        tls_url = self._tls_url(facts)
        if tls_url is not None:
            out.append(
                (
                    "testssl",
                    {"target": tls_url, "severity_floor": "LOW", "check": "protocols"},
                    f"TLS endpoint {tls_url[:80]} confirmed; review protocol support",
                    "escalation: tls -> testssl",
                )
            )
        components = self._components(facts)
        if components:
            out.append(
                (
                    "cve_correlate",
                    {
                        "target": host,
                        "components": components,
                        "min_severity": "high",
                    },
                    f"observed {len(components)} product(s); correlate against local advisories",
                    "escalation: tech stack -> cve_correlate",
                )
            )
        for tech in facts.tech:
            product = tech.split("/")[0].split()[0][:60]
            if len(product) >= 2:
                out.append(
                    (
                        "searchsploit",
                        {"target": host, "query": product},
                        f"observed {product}; look up public exploits locally",
                        f"escalation: {product} -> searchsploit",
                    )
                )
                break
        return out

    def _ladder(
        self, facts: Facts, *, deep: bool
    ) -> list[tuple[str, dict[str, Any] | None, str, str]]:
        """The standard sweep, ordered so each step feeds the next."""
        host = facts.target
        has_templates = bool(self._toolchain_for().nuclei_templates.get("path"))
        discovery_wl = facts.wordlists.get("discovery")
        ladder: list[tuple[str, dict[str, Any] | None, str, str]] = [
            (
                "tcp_probe",
                {"target": host, "ports": list(COMMON_TCP_PORTS), "timeout_s": 1.0},
                "map common TCP ports with the native prober (no binary needed)",
                "ladder 1: port surface",
            ),
            (
                "httpx",
                {
                    "target": f"https://{host}",
                    "tech_detect": True,
                    "follow_redirects": True,
                    "threads": 10,
                },
                "confirm the HTTPS endpoint and fingerprint its technologies",
                "ladder 2: https confirm",
            ),
            (
                "httpx",
                {
                    "target": f"http://{host}",
                    "tech_detect": True,
                    "follow_redirects": True,
                    "threads": 10,
                },
                "confirm the plain HTTP endpoint (downgrade/misconfig signal)",
                "ladder 3: http confirm",
            ),
        ]
        if facts.domain:
            ladder.append(
                (
                    "subfinder",
                    {"target": facts.domain, "all_sources": True},
                    f"enumerate subdomains of {facts.domain} passively",
                    "ladder 4: subdomains",
                )
            )
            ladder.append(
                (
                    "dnsrecon",
                    {"target": facts.domain, "scan_type": "std"},
                    f"collect DNS records for {facts.domain} and check AXFR",
                    "ladder 5: dns",
                )
            )
        ladder.extend(
            [
                (
                    "whatweb",
                    {"target": facts.primary_url, "aggression": 1},
                    "fingerprint the web stack quietly",
                    "ladder 6: fingerprint",
                ),
                (
                    "wafw00f",
                    {"target": facts.primary_url, "find_all": True},
                    "detect filtering in front of the app before heavier scans",
                    "ladder 7: waf check",
                ),
                (
                    "katana",
                    {
                        "target": facts.primary_url,
                        "depth": 2,
                        "concurrency": 8,
                        "rate_limit": 40,
                        "known_files": True,
                    },
                    "crawl endpoints and harvest parameters for validation",
                    "ladder 8: crawl",
                ),
                (
                    "naabu",
                    {"target": host, "top_ports": 1000, "rate": 300},
                    "confirm the top-1000 port surface quickly",
                    "ladder 9: fast ports",
                ),
                (
                    "nmap",
                    self._nmap_args(facts),
                    "service detection across the discovered surface",
                    "ladder 10: services",
                ),
                (
                    "nikto",
                    self._nikto_args(facts),
                    "misconfiguration pass over the web service",
                    "ladder 11: misconfig",
                ),
                (
                    "gobuster",
                    (
                        {"target": facts.primary_url, "mode": "dir", "threads": 20}
                        if discovery_wl
                        else None
                    ),
                    "brute-force directories with the host wordlist",
                    "ladder 12: directories",
                ),
                (
                    "ffuf",
                    (
                        {
                            "target": f"{facts.primary_url}/FUZZ",
                            "wordlist": discovery_wl,
                            "threads": 30,
                            "extensions": ["php", "bak", "txt"],
                        }
                        if discovery_wl
                        else None
                    ),
                    "fuzz content paths including backup extensions",
                    "ladder 13: fuzz",
                ),
            ]
        )
        if deep:
            ladder.append(
                (
                    "feroxbuster",
                    {"target": facts.primary_url, "depth": 2, "threads": 20},
                    "recursive content discovery (deep pass)",
                    "ladder 14: recursive discovery",
                )
            )
        ladder.extend(
            [
                (
                    "arjun",
                    {"target": facts.primary_url, "method": "GET", "threads": 6},
                    "discover hidden HTTP parameters",
                    "ladder 15: parameters",
                ),
                (
                    "nuclei",
                    (
                        {
                            "target": facts.primary_url,
                            "severity": ["low", "medium", "high", "critical"],
                            **({"tags": ["api", "graphql", "swagger", "exposure", "cors"]}
                               if self._api_evidence(facts)
                               else {}),
                            "rate_limit": 20,
                            "concurrency": 10,
                        }
                        if has_templates
                        else None
                    ),
                    "validate with nuclei templates against the live app",
                    "ladder 16: templates",
                ),
            ]
        )
        if facts.domain and facts.wordlists.get("dns"):
            ladder.append(
                (
                    "gobuster",
                    {"target": facts.domain, "mode": "dns", "threads": 20},
                    f"brute-force subdomains of {facts.domain}",
                    "ladder 17: dns brute force",
                )
            )
        if deep:
            if facts.domain:
                ladder.append(
                    (
                        "amass",
                        {"target": facts.domain, "timeout_minutes": 3},
                        "second passive enumeration source (deep pass)",
                        "ladder 18: amass",
                    )
                )
            ladder.append(
                (
                    "masscan",
                    {"target": host, "ports": "1-65535", "rate": 800},
                    "full-range sweep for services on odd ports (deep pass)",
                    "ladder 19: full range",
                )
            )
        return ladder

    # -- argument builders -------------------------------------------------
    def _nmap_args(self, facts: Facts) -> dict[str, Any]:
        if facts.open_ports:
            ports = ",".join(str(port) for port in sorted(facts.open_ports)[:150])
            return {
                "target": facts.target,
                "ports": ports,
                "service_detection": True,
                "timing": 4,
                "scripts": ["http-title", "http-headers", "ssl-cert"],
            }
        return {
            "target": facts.target,
            "ports": "top-1000",
            "service_detection": True,
            "timing": 4,
        }

    def _nikto_args(self, facts: Facts) -> dict[str, Any]:
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(facts.primary_url)
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            port = 443
        return {
            "target": facts.target,
            "port": port,
            "ssl": facts.primary_url.startswith("https"),
        }

    def _login_service(self, facts: Facts) -> tuple[int, str, str] | None:
        for port in sorted(facts.open_ports):
            mapped = _LOGIN_PORTS.get(port)
            if mapped is not None:
                return (port, mapped[0], mapped[1])
        return None

    def _tls_url(self, facts: Facts) -> str | None:
        for url in facts.urls:
            if url.startswith("https://"):
                return url
        for port in sorted(facts.open_ports):
            if port in {443, 8443, 9443}:
                return f"https://{facts.target}:{port}"
        return None

    def _api_evidence(self, facts: Facts) -> bool:
        needles = ("/api", "graphql", "swagger", "openapi")
        haystacks = [url.lower() for url in facts.urls]
        haystacks.extend(tech.lower() for tech in facts.tech)
        return any(needle in hay for needle in needles for hay in haystacks)

    def _components(self, facts: Facts) -> list[dict[str, Any]]:
        components: list[dict[str, Any]] = []
        seen: set[str] = set()
        for tech in facts.tech:
            token = tech.strip()
            if not token or token.lower() in seen:
                continue
            seen.add(token.lower())
            match = _VERSION_RE.match(token)
            if match:
                components.append({"product": match.group(1), "version": match.group(2)})
            else:
                product = token.split("/")[0].split()[0]
                if len(product) >= 2:
                    components.append({"product": product})
            if len(components) >= 10:
                break
        return components

    # -- eligibility -------------------------------------------------------
    def _registry(self) -> dict[str, Any]:
        if self._tools is None:
            from cyberpowerfull.tools.registry import all_tools

            self._tools = all_tools()
        return self._tools

    def _installed_ok(self, tool: str) -> bool:
        if tool not in self._installed:
            handle = self._registry().get(tool)
            if handle is None:
                self._installed[tool] = False
            else:
                try:
                    self._installed[tool] = bool(handle.describe().get("installed", False))
                except Exception:
                    self._installed[tool] = False
        return self._installed[tool]

    def _tool_phase(self, tool: str) -> Phase:
        handle = self._registry().get(tool)
        phase = getattr(handle, "phase", None)
        return phase if isinstance(phase, Phase) else Phase.RECON

    def _capable(self, tool: str) -> bool:
        if self._scope is None:
            return True
        handle = self._registry().get(tool)
        capability = getattr(handle, "required_capability", None)
        try:
            return bool(self._scope.allows(capability))
        except Exception:
            return True

    def _phase_ok(self, tool: str) -> bool:
        if self._scope is None:
            return True
        try:
            return bool(self._scope.phase_allowed(self._tool_phase(tool)))
        except Exception:
            return True

    def _worker_for(self, tool: str) -> str:
        preferred = _WORKER_BY_PHASE.get(self._tool_phase(tool), "recon")
        allowed = WORKER_TOOL_ALLOWLIST
        if tool in allowed.get(preferred, frozenset()):
            return preferred
        for worker in ("recon", "scan", "validate", "external"):
            if tool in allowed.get(worker, frozenset()):
                return worker
        return preferred

    # -- termination -------------------------------------------------------
    def _terminate(self, step: int, reason: str) -> Decision:
        return Decision(step=step, tool="terminate", reason=reason[:2000], done=True)

    def _summary(self) -> str:
        facts = self._facts_for()
        findings = 0
        if self._memory is not None:
            try:
                findings = len(self._memory.findings())
            except Exception:
                findings = 0
        parts = [
            f"coverage complete: {len(self._ok_tools)} tool(s) ran clean, "
            f"{len(self._dead_tools)} unavailable/blocked, "
            f"{len(facts.open_ports)} open port(s), {len(facts.urls)} url(s), "
            f"{findings} finding(s) kept"
        ]
        if self._dead_tools:
            notes = "; ".join(f"{tool} ({why})" for tool, why in sorted(self._dead_tools.items()))
            parts.append(f"unavailable: {notes}"[:1500])
        return ". ".join(parts)


__all__ = ["AutoAgent", "DEEP_BUDGET_ITERATIONS", "MAX_CONSECUTIVE_FAILURES"]
