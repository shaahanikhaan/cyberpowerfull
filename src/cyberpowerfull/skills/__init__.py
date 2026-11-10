"""Skill packs: modular Markdown/Jinja knowledge injected into the system prompt.

A skill pack is not executable code. It is a behavioural contract for one
vulnerability class: signals, probe order, validation criteria, the evidence
required to claim a finding, and the conditions that stop the branch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cyberpowerfull.errors import CyberpowerfullError
from cyberpowerfull.models import Phase
from cyberpowerfull.templating import get_environment


@dataclass(frozen=True)
class SkillPack:
    """Metadata for one skill pack."""

    name: str
    title: str
    category: str
    tools: tuple[str, ...]
    summary: str

    @property
    def template_name(self) -> str:
        return f"skills/packs/{self.name}.md.jinja"


SKILLS: dict[str, SkillPack] = {
    pack.name: pack
    for pack in (
        SkillPack(
            "authentication_jwt",
            "Authentication & JWT",
            "auth",
            ("httpx", "ffuf"),
            "Token handling, signature confusion, claim tampering, session lifecycle.",
        ),
        SkillPack(
            "idor",
            "Insecure Direct Object Reference",
            "access_control",
            ("httpx", "ffuf", "payload", "http_probe"),
            "Horizontal and vertical object access using two identities.",
        ),
        SkillPack(
            "sql_injection",
            "SQL Injection",
            "injection",
            ("sqlmap", "ffuf", "payload", "http_probe"),
            "Boolean differentials, error signatures, confirmation-only sqlmap use.",
        ),
        SkillPack(
            "xss",
            "Cross-Site Scripting",
            "injection",
            ("dalfox", "ffuf", "payload", "http_probe"),
            "Reflection context mapping and payload confirmation.",
        ),
        SkillPack(
            "ssrf",
            "Server-Side Request Forgery",
            "server_side",
            ("httpx", "nuclei", "payload", "http_probe"),
            "Server-initiated requests to in-scope collaborators.",
        ),
        SkillPack(
            "csrf",
            "Cross-Site Request Forgery",
            "session",
            ("httpx",),
            "Token presence, SameSite behaviour, Origin validation.",
        ),
        SkillPack(
            "xxe",
            "XML External Entity",
            "injection",
            ("httpx", "nuclei", "payload", "http_probe"),
            "DOCTYPE/entity handling in XML and document parsers.",
        ),
        SkillPack(
            "rce",
            "Remote Code Execution",
            "injection",
            ("nuclei", "httpx", "payload", "http_probe"),
            "Proof-only evaluation of interpreters and template engines.",
        ),
        SkillPack(
            "business_logic",
            "Business Logic Abuse",
            "logic",
            ("httpx", "ffuf"),
            "Client-controlled value, entitlement, and workflow state.",
        ),
        SkillPack(
            "race_conditions",
            "Race Conditions",
            "logic",
            ("httpx",),
            "Check-then-act limits tested with small parallel bursts.",
        ),
        SkillPack(
            "path_traversal",
            "Path Traversal",
            "file_access",
            ("ffuf", "httpx", "payload", "http_probe"),
            "Encoded traversal sequences against file parameters.",
        ),
        SkillPack(
            "open_redirect",
            "Open Redirect",
            "redirect",
            ("httpx", "nuclei", "payload", "http_probe"),
            "Location header control through redirect parameters.",
        ),
        SkillPack(
            "mass_assignment",
            "Mass Assignment",
            "logic",
            ("httpx", "payload", "http_probe"),
            "Privileged fields accepted from client-controlled bodies.",
        ),
        SkillPack(
            "file_uploads",
            "File Upload",
            "file_access",
            ("httpx", "ffuf"),
            "Type, extension, and serving behaviour of uploaded content.",
        ),
        SkillPack(
            "information_disclosure",
            "Information Disclosure",
            "discovery",
            ("nmap", "httpx", "nikto", "nuclei", "ffuf", "tcp_probe"),
            "Banners, debug endpoints, backups, and leaked metadata.",
        ),
        SkillPack(
            "subdomain_takeover",
            "Subdomain Takeover",
            "dns",
            ("subfinder", "httpx"),
            "Dangling DNS records pointing at unclaimed provider resources.",
        ),
        SkillPack(
            "subdomain_enum",
            "Subdomain Enumeration",
            "dns",
            ("subfinder", "amass", "dnsrecon", "gobuster", "httpx"),
            "Passive-first subdomain discovery and scoped resolution.",
        ),
        SkillPack(
            "network_services",
            "Network Service Assessment",
            "network",
            ("nmap", "masscan", "naabu", "tcp_probe", "searchsploit", "cve_correlate"),
            "Port surface, service identification, and exploit availability.",
        ),
        SkillPack(
            "tls_hardening",
            "TLS Configuration Review",
            "tls",
            ("testssl", "httpx"),
            "Protocol, cipher, and certificate weaknesses with testssl evidence.",
        ),
        SkillPack(
            "api_security",
            "API Security",
            "api",
            ("katana", "arjun", "nuclei", "ffuf", "http_probe", "payload"),
            "Route harvesting, hidden parameters, and object-level authorisation.",
        ),
        SkillPack(
            "graphql",
            "GraphQL",
            "api",
            ("katana", "arjun", "nuclei", "payload", "http_probe"),
            "Introspection exposure, field suggestions, and mutation authorisation.",
        ),
        SkillPack(
            "deserialization",
            "Insecure Deserialization",
            "injection",
            ("httpx", "nuclei"),
            "Serialised blobs, type confusion, and proof-only validation.",
        ),
        SkillPack(
            "cms_wordpress",
            "WordPress and CMS",
            "cms",
            ("wpscan", "whatweb", "nuclei"),
            "Core, plugin and theme enumeration with advisory matching.",
        ),
        SkillPack(
            "cloud_metadata",
            "Cloud Metadata Exposure",
            "cloud",
            ("httpx", "nuclei"),
            "Link-local reachability from client-controlled fetches.",
        ),
        SkillPack(
            "active_directory",
            "Active Directory",
            "network",
            ("nmap", "dnsrecon", "tcp_probe"),
            "Domain discovery and anonymous read access on AD services.",
        ),
        SkillPack(
            "container_kubernetes",
            "Containers and Kubernetes",
            "cloud",
            ("httpx", "nuclei", "testssl"),
            "Orchestrator and kubelet endpoints, read-only exposure checks.",
        ),
        SkillPack(
            "credential_testing",
            "Bounded Credential Testing",
            "credentials",
            ("hydra", "httpx"),
            "Explicit, capped, account-scoped authentication testing.",
        ),
        SkillPack(
            "exploit_availability",
            "Exploit Availability",
            "exploit",
            ("searchsploit", "nuclei", "cve_correlate", "http_probe"),
            "Local Exploit-DB correlation against confirmed versions.",
        ),
        SkillPack(
            "external_validation",
            "External Agent Validation",
            "automation",
            ("strix", "pentagi", "sn1per"),
            "Budgeted delegation to an external autonomous agent.",
        ),
    )
}


#: Skill packs that fit a phase when the attack tree names no skill.
_PHASE_PRIORITY: dict[Phase, tuple[str, ...]] = {
    Phase.RECON: (
        "information_disclosure",
        "subdomain_enum",
        "network_services",
        "subdomain_takeover",
        "tls_hardening",
        "api_security",
        "cloud_metadata",
        "active_directory",
        "container_kubernetes",
    ),
    Phase.SCANNING: (
        "information_disclosure",
        "network_services",
        "tls_hardening",
        "cms_wordpress",
        "api_security",
        "subdomain_enum",
        "graphql",
        "credential_testing",
        "exploit_availability",
        "active_directory",
        "container_kubernetes",
        "cloud_metadata",
    ),
    Phase.VALIDATION: (
        "sql_injection",
        "xss",
        "ssrf",
        "idor",
        "authentication_jwt",
        "rce",
        "path_traversal",
        "file_uploads",
        "xxe",
        "business_logic",
        "api_security",
        "graphql",
        "exploit_availability",
        "external_validation",
        "deserialization",
        "csrf",
        "open_redirect",
        "mass_assignment",
        "race_conditions",
        "information_disclosure",
    ),
    Phase.REPORTING: ("information_disclosure",),
}


def select_skills(
    phase: Phase,
    node_skills: list[str] | None = None,
    *,
    limit: int = 8,
) -> list[str]:
    """Choose the skill packs for one step.

    Injected skill text is context, and context is the scarcest resource on a
    small local model. The tree's own hypotheses come first, then the packs that
    fit the current phase, then deterministic fill. The result is capped.
    """
    selected: list[str] = []
    for name in node_skills or []:
        if name in SKILLS and name not in selected:
            selected.append(name)
    for name in _PHASE_PRIORITY.get(phase, ()):
        if name in SKILLS and name not in selected:
            selected.append(name)
    for name in skill_names():
        if name not in selected:
            selected.append(name)
    return selected[: max(limit, 1)]


def skill_names() -> list[str]:
    return sorted(SKILLS)


def get_skill(name: str) -> SkillPack:
    try:
        return SKILLS[name]
    except KeyError as exc:
        raise CyberpowerfullError(
            f"unknown skill pack {name!r}; available: {', '.join(skill_names())}"
        ) from exc


def render_skill(name: str, context: dict[str, Any]) -> str:
    """Render one skill pack to text."""
    pack = get_skill(name)
    template = get_environment().get_template(pack.template_name)
    return template.render(**context).strip()


def render_skills(names: list[str] | None, context: dict[str, Any]) -> str:
    """Render several skill packs, joined by a separator."""
    selected = names if names else skill_names()
    blocks = [render_skill(name, context) for name in selected]
    return "\n\n---\n\n".join(blocks)


def skill_index() -> list[dict[str, Any]]:
    """Machine-readable index injected into the system prompt and the CLI."""
    return [
        {
            "name": pack.name,
            "title": pack.title,
            "category": pack.category,
            "tools": list(pack.tools),
            "summary": pack.summary,
        }
        for pack in (SKILLS[name] for name in skill_names())
    ]


__all__ = [
    "SKILLS",
    "SkillPack",
    "get_skill",
    "render_skill",
    "render_skills",
    "select_skills",
    "skill_index",
    "skill_names",
]
