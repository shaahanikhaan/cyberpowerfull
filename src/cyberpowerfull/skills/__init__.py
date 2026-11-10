"""Skill packs: modular Markdown/Jinja knowledge injected into the system prompt.

A skill pack is not executable code. It is a behavioural contract for one
vulnerability class: signals, probe order, validation criteria, the evidence
required to claim a finding, and the conditions that stop the branch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cyberpowerfull.errors import CyberpowerfullError
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
            ("httpx", "ffuf"),
            "Horizontal and vertical object access using two identities.",
        ),
        SkillPack(
            "sql_injection",
            "SQL Injection",
            "injection",
            ("sqlmap", "ffuf"),
            "Boolean differentials, error signatures, confirmation-only sqlmap use.",
        ),
        SkillPack(
            "xss",
            "Cross-Site Scripting",
            "injection",
            ("dalfox", "ffuf"),
            "Reflection context mapping and payload confirmation.",
        ),
        SkillPack(
            "ssrf",
            "Server-Side Request Forgery",
            "server_side",
            ("httpx", "nuclei"),
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
            ("httpx", "nuclei"),
            "DOCTYPE/entity handling in XML and document parsers.",
        ),
        SkillPack(
            "rce",
            "Remote Code Execution",
            "injection",
            ("nuclei", "httpx"),
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
            ("ffuf", "httpx"),
            "Encoded traversal sequences against file parameters.",
        ),
        SkillPack(
            "open_redirect",
            "Open Redirect",
            "redirect",
            ("httpx", "nuclei"),
            "Location header control through redirect parameters.",
        ),
        SkillPack(
            "mass_assignment",
            "Mass Assignment",
            "logic",
            ("httpx",),
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
    )
}


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
    "skill_index",
    "skill_names",
]
