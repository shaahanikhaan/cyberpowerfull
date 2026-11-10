"""Payload data model and the proof-only safety guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cyberpowerfull.errors import PolicyViolation

#: Substrings that have no place in a proof payload. Generation refuses them.
FORBIDDEN_TOKENS: tuple[str, ...] = (
    "rm -rf",
    "mkfs",
    "/etc/shadow",
    "/etc/passwd",
    ":(){:|:&};:",
    "nc -e",
    "bash -i",
    "/bin/sh -i",
    "curl -s http://169.254",
    "169.254.169.254",
    "DROP TABLE",
    "DROP DATABASE",
    "TRUNCATE TABLE",
    "LOAD_FILE(",
    "INTO OUTFILE",
    "xp_cmdshell",
)


@dataclass(frozen=True)
class Payload:
    """One catalogue entry. Templates use ``{marker}``, ``{param}``, ``{target}``."""

    id: str
    skill: str
    technique: str
    context: str
    template: str
    expected_signal: str
    mode: str = "query"
    method: str = "GET"
    header: str | None = None
    builder: str | None = None
    note: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def render(self, *, marker: str, param: str, target: str) -> str:
        text = self.template
        for token, value in (("{marker}", marker), ("{param}", param), ("{target}", target)):
            text = text.replace(token, value)
        return text

    def contains_forbidden(self) -> str | None:
        haystack = " ".join((self.template, self.note)).lower()
        for token in FORBIDDEN_TOKENS:
            if token.lower() in haystack:
                return token
        return None


@dataclass(frozen=True)
class SafetyReport:
    """Result of auditing the catalogue at import/generation time."""

    total: int
    skills: tuple[str, ...]
    violations: tuple[tuple[str, str], ...] = ()

    @property
    def clean(self) -> bool:
        return not self.violations

    def require_clean(self) -> None:
        if self.violations:
            joined = ", ".join(f"{payload_id}:{token}" for payload_id, token in self.violations)
            raise PolicyViolation(f"payload catalogue contains forbidden tokens: {joined}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "skills": list(self.skills),
            "violations": [{"payload": pid, "token": token} for pid, token in self.violations],
            "clean": self.clean,
        }


__all__ = ["FORBIDDEN_TOKENS", "Payload", "SafetyReport"]
