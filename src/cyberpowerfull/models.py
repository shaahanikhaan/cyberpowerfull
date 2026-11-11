"""Core data contracts shared by every layer.

Everything the reasoning model exchanges with the rest of the system is typed
here: phases, severities, findings, and the single-decision JSON contract
``{"step": ..., "tool": ..., "args": {...}, "reason": ...}``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp used across traces and memory rows."""
    return datetime.now(timezone.utc)


def new_id(prefix: str = "") -> str:
    """Short, trace-friendly identifier."""
    token = uuid.uuid4().hex[:12]
    return f"{prefix}{token}" if prefix else token


class Phase(str, Enum):
    """Pentest phases. There is no chat phase by design."""

    RECON = "recon"
    SCANNING = "scanning"
    VALIDATION = "validation"
    REPORTING = "reporting"


class Capability(str, Enum):
    """Explicit, opt-in engagement permissions declared in ``scope.json``.

    A tool that needs one of these is blocked by the worker layer unless the
    scope grants it. Nothing is enabled by default: a scope with no
    ``capabilities`` entry runs only passive and polite checks.
    """

    AGGRESSIVE = "aggressive"
    CREDENTIAL_TESTING = "credential_testing"
    EXTERNAL_AGENTS = "external_agents"
    DESTRUCTIVE = "destructive"


class Severity(str, Enum):
    """Finding severity, ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def coerce(cls, value: str | None) -> Severity:
        """Map tool-specific severity labels onto this enum."""
        if not value:
            return cls.INFO
        normalised = str(value).strip().lower()
        aliases = {
            "informational": cls.INFO,
            "unknown": cls.INFO,
            "none": cls.INFO,
            "moderate": cls.MEDIUM,
            "important": cls.HIGH,
            "crit": cls.CRITICAL,
            "error": cls.HIGH,
            "warning": cls.MEDIUM,
        }
        if normalised in aliases:
            return aliases[normalised]
        try:
            return cls(normalised)
        except ValueError:
            return cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Finding(BaseModel):
    """A single evidenced observation produced by a tool wrapper.

    A finding is only created from tool output; the reasoning model may
    prioritise findings but can never invent one.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: new_id("f-"))
    title: str = Field(min_length=3, max_length=300)
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    target: str
    endpoint: str | None = None
    evidence: str = Field(default="", max_length=4000)
    tool: str = ""
    skill: str | None = None
    cwe: str | None = None
    cve: str | None = None
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    remediation: str | None = None
    verified: bool = False
    phase: Phase = Phase.RECON
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("evidence")
    @classmethod
    def _trim_evidence(cls, value: str) -> str:
        return value.strip()


class Decision(BaseModel):
    """The reasoning layer's single-step output contract.

    Exactly one JSON object per step. ``tool`` names either an orchestrator
    action (``delegate`` / ``terminate``) or a concrete tool for a worker.
    """

    model_config = ConfigDict(extra="forbid")

    step: int = 0
    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=2000)
    thought: str | None = Field(default=None, max_length=4000)
    phase: Phase = Phase.RECON
    node: str | None = None
    done: bool = False


class BudgetState(BaseModel):
    """Deterministic run budget, checked by the orchestrator (never the model)."""

    max_iterations: int = 12
    max_tokens: int = 32_000
    max_seconds: int = 900
    iterations: int = 0
    tokens_used: int = 0
    seconds_used: float = 0.0

    @property
    def tokens_left(self) -> int:
        return max(self.max_tokens - self.tokens_used, 0)

    @property
    def iterations_left(self) -> int:
        return max(self.max_iterations - self.iterations, 0)

    def exhausted(self) -> str | None:
        """Return the exhausted dimension, or ``None`` when budget remains."""
        if self.iterations >= self.max_iterations:
            return "iterations"
        if self.tokens_used >= self.max_tokens:
            return "tokens"
        if self.seconds_used >= self.max_seconds:
            return "seconds"
        return None


def estimate_tokens(text: str) -> int:
    """Cheap deterministic token estimate (~4 characters per token)."""
    return max(len(text) // 4, 1)


__all__ = [
    "BudgetState",
    "Capability",
    "Decision",
    "Finding",
    "Phase",
    "Severity",
    "estimate_tokens",
    "new_id",
    "utcnow",
]
