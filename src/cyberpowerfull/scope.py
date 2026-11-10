"""Engagement scope: the gate every action must pass.

The agent refuses to start without a valid ``scope.json``. Scope is loaded from
disk, validated, fingerprinted, and injected into the system prompt by the
system - never by the reasoning model. Every tool call is re-checked against the
loaded scope by the worker layer.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cyberpowerfull.errors import ScopeError
from cyberpowerfull.models import Phase

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_HOST_ALLOWED = re.compile(r"^[A-Za-z0-9.\-_:\[\]]+$")


def normalize_host(value: str) -> str:
    """Reduce a URL, host:port, or bare host to a lowercase host string."""
    if not isinstance(value, str) or not value.strip():
        raise ScopeError("empty host value")
    candidate = value.strip()
    candidate = _SCHEME_RE.sub("", candidate)
    candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    candidate = candidate.rsplit("@", 1)[-1]
    if candidate.startswith("["):  # bracketed IPv6, optionally with port
        end = candidate.find("]")
        candidate = candidate[1:end] if end != -1 else candidate[1:]
    elif candidate.count(":") == 1:  # host:port (IPv4 / DNS)
        candidate = candidate.split(":", 1)[0]
    candidate = candidate.rstrip(".")
    if not _HOST_ALLOWED.match(candidate):
        raise ScopeError(f"refusing to parse host value: {value!r}")
    return candidate.lower()


def _as_network(entry: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _suffix_match(host: str, entry: str) -> bool:
    entry = entry.lower().rstrip(".")
    if entry.startswith("*."):
        entry = entry[2:]
    return host == entry or host.endswith("." + entry)


class Scope(BaseModel):
    """Authorized engagement scope, as declared on disk."""

    model_config = ConfigDict(extra="forbid")

    engagement: str = Field(min_length=1, max_length=120)
    authorized: bool = False
    authorization_ref: str | None = Field(default=None, max_length=200)
    targets: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    allowed_phases: list[Phase] = Field(
        default_factory=lambda: [Phase.RECON, Phase.SCANNING, Phase.VALIDATION]
    )
    max_rps: float = Field(default=5.0, gt=0, le=100)
    expires: date | None = None
    contact: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("targets", "domains", "exclude")
    @classmethod
    def _validate_entries(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("scope entries must be non-empty strings")
            cleaned.append(value.strip())
        return cleaned

    def assert_runnable(self) -> None:
        """Raise :class:`ScopeError` unless this engagement may be executed."""
        if not self.authorized:
            raise ScopeError(
                'scope.json is not marked authorized: set "authorized": true only for '
                "engagements you are contractually permitted to test"
            )
        if not self.targets and not self.domains:
            raise ScopeError("scope.json must declare at least one target or domain")
        if not self.allowed_phases:
            raise ScopeError("scope.json must declare at least one allowed phase")
        if self.expires is not None:
            today = datetime.now(timezone.utc).date()
            if self.expires < today:
                raise ScopeError(f"scope.json expired on {self.expires.isoformat()}")

    def _excluded(self, host: str) -> bool:
        for entry in self.exclude:
            network = _as_network(entry)
            if network is not None:
                try:
                    if ipaddress.ip_address(host) in network:
                        return True
                except ValueError:
                    continue
                continue
            entry_host = _entry_host(entry)
            if entry_host is not None and _suffix_match(host, entry_host):
                return True
        return False

    def authorizes(self, target: str) -> bool:
        """Return ``True`` only when ``target`` is inside the declared scope."""
        if not self.authorized:
            return False
        try:
            host = normalize_host(target)
        except ScopeError:
            return False
        if self._excluded(host):
            return False
        candidates = [*self.targets, *self.domains]
        for entry in candidates:
            network = _as_network(entry)
            if network is not None:
                try:
                    if ipaddress.ip_address(host) in network:
                        return True
                except ValueError:
                    continue
                continue
            entry_host = _entry_host(entry)
            if entry_host is not None and _suffix_match(host, entry_host):
                return True
        return False

    def require(self, target: str) -> str:
        """Validate and return ``target`` or raise :class:`ScopeViolation`."""
        from cyberpowerfull.errors import ScopeViolation

        if not self.authorizes(target):
            raise ScopeViolation(f"target {target!r} is not inside the authorized scope")
        return normalize_host(target)

    def phase_allowed(self, phase: Phase) -> bool:
        return phase in self.allowed_phases

    def fingerprint(self) -> str:
        """Stable hash of the scope, embedded in every trace for audit."""
        payload = self.model_dump(mode="json", exclude_none=True)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def prompt_block(self) -> str:
        """System-verified scope text injected into the system prompt."""
        lines = [
            f"engagement: {self.engagement}",
            f"authorization_ref: {self.authorization_ref or 'not-declared'}",
            f"in_scope_targets: {', '.join(self.targets) or 'none'}",
            f"in_scope_domains: {', '.join(self.domains) or 'none'}",
            f"excluded: {', '.join(self.exclude) or 'none'}",
            f"allowed_phases: {', '.join(p.value for p in self.allowed_phases)}",
            f"max_requests_per_second: {self.max_rps}",
            f"expires: {self.expires.isoformat() if self.expires else 'no-expiry'}",
            f"scope_fingerprint: {self.fingerprint()[:16]}",
        ]
        return "\n".join(lines)


def _entry_host(entry: str) -> str | None:
    """Normalise a scope entry, tolerating the ``*.`` wildcard prefix."""
    candidate = entry[2:] if entry.startswith("*.") else entry
    try:
        return normalize_host(candidate)
    except ScopeError:
        return None


def load_scope(path: str | Path) -> Scope:
    """Load ``scope.json`` from disk, refusing anything unusable."""
    scope_path = Path(path)
    if not scope_path.exists():
        raise ScopeError(
            f"scope file not found: {scope_path}. The agent refuses to run without an "
            "authorized scope.json (see scope.example.json)"
        )
    try:
        raw: Any = json.loads(scope_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - message detail
        raise ScopeError(f"scope file is not valid JSON: {scope_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScopeError(f"scope file must contain a JSON object: {scope_path}")
    try:
        scope = Scope.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError
        raise ScopeError(f"scope file failed validation: {scope_path}: {exc}") from exc
    scope.assert_runnable()
    return scope


__all__ = ["Scope", "load_scope", "normalize_host"]
