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
from collections.abc import Sequence
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from cyberpowerfull.errors import ScopeError
from cyberpowerfull.models import Capability, Phase

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_HOST = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$")
_IPV4_MAPPED_NETWORK = ipaddress.IPv6Network("::ffff:0:0/96")


def normalize_host(value: str) -> str:
    """Parse and validate a URL, host:port, or bare host into a canonical host.

    Reject ambiguous authorities, userinfo and non-canonical numeric IPs rather
    than checking a different host from the one a network client will use.
    """
    if not isinstance(value, str) or not value.strip():
        raise ScopeError("empty host value")
    candidate = value.strip()
    if "\\" in candidate or any(ord(ch) < 33 or ord(ch) == 127 for ch in candidate):
        raise ScopeError(f"refusing to parse host value: {value!r}")

    # A bare IPv6 literal is ambiguous to urlsplit; validate it directly.
    if (
        not _SCHEME_RE.match(candidate)
        and candidate.count(":") > 1
        and not candidate.startswith("[")
    ):
        try:
            return _canonical_ip(candidate)
        except ValueError as exc:
            raise ScopeError(f"invalid IP address: {value!r}") from exc
    try:
        parsed = urlsplit(candidate if _SCHEME_RE.match(candidate) else "//" + candidate)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("only HTTP(S) URLs are supported")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL userinfo is not permitted")
        _ = parsed.port  # Raises on invalid ports.
        host = (parsed.hostname or "").rstrip(".").lower()
    except ValueError as exc:
        raise ScopeError(f"refusing to parse host value: {value!r}: {exc}") from exc
    if not host:
        raise ScopeError(f"refusing to parse host value: {value!r}")
    try:
        return _canonical_ip(host)
    except ValueError:
        pass
    labels = host.split(".")
    if (
        len(host) > 253
        or any(not _HOST_LABEL.fullmatch(label) for label in labels)
        or _NUMERIC_HOST.fullmatch(host) is not None
    ):
        raise ScopeError(f"refusing to parse host value: {value!r}")
    return host


def _canonical_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def _as_network(entry: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def network_contains(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Match IPv4-mapped IPv6 aliases against either explicit address family.

    A specifically mapped IPv6 CIDR must not become ineffective merely because
    the host was canonicalized to IPv4. Broad IPv6 CIDRs do not implicitly grant
    authority over ordinary IPv4 addresses.
    """
    if (
        isinstance(address, ipaddress.IPv6Address)
        and address.ipv4_mapped is not None
        and isinstance(network, ipaddress.IPv4Network)
    ):
        return address.ipv4_mapped in network
    if (
        isinstance(address, ipaddress.IPv4Address)
        and isinstance(network, ipaddress.IPv6Network)
        and network.subnet_of(_IPV4_MAPPED_NETWORK)
    ):
        return ipaddress.IPv6Address(f"::ffff:{address}") in network
    return address in network


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _suffix_match(host: str, entry: str) -> bool:
    entry = entry.lower().rstrip(".")
    wildcard = entry.startswith("*.")
    if wildcard:
        entry = entry[2:]
    return (not wildcard and host == entry) or host.endswith("." + entry)


class Scope(BaseModel):
    """Authorized engagement scope, as declared on disk."""

    model_config = ConfigDict(extra="forbid")

    engagement: str = Field(min_length=1, max_length=120)
    authorized: StrictBool = False
    authorization_ref: str | None = Field(default=None, max_length=200)
    targets: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    allowed_phases: list[Phase] = Field(
        default_factory=lambda: [Phase.RECON, Phase.SCANNING, Phase.VALIDATION]
    )
    capabilities: list[Capability] = Field(default_factory=list)
    max_rps: float = Field(default=5.0, gt=0, le=100, allow_inf_nan=False)
    allow_passive_sources: StrictBool = False
    allowed_wordlists: list[str] = Field(default_factory=list, max_length=50)
    allowed_nuclei_templates: list[str] = Field(default_factory=list, max_length=50)
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
            entry = value.strip()
            if _as_network(entry) is None:
                candidate = entry[2:] if entry.startswith("*.") else entry
                # Scope is host-based: a URL, path or port would imply a restriction
                # that cannot actually be enforced by the matching logic.
                if any(ch in candidate for ch in "/?#@") or (
                    ":" in candidate and not _is_ip_literal(candidate)
                ):
                    raise ValueError("scope entries must be bare hosts, wildcards, or CIDRs")
                try:
                    normalize_host(candidate)
                except ScopeError as exc:
                    raise ValueError(str(exc)) from exc
            cleaned.append(entry)
        return cleaned

    @field_validator("allowed_wordlists", "allowed_nuclei_templates")
    @classmethod
    def _validate_paths(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or "\x00" in value for value in values):
            raise ValueError("allowed local paths must be non-empty")
        return [value.strip() for value in values]

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
                    if network_contains(network, ipaddress.ip_address(host)):
                        return True
                except ValueError:
                    continue
                continue
            entry_host = _entry_host(entry)
            if entry_host is not None and _suffix_match(host, entry):
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
        for entry in self.targets:
            network = _as_network(entry)
            if network is not None:
                try:
                    if network_contains(network, ipaddress.ip_address(host)):
                        return True
                except ValueError:
                    pass
            elif entry.startswith("*."):
                if _suffix_match(host, entry):
                    return True
            elif host == _entry_host(entry):
                return True
        for entry in self.domains:
            network = _as_network(entry)
            if network is not None:
                try:
                    if network_contains(network, ipaddress.ip_address(host)):
                        return True
                except ValueError:
                    pass
            elif _entry_host(entry) is not None and _suffix_match(host, entry):
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

    def allows(self, capability: Capability | str | None) -> bool:
        """Return ``True`` when the engagement grants ``capability``.

        ``None`` means "no special permission required" and is always allowed.
        """
        if capability is None:
            return True
        try:
            wanted = capability if isinstance(capability, Capability) else Capability(capability)
        except ValueError:
            return False
        return wanted in self.capabilities

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
            f"granted_capabilities: {', '.join(c.value for c in self.capabilities) or 'none'}",
            f"max_requests_per_second: {self.max_rps}",
            f"allow_passive_sources: {self.allow_passive_sources}",
            f"allowed_wordlists: {', '.join(self.allowed_wordlists) or 'none'}",
            f"allowed_nuclei_templates: {', '.join(self.allowed_nuclei_templates) or 'none'}",
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
    except json.JSONDecodeError as exc:
        raise ScopeError(f"scope file is not valid JSON: {scope_path}: {exc}") from exc
    except (OSError, UnicodeError) as exc:
        raise ScopeError(f"scope file could not be read: {scope_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScopeError(f"scope file must contain a JSON object: {scope_path}")
    try:
        scope = Scope.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError
        raise ScopeError(f"scope file failed validation: {scope_path}: {exc}") from exc
    scope.assert_runnable()
    return scope


def write_scope(path: str | Path, scope: Scope, *, force: bool = False) -> Path:
    """Write a validated scope to disk without ever overwriting silently."""
    target = Path(path)
    if target.exists() and not force:
        raise ScopeError(f"{target} already exists; edit that file or pass --force to replace it")
    payload = scope.model_dump(mode="json", exclude_none=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def bootstrap_scope(
    *,
    engagement: str,
    targets: Sequence[str],
    domains: Sequence[str] = (),
    exclude: Sequence[str] = (),
    capabilities: Sequence[str | Capability] = (),
    authorization_ref: str | None = None,
    authorized: bool = False,
    expires: date | None = None,
    contact: str | None = None,
    max_rps: float = 5.0,
    allow_passive_sources: bool = False,
    allowed_wordlists: Sequence[str] = (),
    allowed_nuclei_templates: Sequence[str] = (),
    notes: str | None = None,
) -> Scope:
    """Build a validated :class:`Scope` for ``--init-scope``.

    ``authorized`` is only meaningful together with an authorization reference:
    the caller passes both after the operator confirms written authorization.
    Without them the scope is written unauthorized and refuses to run, which is
    the same contract as ``scope.example.json``.
    """
    if authorized and not (authorization_ref or "").strip():
        raise ScopeError(
            "refusing to mark a scope authorized without --authorization-ref: record the "
            "written authorization you are working under"
        )
    try:
        parsed_capabilities = [Capability(item) for item in capabilities]
    except ValueError as exc:
        allowed = ", ".join(capability.value for capability in Capability)
        raise ScopeError(f"unknown capability: {exc}; allowed: {allowed}") from exc
    try:
        scope = Scope(
            engagement=engagement,
            authorized=authorized,
            authorization_ref=authorization_ref,
            targets=list(targets),
            domains=list(domains),
            exclude=list(exclude),
            capabilities=parsed_capabilities,
            max_rps=max_rps,
            allow_passive_sources=allow_passive_sources,
            allowed_wordlists=list(allowed_wordlists),
            allowed_nuclei_templates=list(allowed_nuclei_templates),
            expires=expires,
            contact=contact,
            notes=notes,
        )
    except Exception as exc:  # pydantic.ValidationError
        raise ScopeError(f"invalid scope values: {exc}") from exc
    return scope


__all__ = [
    "Scope",
    "bootstrap_scope",
    "load_scope",
    "network_contains",
    "normalize_host",
    "write_scope",
]
