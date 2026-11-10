"""Proof-only payload generation.

The catalogue defines what a safe proof looks like for each vulnerability class;
:mod:`cyberpowerfull.payloads.engine` turns entries into concrete HTTP requests
that the ``payload`` tool hands to the model. Nothing here touches a target.
"""

from __future__ import annotations

from cyberpowerfull.payloads.engine import (
    DEFAULT_MARKER,
    RenderedPayload,
    audit,
    build_jwt_none,
    catalog,
    generate,
    render_payload,
    resolve_skill,
    select,
    skills,
)
from cyberpowerfull.payloads.library import PAYLOADS
from cyberpowerfull.payloads.models import Payload, SafetyReport

__all__ = [
    "DEFAULT_MARKER",
    "PAYLOADS",
    "Payload",
    "RenderedPayload",
    "SafetyReport",
    "audit",
    "build_jwt_none",
    "catalog",
    "generate",
    "render_payload",
    "resolve_skill",
    "select",
    "skills",
]
