"""Shared Jinja2 environment.

Templates live inside the package so they ship with the wheel. ``StrictUndefined``
guarantees that a missing context key fails loudly instead of silently rendering
an incomplete behavioural contract.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

PACKAGE_ROOT = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def get_environment() -> Environment:
    """Return the cached, sandbox-free Jinja2 environment."""
    return Environment(
        loader=FileSystemLoader(str(PACKAGE_ROOT)),
        undefined=StrictUndefined,
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


__all__ = ["PACKAGE_ROOT", "get_environment"]
