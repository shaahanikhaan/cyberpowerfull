"""Version parsing and comparison for advisory range matching.

Deliberately dependency-free and deterministic: versions are tokenised into
numeric, pre-release and alphabetic runs, so ``2.4.49``, ``9.6p1``, ``1.0.2k``
and ``2.0-beta9`` all compare sensibly for the purpose of range membership.
"""

from __future__ import annotations

import re

_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

#: Words that mark a pre-release, which sorts *before* the release it precedes.
_PRE_RELEASE = frozenset(
    {"alpha", "beta", "rc", "pre", "preview", "snapshot", "dev", "milestone", "nightly"}
)


def version_key(value: str) -> tuple[tuple[int, object], ...]:
    """Return a comparable key for a version string."""
    cleaned = (value or "").strip()
    if cleaned.startswith("v") and cleaned[1:2].isdigit():
        cleaned = cleaned[1:]
    tokens: list[tuple[int, object]] = []
    for token in _TOKEN_RE.findall(cleaned):
        if token.isdigit():
            tokens.append((2, int(token)))
        elif token.lower() in _PRE_RELEASE:
            tokens.append((0, token.lower()))
        else:
            tokens.append((1, token.lower()))
    return tuple(tokens)


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 for ``left`` vs ``right``."""
    left_key = version_key(left)
    right_key = version_key(right)
    size = min(len(left_key), len(right_key))
    for index in range(size):
        if left_key[index] == right_key[index]:
            continue
        return -1 if left_key[index] < right_key[index] else 1
    if len(left_key) == len(right_key):
        return 0
    # A pre-release suffix sorts *before* the plain release it precedes:
    # ``1.0-rc1 < 1.0`` and ``2.0-beta9 < 2.0.0``.
    longer = left_key if len(left_key) > len(right_key) else right_key
    if longer[size][0] == 0:
        return -1 if longer is left_key else 1
    return -1 if len(left_key) < len(right_key) else 1


def normalize_product(value: str) -> str:
    """Normalise a vendor/product string for comparison."""
    return _NON_ALNUM.sub("", (value or "").lower())


def version_in_range(
    version: str | None,
    spec: object | None = None,
    *,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
    exact: str | None = None,
) -> bool:
    """Return whether ``version`` falls inside an advisory range.

    ``introduced`` is inclusive, ``fixed`` is exclusive, ``last_affected`` is
    inclusive, and ``exact`` demands equality. A ``None`` version cannot be
    ranged and returns ``False`` — the caller decides how to treat unversioned
    components.

    ``spec`` is any object exposing ``introduced``/``fixed``/``last_affected``/
    ``exact`` attributes (typically a ``VersionRange``); explicit keywords win.
    """
    if spec is not None:
        introduced = introduced if introduced is not None else getattr(spec, "introduced", None)
        fixed = fixed if fixed is not None else getattr(spec, "fixed", None)
        last_affected = (
            last_affected if last_affected is not None else getattr(spec, "last_affected", None)
        )
        exact = exact if exact is not None else getattr(spec, "exact", None)
    if version is None or not version.strip():
        return False
    candidate = version.strip()
    if exact is not None:
        return compare_versions(candidate, exact) == 0
    if introduced is not None and compare_versions(candidate, introduced) < 0:
        return False
    if fixed is not None and compare_versions(candidate, fixed) >= 0:
        return False
    return not (last_affected is not None and compare_versions(candidate, last_affected) > 0)


__all__ = [
    "compare_versions",
    "normalize_product",
    "version_in_range",
    "version_key",
]
