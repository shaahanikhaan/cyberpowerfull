"""Exception hierarchy and process exit codes.

Exit codes are part of the CLI contract and are documented in README.md.
"""

from __future__ import annotations


class CyberpowerfullError(Exception):
    """Base class for every error raised by this project."""

    exit_code: int = 1


class ScopeError(CyberpowerfullError):
    """The engagement scope is missing, malformed, or not runnable."""

    exit_code = 3


class ScopeViolation(ScopeError):
    """A requested action falls outside the authorized engagement scope."""

    exit_code = 4


class InvalidToolArguments(CyberpowerfullError):
    """Tool arguments failed Pydantic validation."""

    exit_code = 6


class ToolError(CyberpowerfullError):
    """A tool wrapper failed in a way the agent cannot recover from."""

    exit_code = 6


class ToolNotFound(ToolError):
    """The requested tool is not registered."""


class LLMError(CyberpowerfullError):
    """Local inference failed, was unreachable, or returned unusable output."""

    exit_code = 5


class PolicyViolation(CyberpowerfullError):
    """The reasoning model attempted an action forbidden to its role."""

    exit_code = 7


class BudgetExhausted(CyberpowerfullError):
    """The iteration, token, or wall-clock budget is exhausted."""

    exit_code = 0


class MemoryError_(CyberpowerfullError):
    """Deterministic memory layer failure (append-only invariant broken)."""


__all__ = [
    "BudgetExhausted",
    "CyberpowerfullError",
    "InvalidToolArguments",
    "LLMError",
    "MemoryError_",
    "PolicyViolation",
    "ScopeError",
    "ScopeViolation",
    "ToolError",
    "ToolNotFound",
]
