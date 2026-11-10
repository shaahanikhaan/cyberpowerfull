"""Structured JSON traces: every step, tool call, and finding, replayable.

A trace is the audit artefact of a run. ``--replay traces/latest.json`` renders a
recorded run without touching a tool or a model, which is how findings are
reviewed after the engagement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyberpowerfull import AGENT_NAME, __version__
from cyberpowerfull.models import (
    BudgetState,
    Finding,
    Phase,
    Severity,
    new_id,
    utcnow,
)
from cyberpowerfull.storage import write_private_text

TRACE_SCHEMA_VERSION = "1.0"


class StepRecord(BaseModel):
    """One reasoning step: the decision, the tool call, and the parsed result."""

    model_config = ConfigDict(extra="forbid")

    index: int
    role: str = "root"
    action: str
    phase: Phase = Phase.RECON
    tool: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    thought: str | None = None
    node: str | None = None
    tda: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    finding_ids: list[str] = Field(default_factory=list)
    started_at: str = Field(default_factory=lambda: utcnow().isoformat())
    duration_ms: int = 0
    error: str | None = None


class Trace(BaseModel):
    """Complete, self-describing record of one agent run."""

    schema_version: str = TRACE_SCHEMA_VERSION
    agent: str = AGENT_NAME
    agent_version: str = __version__
    run_id: str = Field(
        default_factory=lambda: new_id("run-"),
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
    model: str = "unknown"
    backend: str = "unknown"
    engagement: str = "unknown"
    target: str = "unknown"
    scope_fingerprint: str = ""
    started_at: str = Field(default_factory=lambda: utcnow().isoformat())
    finished_at: str | None = None
    stop_reason: str | None = None
    error: str | None = None
    budget: BudgetState = Field(default_factory=BudgetState)
    steps: list[StepRecord] = Field(default_factory=list)
    #: Steps that were considered but not executed, each with its real reason
    #: (missing binary, unpermitted phase, ungranted capability, negative cache).
    skipped: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    attack_tree: dict[str, Any] = Field(default_factory=dict)
    memory_stats: dict[str, Any] = Field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda finding: (finding.severity.rank, finding.confidence),
            reverse=True,
        )


class TraceRecorder:
    """Mutable builder that produces an immutable :class:`Trace`."""

    def __init__(
        self,
        *,
        target: str,
        engagement: str,
        model: str,
        backend: str,
        scope_fingerprint: str,
        run_id: str | None = None,
    ) -> None:
        self._trace = Trace(
            run_id=run_id or new_id("run-"),
            target=target,
            engagement=engagement,
            model=model,
            backend=backend,
            scope_fingerprint=scope_fingerprint,
        )

    @property
    def trace(self) -> Trace:
        return self._trace

    @property
    def findings(self) -> list[Finding]:
        return list(self._trace.findings)

    def add_step(self, record: StepRecord) -> StepRecord:
        self._trace.steps.append(record)
        return record

    def add_findings(self, findings: list[Finding]) -> None:
        known = {finding.id for finding in self._trace.findings}
        for finding in findings:
            if finding.id not in known:
                self._trace.findings.append(finding)
                known.add(finding.id)

    def set_budget(self, budget: BudgetState) -> None:
        self._trace.budget = budget

    def finish(
        self,
        *,
        stop_reason: str,
        error: str | None = None,
        tree: dict[str, Any] | None = None,
        memory_stats: dict[str, Any] | None = None,
    ) -> Trace:
        self._trace.stop_reason = stop_reason
        self._trace.error = error
        self._trace.finished_at = utcnow().isoformat()
        if tree is not None:
            self._trace.attack_tree = tree
        if memory_stats is not None:
            self._trace.memory_stats = memory_stats
        return self._trace

    def save(self, path: str | Path) -> Path:
        return write_private_text(path, self._trace.model_dump_json(indent=2))


def save_trace(trace: Trace, path: str | Path) -> Path:
    return write_private_text(path, trace.model_dump_json(indent=2))


def load_trace(path: str | Path) -> Trace:
    """Load a recorded trace for replay or review."""
    from cyberpowerfull.errors import CyberpowerfullError

    trace_path = Path(path)
    if not trace_path.exists():
        raise CyberpowerfullError(f"trace not found: {trace_path}")
    try:
        payload = json.loads(trace_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CyberpowerfullError(f"trace is not valid JSON: {trace_path}: {exc}") from exc
    except (OSError, UnicodeError) as exc:
        raise CyberpowerfullError(f"trace could not be read: {trace_path}: {exc}") from exc
    try:
        trace = Trace.model_validate(payload)
    except Exception as exc:
        raise CyberpowerfullError(f"trace failed validation: {trace_path}: {exc}") from exc
    if trace.schema_version != TRACE_SCHEMA_VERSION:
        raise CyberpowerfullError(f"unsupported trace schema version: {trace.schema_version}")
    return trace


def summarize_trace(trace: Trace) -> dict[str, Any]:
    """Compact machine-readable summary used by the CLI and reports."""
    return {
        "run_id": trace.run_id,
        "target": trace.target,
        "engagement": trace.engagement,
        "stop_reason": trace.stop_reason,
        "steps": len(trace.steps),
        "tool_calls": sum(1 for step in trace.steps if step.tool),
        "findings": len(trace.findings),
        "severity_counts": trace.severity_counts(),
        "verified_findings": sum(1 for finding in trace.findings if finding.verified),
        "model": trace.model,
        "backend": trace.backend,
        "started_at": trace.started_at,
        "finished_at": trace.finished_at,
    }


__all__ = [
    "TRACE_SCHEMA_VERSION",
    "StepRecord",
    "Trace",
    "TraceRecorder",
    "load_trace",
    "save_trace",
    "summarize_trace",
]
