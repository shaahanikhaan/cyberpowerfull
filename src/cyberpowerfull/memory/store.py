"""Deterministic, append-only memory layer (Layer 3 of the brain).

SQLite triggers reject ordinary UPDATE and DELETE statements; someone with
filesystem or schema access can still alter history. The reasoning model receives
a read-only :class:`MemoryView`; the orchestrator records steps and evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from cyberpowerfull.errors import MemoryError_
from cyberpowerfull.memory import SCHEMA_VERSION  # noqa: F401 - re-exported for callers
from cyberpowerfull.models import Finding, Phase, Severity, utcnow

_SCHEMA = """
CREATE TABLE IF NOT EXISTS steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    ts TEXT NOT NULL,
    phase TEXT NOT NULL,
    tool TEXT NOT NULL,
    ok INTEGER NOT NULL,
    reason TEXT,
    args_hash TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    target TEXT NOT NULL,
    endpoint TEXT,
    tool TEXT NOT NULL,
    skill TEXT,
    verified INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    target TEXT NOT NULL,
    ok INTEGER NOT NULL,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_attempts_run_key ON attempts(run_id, tool, args_hash);
CREATE INDEX IF NOT EXISTS idx_steps_run ON steps(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TRIGGER IF NOT EXISTS steps_no_update BEFORE UPDATE ON steps
BEGIN SELECT RAISE(ABORT, 'memory is append-only: steps cannot be updated'); END;

CREATE TRIGGER IF NOT EXISTS steps_no_delete BEFORE DELETE ON steps
BEGIN SELECT RAISE(ABORT, 'memory is append-only: steps cannot be deleted'); END;

CREATE TRIGGER IF NOT EXISTS findings_no_update BEFORE UPDATE ON findings
BEGIN SELECT RAISE(ABORT, 'memory is append-only: findings cannot be updated'); END;

CREATE TRIGGER IF NOT EXISTS findings_no_delete BEFORE DELETE ON findings
BEGIN SELECT RAISE(ABORT, 'memory is append-only: findings cannot be deleted'); END;

CREATE TRIGGER IF NOT EXISTS attempts_no_update BEFORE UPDATE ON attempts
BEGIN SELECT RAISE(ABORT, 'memory is append-only: attempts cannot be updated'); END;

CREATE TRIGGER IF NOT EXISTS attempts_no_delete BEFORE DELETE ON attempts
BEGIN SELECT RAISE(ABORT, 'memory is append-only: attempts cannot be deleted'); END;
"""

_SEVERITY_EVIDENCE_WEIGHT = {
    Severity.INFO: 0.15,
    Severity.LOW: 0.35,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 1.0,
}


def args_hash(tool: str, args: dict[str, Any]) -> str:
    """Stable hash of a tool invocation, used as the negative-cache key."""
    canonical = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


class MemoryStore:
    """Append-only finding / attempt / step store."""

    def __init__(self, path: str | Path = ":memory:", run_id: str = "local") -> None:
        self.path = str(path)
        self.run_id = run_id
        if self.path != ":memory:":
            db_path = Path(self.path)
            db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                fd = os.open(db_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                if db_path.is_symlink() or not db_path.is_file():
                    raise MemoryError_(f"memory path must be a regular file: {db_path}") from None
                os.chmod(db_path, 0o600)
            else:
                os.close(fd)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- writes ------------------------------------------------------------
    def append_step(
        self,
        *,
        step: int,
        phase: Phase,
        tool: str,
        args: dict[str, Any] | None = None,
        ok: bool = True,
        reason: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO steps (run_id, step, ts, phase, tool, ok, reason, args_hash, "
            "payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self.run_id,
                step,
                utcnow().isoformat(),
                phase.value,
                tool,
                int(ok),
                reason,
                args_hash(tool, args or {}),
                json.dumps(payload or {}, default=str),
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    def append_finding(self, finding: Finding) -> int:
        cursor = self._conn.execute(
            "INSERT INTO findings (run_id, finding_id, ts, title, severity, confidence, "
            "target, endpoint, tool, skill, verified, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self.run_id,
                finding.id,
                finding.created_at.isoformat(),
                finding.title,
                finding.severity.value,
                finding.confidence,
                finding.target,
                finding.endpoint,
                finding.tool,
                finding.skill,
                int(finding.verified),
                finding.model_dump_json(),
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    def record_attempt(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        target: str,
        ok: bool,
        error: str | None = None,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO attempts (run_id, ts, tool, args_hash, target, ok, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                self.run_id,
                utcnow().isoformat(),
                tool,
                args_hash(tool, args),
                target,
                int(ok),
                error,
            ),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    # -- reads -------------------------------------------------------------
    def findings(self) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT payload_json FROM findings WHERE run_id = ? ORDER BY id ASC",
            (self.run_id,),
        ).fetchall()
        findings: list[Finding] = []
        for row in rows:
            try:
                findings.append(Finding.model_validate_json(row["payload_json"]))
            except Exception:
                continue
        return findings

    def steps(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT step, ts, phase, tool, ok, reason, args_hash FROM steps "
            "WHERE run_id = ? ORDER BY id ASC",
            (self.run_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def negative_cache_hit(self, tool: str, args: dict[str, Any]) -> str | None:
        """Return the last failure message for this exact invocation, if any."""
        key = args_hash(tool, args)
        row = self._conn.execute(
            "SELECT ok, error FROM attempts WHERE run_id = ? AND tool = ? AND args_hash = ? "
            "ORDER BY id DESC LIMIT 1",
            (self.run_id, tool, key),
        ).fetchone()
        if row is None or row["ok"]:
            return None
        return str(row["error"] or "previous attempt failed")

    def consecutive_failures(self, tool: str, args: dict[str, Any], limit: int = 2) -> int:
        """Count recent consecutive failures for this invocation in the current run."""
        rows = self._conn.execute(
            "SELECT ok FROM attempts WHERE run_id = ? AND tool = ? AND args_hash = ? "
            "ORDER BY id DESC LIMIT ?",
            (self.run_id, tool, args_hash(tool, args), limit),
        ).fetchall()
        failures = 0
        for row in rows:
            if row["ok"]:
                break
            failures += 1
        return failures

    def success_rate(self, tool: str | None = None) -> float:
        """Historical success rate, used by TDA. Zero attempts -> 0.0."""
        if tool:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total, SUM(ok) AS wins FROM attempts "
                "WHERE run_id = ? AND tool = ?",
                (self.run_id, tool),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total, SUM(ok) AS wins FROM attempts WHERE run_id = ?",
                (self.run_id,),
            ).fetchone()
        total = int(row["total"] or 0)
        if total == 0:
            return 0.0
        return round(float(row["wins"] or 0) / total, 4)

    def evidence_confidence(self) -> float:
        """Aggregate strength of collected evidence, saturating at 1.0."""
        findings = self.findings()
        if not findings:
            return 0.0
        weights = [
            _SEVERITY_EVIDENCE_WEIGHT[finding.severity] * (1.0 if finding.verified else 0.75)
            for finding in findings
        ]
        mean = sum(weights) / len(weights)
        return round(min(1.0, mean + 0.03 * min(len(weights), 10)), 4)

    def highest_severity(self) -> Severity:
        findings = self.findings()
        if not findings:
            return Severity.INFO
        return max((finding.severity for finding in findings), key=lambda sev: sev.rank)

    def digest(self, max_rows: int = 8) -> str:
        """Compact, read-only snapshot injected into the system prompt."""
        findings = self.findings()
        lines = [
            f"findings_total: {len(findings)}",
            f"highest_severity: {self.highest_severity().value}",
            f"evidence_confidence: {self.evidence_confidence():.2f}",
            f"historical_success: {self.success_rate():.2f}",
        ]
        if findings:
            lines.append("recent_findings:")
            for finding in findings[-max_rows:]:
                lines.append(
                    f"  - [{finding.severity.value}] {finding.title} "
                    f"tool={finding.tool} verified={finding.verified} id={finding.id}"
                )
        failures = self._conn.execute(
            "SELECT tool, COUNT(*) AS n FROM attempts WHERE run_id = ? AND ok = 0 "
            "GROUP BY tool ORDER BY n DESC",
            (self.run_id,),
        ).fetchall()
        if failures:
            lines.append("failed_attempts_by_tool:")
            for row in failures[:max_rows]:
                lines.append(f"  - {row['tool']}: {row['n']}")
        return "\n".join(lines)

    def stats(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "steps": self._count("steps"),
            "findings": self._count("findings"),
            "attempts": self._count("attempts"),
            "success_rate": self.success_rate(),
            "evidence_confidence": self.evidence_confidence(),
        }

    def _count(self, table: str) -> int:
        # Only fixed internal table names are passed here.
        row = self._conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE run_id = ?", (self.run_id,)
        ).fetchone()
        return int(row[0])

    def view(self) -> MemoryView:
        """Read-only projection handed to the prompt builder."""
        return MemoryView(self)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> MemoryStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class MemoryView:
    """Read-only memory facade. The reasoning layer cannot write through this."""

    __slots__ = ("_store",)

    def __init__(self, store: MemoryStore) -> None:
        object.__setattr__(self, "_store", store)

    def __setattr__(self, name: str, value: object) -> None:  # pragma: no cover - guard
        raise AttributeError("MemoryView is read-only")

    def findings(self) -> list[Finding]:
        return self._store.findings()

    def digest(self, max_rows: int = 8) -> str:
        return self._store.digest(max_rows)

    def success_rate(self, tool: str | None = None) -> float:
        return self._store.success_rate(tool)

    def evidence_confidence(self) -> float:
        return self._store.evidence_confidence()

    def negative_cache_hit(self, tool: str, args: dict[str, Any]) -> str | None:
        return self._store.negative_cache_hit(tool, args)

    def highest_severity(self) -> Severity:
        return self._store.highest_severity()

    def stats(self) -> dict[str, Any]:
        return self._store.stats()


__all__ = ["MemoryStore", "MemoryView", "args_hash"]
