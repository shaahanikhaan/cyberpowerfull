"""Task Difficulty Assessment (TDA).

Four measurable dimensions drive every planning decision:

``horizon``             fraction of the step budget already consumed
``evidence_confidence`` strength of the collected evidence (0-1)
``context_load``        fraction of the context window consumed
``historical_success``  past success rate on similar tasks, from memory

The composite score gates attack-tree expansion: when difficulty is high the
agent raises its acceptance threshold and prunes low-value branches instead of
over-committing to them.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class DifficultyLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Weights sum to 1.0 so ``difficulty`` is always in [0, 1].
WEIGHTS = {
    "horizon": 0.35,
    "evidence_gap": 0.30,
    "context_load": 0.20,
    "success_gap": 0.15,
}

_MAX_DEPTH_BY_LEVEL = {
    DifficultyLevel.LOW: 4,
    DifficultyLevel.MEDIUM: 3,
    DifficultyLevel.HIGH: 2,
    DifficultyLevel.CRITICAL: 1,
}

_DIRECTIVE_BY_LEVEL = {
    DifficultyLevel.LOW: (
        "difficulty=low: expand selectively; prefer verification of existing evidence over "
        "new discovery."
    ),
    DifficultyLevel.MEDIUM: (
        "difficulty=medium: balance discovery and validation; expand only nodes with score "
        "above the threshold."
    ),
    DifficultyLevel.HIGH: (
        "difficulty=high: do not over-commit; prune low-value branches, re-test the highest "
        "expected-value node, and consolidate evidence."
    ),
    DifficultyLevel.CRITICAL: (
        "difficulty=critical: stop expanding the tree; validate one existing hypothesis, then "
        "move to reporting."
    ),
}


class TDAInput(BaseModel):
    """Deterministic inputs for one assessment."""

    iteration: int = Field(default=0, ge=0)
    max_iterations: int = Field(default=12, ge=1)
    evidence_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_count: int = Field(default=0, ge=0)
    tokens_used: int = Field(default=0, ge=0)
    context_window: int = Field(default=32768, ge=1)
    historical_success: float = Field(default=0.0, ge=0.0, le=1.0)
    open_nodes: int = Field(default=1, ge=0)
    failed_attempts: int = Field(default=0, ge=0)


class TDAReport(BaseModel):
    """Result of a TDA pass, embedded in every trace step and the system prompt."""

    horizon: float = Field(ge=0.0, le=1.0)
    evidence_confidence: float = Field(ge=0.0, le=1.0)
    context_load: float = Field(ge=0.0, le=1.0)
    historical_success: float = Field(ge=0.0, le=1.0)
    difficulty: float = Field(ge=0.0, le=1.0)
    level: DifficultyLevel
    expansion_threshold: float = Field(ge=0.0, le=1.0)
    max_depth: int = Field(ge=0)
    rationale: list[str] = Field(default_factory=list)

    @property
    def directive(self) -> str:
        return _DIRECTIVE_BY_LEVEL[self.level]

    def as_context(self) -> dict[str, object]:
        return {
            "horizon": round(self.horizon, 3),
            "evidence_confidence": round(self.evidence_confidence, 3),
            "context_load": round(self.context_load, 3),
            "historical_success": round(self.historical_success, 3),
            "difficulty": round(self.difficulty, 3),
            "level": self.level.value,
            "expansion_threshold": round(self.expansion_threshold, 3),
            "max_depth": self.max_depth,
            "rationale": self.rationale,
        }


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


class TaskDifficultyAssessor:
    """Pure, deterministic TDA implementation (no model, no randomness)."""

    def assess(self, data: TDAInput) -> TDAReport:
        horizon = _clamp(data.iteration / max(data.max_iterations, 1))
        context_load = _clamp(data.tokens_used / max(data.context_window, 1))
        evidence = _clamp(data.evidence_confidence)
        success = _clamp(data.historical_success)

        difficulty = _clamp(
            WEIGHTS["horizon"] * horizon
            + WEIGHTS["evidence_gap"] * (1.0 - evidence)
            + WEIGHTS["context_load"] * context_load
            + WEIGHTS["success_gap"] * (1.0 - success)
        )
        level = self._level(difficulty)
        rationale = [
            f"horizon={horizon:.2f} (step {data.iteration}/{data.max_iterations})",
            f"evidence_confidence={evidence:.2f} from {data.evidence_count} finding(s)",
            f"context_load={context_load:.2f} ({data.tokens_used}/{data.context_window} tokens)",
            f"historical_success={success:.2f} over recorded attempts",
            f"open_attack_nodes={data.open_nodes}, failed_attempts={data.failed_attempts}",
        ]
        if data.failed_attempts >= 3:
            rationale.append("repeated failures detected; raise threshold and prune")
        return TDAReport(
            horizon=round(horizon, 4),
            evidence_confidence=round(evidence, 4),
            context_load=round(context_load, 4),
            historical_success=round(success, 4),
            difficulty=round(difficulty, 4),
            level=level,
            expansion_threshold=round(_clamp(0.35 + 0.5 * difficulty), 4),
            max_depth=_MAX_DEPTH_BY_LEVEL[level],
            rationale=rationale,
        )

    @staticmethod
    def _level(difficulty: float) -> DifficultyLevel:
        if difficulty < 0.35:
            return DifficultyLevel.LOW
        if difficulty < 0.55:
            return DifficultyLevel.MEDIUM
        if difficulty < 0.75:
            return DifficultyLevel.HIGH
        return DifficultyLevel.CRITICAL


__all__ = [
    "WEIGHTS",
    "DifficultyLevel",
    "TDAInput",
    "TDAReport",
    "TaskDifficultyAssessor",
]
