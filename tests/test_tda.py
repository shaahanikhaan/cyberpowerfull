"""Task Difficulty Assessment tests: measurability and monotonic behaviour."""

from __future__ import annotations

import pytest

from cyberpowerfull.brain.tda import (
    WEIGHTS,
    DifficultyLevel,
    TaskDifficultyAssessor,
    TDAInput,
)


@pytest.fixture
def assessor() -> TaskDifficultyAssessor:
    return TaskDifficultyAssessor()


def test_weights_sum_to_one() -> None:
    assert pytest.approx(sum(WEIGHTS.values()), abs=1e-9) == 1.0


def test_easy_conditions_are_low_difficulty(assessor: TaskDifficultyAssessor) -> None:
    report = assessor.assess(
        TDAInput(iteration=0, max_iterations=20, evidence_confidence=1.0, historical_success=1.0)
    )
    assert report.level is DifficultyLevel.LOW
    assert report.difficulty < 0.35
    assert report.max_depth == 4


def test_hard_conditions_are_critical(assessor: TaskDifficultyAssessor) -> None:
    report = assessor.assess(
        TDAInput(
            iteration=12,
            max_iterations=12,
            evidence_confidence=0.0,
            tokens_used=32000,
            context_window=32768,
            historical_success=0.0,
            failed_attempts=5,
        )
    )
    assert report.level is DifficultyLevel.CRITICAL
    assert report.max_depth == 1
    assert report.expansion_threshold > 0.6


def test_horizon_increases_monotonically(assessor: TaskDifficultyAssessor) -> None:
    early = assessor.assess(TDAInput(iteration=1, max_iterations=10))
    late = assessor.assess(TDAInput(iteration=9, max_iterations=10))
    assert late.horizon > early.horizon
    assert late.difficulty > early.difficulty


def test_evidence_lowers_difficulty(assessor: TaskDifficultyAssessor) -> None:
    without = assessor.assess(TDAInput(evidence_confidence=0.0))
    with_evidence = assessor.assess(TDAInput(evidence_confidence=1.0))
    assert with_evidence.difficulty < without.difficulty


def test_context_load_dimension(assessor: TaskDifficultyAssessor) -> None:
    report = assessor.assess(TDAInput(tokens_used=16384, context_window=32768))
    assert report.context_load == pytest.approx(0.5)


def test_context_window_guard(assessor: TaskDifficultyAssessor) -> None:
    report = assessor.assess(TDAInput(tokens_used=999999, context_window=1000))
    assert report.context_load == 1.0


def test_historical_success_dimension(assessor: TaskDifficultyAssessor) -> None:
    report = assessor.assess(TDAInput(historical_success=0.75))
    assert report.historical_success == pytest.approx(0.75)


def test_rationale_is_measurable(assessor: TaskDifficultyAssessor) -> None:
    report = assessor.assess(TDAInput(iteration=3, max_iterations=10, evidence_count=2))
    joined = " ".join(report.rationale)
    assert "horizon=" in joined
    assert "evidence_confidence=" in joined
    assert "context_load=" in joined
    assert "historical_success=" in joined
    assert "2 finding(s)" in joined


def test_failure_directive(assessor: TaskDifficultyAssessor) -> None:
    report = assessor.assess(TDAInput(failed_attempts=3))
    assert any("prune" in line for line in report.rationale)


@pytest.mark.parametrize(
    ("difficulty_input", "expected_level"),
    [
        (
            TDAInput(
                iteration=0, max_iterations=100, evidence_confidence=1.0, historical_success=1.0
            ),
            "low",
        ),
        (TDAInput(iteration=50, max_iterations=100, evidence_confidence=0.5), "medium"),
    ],
)
def test_level_thresholds(assessor, difficulty_input, expected_level) -> None:
    report = assessor.assess(difficulty_input)
    assert report.level.value == expected_level


def test_as_context_serialisable(assessor: TaskDifficultyAssessor) -> None:
    context = assessor.assess(TDAInput()).as_context()
    assert set(context) >= {
        "horizon",
        "evidence_confidence",
        "context_load",
        "historical_success",
        "difficulty",
        "level",
        "expansion_threshold",
        "max_depth",
    }
    assert isinstance(context["level"], str)


def test_directive_is_imperative(assessor: TaskDifficultyAssessor) -> None:
    report = assessor.assess(TDAInput(iteration=20, max_iterations=20, tokens_used=30000))
    assert report.directive.startswith("difficulty=")
