"""EGATS attack tree tests: selection gating, evidence, pruning, exhaustion."""

from __future__ import annotations

import pytest

from cyberpowerfull.brain.attack_tree import (
    AttackTree,
    ExpansionProposal,
    NodeStatus,
)
from cyberpowerfull.brain.tda import DifficultyLevel, TDAReport
from cyberpowerfull.models import Finding, Severity


def tda(
    level: DifficultyLevel = DifficultyLevel.LOW, threshold: float = 0.3, depth: int = 4
) -> TDAReport:
    return TDAReport(
        horizon=0.1,
        evidence_confidence=0.2,
        context_load=0.1,
        historical_success=0.5,
        difficulty=0.4,
        level=level,
        expansion_threshold=threshold,
        max_depth=depth,
    )


def finding(severity: Severity = Severity.HIGH, verified: bool = True) -> Finding:
    return Finding(
        title=f"{severity.value} finding",
        severity=severity,
        target="127.0.0.1",
        tool="nuclei",
        verified=verified,
    )


@pytest.fixture
def tree() -> AttackTree:
    return AttackTree(target="127.0.0.1")


def test_root_exists(tree: AttackTree) -> None:
    root = tree.get(tree.root_id)
    assert root.depth == 0
    assert root.status is NodeStatus.OPEN
    assert "127.0.0.1" in root.hypothesis


def test_add_and_expand(tree: AttackTree) -> None:
    tree.add(hypothesis="Test IDOR on /api/users/1", skill="idor", parent=tree.root_id)
    assert len(tree) == 2
    children = tree.expand(
        tree.root_id,
        [ExpansionProposal(hypothesis="Probe admin panel", skill="information_disclosure")],
        max_depth=3,
    )
    assert children
    assert tree.get(children[0]).parent == tree.root_id
    assert tree.get(tree.root_id).status is NodeStatus.EXPANDED


def test_expansion_respects_depth(tree: AttackTree) -> None:
    tree.add(hypothesis="depth one", parent=tree.root_id)
    node = tree.open_nodes()[0]
    added = tree.expand(node.id, [ExpansionProposal(hypothesis="too deep")], max_depth=0)
    assert added == []


def test_node_limit(tree: AttackTree) -> None:
    small = AttackTree(target="127.0.0.1", max_nodes=2)
    small.add(hypothesis="one", parent=small.root_id)
    with pytest.raises(ValueError):
        small.add(hypothesis="two", parent=small.root_id)


def test_select_picks_highest_score(tree: AttackTree) -> None:
    tree.add(hypothesis="low prior", prior=0.1, parent=tree.root_id)
    strong = tree.add(hypothesis="high prior", prior=0.9, parent=tree.root_id)
    assert tree.select(tda()).id == strong.id


def test_high_difficulty_gate_blocks_low_value(tree: AttackTree) -> None:
    tree.add(hypothesis="weak branch", prior=0.1, parent=tree.root_id)
    assert tree.select(tda(DifficultyLevel.HIGH, threshold=0.9)) is None
    assert tree.select(tda(DifficultyLevel.LOW, threshold=0.9)) is not None


def test_prune_low_value_keeps_root(tree: AttackTree) -> None:
    tree.add(hypothesis="weak branch", prior=0.1, parent=tree.root_id)
    pruned = tree.prune_low_value(tda(DifficultyLevel.HIGH, threshold=0.9))
    assert pruned == ["n2"]
    assert tree.get(tree.root_id).status is NodeStatus.OPEN


def test_enforce_depth(tree: AttackTree) -> None:
    child = tree.add(hypothesis="depth one", parent=tree.root_id)
    grandchild = tree.add(hypothesis="depth two", parent=child.id)
    assert tree.enforce_depth(1) == [grandchild.id]
    assert tree.get(grandchild.id).status is NodeStatus.PRUNED


def test_apply_result_failure_prunes_after_two(tree: AttackTree) -> None:
    node = tree.add(hypothesis="failing branch", parent=tree.root_id)
    tree.apply_result(node.id, ok=False, findings=[])
    assert node.attempts == 1
    assert node.failures == 1
    assert node.status is NodeStatus.OPEN
    tree.apply_result(node.id, ok=False, findings=[])
    assert node.status is NodeStatus.PRUNED


def test_apply_result_confirms_strong_finding(tree: AttackTree) -> None:
    node = tree.add(hypothesis="sqli branch", skill="sql_injection", parent=tree.root_id)
    tree.apply_result(node.id, ok=True, findings=[finding(Severity.HIGH)])
    assert node.status is NodeStatus.CONFIRMED
    assert "confirmed by nuclei" in (node.note or "")
    assert tree.confirmed() == [node]


def test_weak_evidence_keeps_hypothesis_alive(tree: AttackTree) -> None:
    node = tree.add(hypothesis="weak branch", skill="xss", parent=tree.root_id)
    tree.apply_result(node.id, ok=True, findings=[finding(Severity.MEDIUM, verified=False)])
    assert node.status is NodeStatus.OPEN
    assert node.evidence_weight > 0
    assert "no confirmation" in (node.note or "")


def test_attempt_budget_limits_reselection(tree: AttackTree) -> None:
    node = tree.add(hypothesis="repeated branch", parent=tree.root_id)
    tree.apply_result(node.id, ok=True, findings=[])
    assert node.status is NodeStatus.EXHAUSTED
    assert not tree._selectable(node)
    open_node = tree.add(hypothesis="open branch", parent=tree.root_id)
    tree.apply_result(open_node.id, ok=True, findings=[finding(Severity.LOW, verified=False)])
    assert tree._selectable(open_node)
    tree.apply_result(open_node.id, ok=True, findings=[finding(Severity.LOW, verified=False)])
    assert not tree._selectable(open_node)


def test_evidence_boost_by_skill(tree: AttackTree) -> None:
    node = tree.add(hypothesis="idor branch", skill="idor", parent=tree.root_id)
    tree.apply_evidence("idor", 0.2)
    assert node.evidence_weight == pytest.approx(0.2)


def test_exhaustion(tree: AttackTree) -> None:
    assert not tree.is_exhausted()
    tree.apply_result(tree.root_id, ok=True, findings=[])
    assert tree.is_exhausted()
    assert tree.select(tda()) is None


def test_best_path(tree: AttackTree) -> None:
    child = tree.add(hypothesis="child", skill="sql_injection", parent=tree.root_id)
    tree.apply_result(child.id, ok=True, findings=[finding(Severity.CRITICAL)])
    path = tree.best_path()
    assert [node.id for node in path] == [tree.root_id, child.id]
    assert tree.best_path(tree.root_id) == [tree.get(tree.root_id)]


def test_digest_is_readable(tree: AttackTree) -> None:
    digest = tree.digest()
    assert "tree_stats:" in digest
    assert tree.root_id in digest
    assert "target" not in digest


def test_stats_counts(tree: AttackTree) -> None:
    stats = tree.stats()
    assert stats["total"] == 1
    assert stats["open"] == 1


def test_apply_result_unknown_node_is_noop(tree: AttackTree) -> None:
    tree.apply_result("n999", ok=True, findings=[])
    assert len(tree) == 1
