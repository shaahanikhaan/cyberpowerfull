"""Evidence-Guided Attack Tree Search (EGATS).

Nodes are hypotheses. The tree is deterministic state: only the orchestrator
mutates it, and only from tool results and model-proposed expansions. Selection
is score-based and TDA-gated, so a high-difficulty run stops expanding
low-value branches instead of over-committing to them.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from cyberpowerfull.brain.tda import TDAReport
from cyberpowerfull.models import Finding, Phase, Severity


class NodeStatus(str, Enum):
    OPEN = "open"
    EXPANDED = "expanded"
    CONFIRMED = "confirmed"
    PRUNED = "pruned"
    EXHAUSTED = "exhausted"


class AttackNode(BaseModel):
    """One hypothesis in the attack tree."""

    id: str
    hypothesis: str = Field(min_length=3, max_length=400)
    phase: Phase = Phase.RECON
    skill: str | None = None
    prior: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_weight: float = Field(default=0.0, ge=0.0, le=1.0)
    attempts: int = Field(default=0, ge=0)
    failures: int = Field(default=0, ge=0)
    status: NodeStatus = NodeStatus.OPEN
    parent: str | None = None
    depth: int = Field(default=0, ge=0)
    children: list[str] = Field(default_factory=list)
    note: str | None = None

    @property
    def score(self) -> float:
        """Expected value of investigating this node, in [0, 1]."""
        raw = self.prior * (1.0 + 0.5 * self.evidence_weight) - 0.15 * self.failures
        return round(max(0.0, min(1.0, raw)), 4)

    def summary(self) -> str:
        skill = f" skill={self.skill}" if self.skill else ""
        return (
            f"{self.id} [{self.status.value}] phase={self.phase.value}{skill} "
            f"score={self.score:.2f} attempts={self.attempts} :: {self.hypothesis}"
        )


class ExpansionProposal(BaseModel):
    """Model-proposed child hypothesis, validated before insertion."""

    hypothesis: str = Field(min_length=3, max_length=400)
    skill: str | None = None
    phase: Phase | None = None
    prior: float = Field(default=0.5, ge=0.0, le=1.0)


#: A node may be revisited this many times before it stops being selectable.
MAX_NODE_ATTEMPTS = 2


class AttackTree:
    """Deterministic attack-tree state machine."""

    def __init__(self, target: str, max_nodes: int = 64) -> None:
        self.target = target
        self.max_nodes = max_nodes
        self._nodes: dict[str, AttackNode] = {}
        self._counter = 0
        root = self.add(
            hypothesis=f"Map the reachable attack surface of {target}",
            phase=Phase.RECON,
            skill="information_disclosure",
            prior=0.85,
        )
        self.root_id = root.id

    # -- basic accessors ---------------------------------------------------
    def __len__(self) -> int:
        return len(self._nodes)

    def get(self, node_id: str) -> AttackNode:
        return self._nodes[node_id]

    def has(self, node_id: str) -> bool:
        return node_id in self._nodes

    def nodes(self) -> list[AttackNode]:
        return list(self._nodes.values())

    def open_nodes(self) -> list[AttackNode]:
        return [node for node in self._nodes.values() if node.status is NodeStatus.OPEN]

    def _selectable(self, node: AttackNode) -> bool:
        """Open and confirmed-leaf nodes are selectable while attempts remain."""
        if node.attempts >= MAX_NODE_ATTEMPTS:
            return False
        if node.status is NodeStatus.OPEN:
            return True
        return node.status is NodeStatus.CONFIRMED and not node.children

    def selectable_nodes(self) -> list[AttackNode]:
        return [node for node in self._nodes.values() if self._selectable(node)]

    # -- construction ------------------------------------------------------
    def add(
        self,
        *,
        hypothesis: str,
        phase: Phase = Phase.RECON,
        skill: str | None = None,
        prior: float = 0.5,
        parent: str | None = None,
    ) -> AttackNode:
        if len(self._nodes) >= self.max_nodes:
            raise ValueError(f"attack tree node limit reached ({self.max_nodes})")
        parent_node = self._nodes.get(parent) if parent else None
        depth = (parent_node.depth + 1) if parent_node else 0
        self._counter += 1
        node = AttackNode(
            id=f"n{self._counter}",
            hypothesis=hypothesis,
            phase=phase,
            skill=skill,
            prior=prior,
            parent=parent,
            depth=depth,
        )
        self._nodes[node.id] = node
        if parent_node is not None and node.id not in parent_node.children:
            parent_node.children.append(node.id)
        return node

    def expand(self, node_id: str, proposals: list[ExpansionProposal], max_depth: int) -> list[str]:
        """Attach model-proposed children, respecting the TDA depth ceiling."""
        parent = self._nodes[node_id]
        added: list[str] = []
        for proposal in proposals:
            if parent.depth + 1 > max_depth:
                break
            if len(self._nodes) >= self.max_nodes:
                break
            child = self.add(
                hypothesis=proposal.hypothesis,
                phase=proposal.phase or parent.phase,
                skill=proposal.skill or parent.skill,
                prior=proposal.prior,
                parent=node_id,
            )
            added.append(child.id)
        if added and parent.status is NodeStatus.OPEN:
            parent.status = NodeStatus.EXPANDED
        return added

    # -- selection ---------------------------------------------------------
    def select(self, tda: TDAReport) -> AttackNode | None:
        """Return the highest expected-value selectable node that passes the TDA gate."""
        candidates = self.selectable_nodes()
        if not candidates:
            return None
        ranked = sorted(candidates, key=lambda node: (node.score, -node.depth), reverse=True)
        best = ranked[0]
        if tda.level.value in {"high", "critical"} and best.score < tda.expansion_threshold:
            return None
        return best

    def prune_low_value(self, tda: TDAReport) -> list[str]:
        """Prune open nodes that cannot justify their cost under current difficulty."""
        pruned: list[str] = []
        for node in self.open_nodes():
            if node.score < tda.expansion_threshold and node.depth > 0:
                node.status = NodeStatus.PRUNED
                node.note = (
                    f"pruned: score {node.score:.2f} < threshold {tda.expansion_threshold:.2f}"
                )
                pruned.append(node.id)
        return pruned

    def enforce_depth(self, max_depth: int) -> list[str]:
        """Prune nodes deeper than the TDA-allowed expansion depth."""
        pruned: list[str] = []
        for node in self.open_nodes():
            if node.depth > max_depth:
                node.status = NodeStatus.PRUNED
                node.note = f"pruned: depth {node.depth} > max_depth {max_depth}"
                pruned.append(node.id)
        return pruned

    # -- evidence ----------------------------------------------------------
    def apply_evidence(self, skill: str | None, weight: float) -> None:
        """Boost nodes that share a skill with a confirmed finding."""
        for node in self._nodes.values():
            if (
                skill
                and node.skill == skill
                and node.status in {NodeStatus.OPEN, NodeStatus.EXPANDED}
            ):
                node.evidence_weight = min(1.0, round(node.evidence_weight + weight, 4))

    def apply_result(
        self,
        node_id: str,
        *,
        ok: bool,
        findings: list[Finding],
        reason: str | None = None,
    ) -> None:
        """Fold one tool result into the tree. Deterministic, no model input."""
        node = self._nodes.get(node_id)
        if node is None:
            return
        node.attempts += 1
        if not ok:
            node.failures += 1
            node.note = reason or "tool invocation failed"
            if node.failures >= 2:
                node.status = NodeStatus.PRUNED
                node.note = f"pruned after {node.failures} failed attempts"
            return
        strong = [
            finding
            for finding in findings
            if finding.severity.rank >= Severity.HIGH.rank and finding.verified
        ]
        if strong:
            node.status = NodeStatus.CONFIRMED
            node.note = f"confirmed by {strong[0].tool}: {strong[0].title}"
            self.apply_evidence(node.skill, 0.2)
        elif findings:
            # Evidence arrived but nothing is confirmed: keep the hypothesis alive
            # until its attempt budget is spent or the model expands it.
            node.evidence_weight = min(1.0, round(node.evidence_weight + 0.1, 4))
            node.note = f"{len(findings)} evidence item(s) collected, no confirmation"
        else:
            node.status = NodeStatus.EXHAUSTED
            node.note = "no evidence produced"

    # -- state -------------------------------------------------------------
    def is_exhausted(self) -> bool:
        return not self.selectable_nodes()

    def confirmed(self) -> list[AttackNode]:
        return [node for node in self._nodes.values() if node.status is NodeStatus.CONFIRMED]

    def best_path(self, node_id: str | None = None) -> list[AttackNode]:
        """Walk parents from ``node_id`` (default: best confirmed node)."""
        if node_id is None:
            confirmed = self.confirmed()
            if not confirmed:
                return []
            node_id = max(confirmed, key=lambda node: node.score).id
        path: list[AttackNode] = []
        current: str | None = node_id
        while current is not None and len(path) < 32:
            node = self._nodes.get(current)
            if node is None:
                break
            path.append(node)
            current = node.parent
        return list(reversed(path))

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {status.value: 0 for status in NodeStatus}
        for node in self._nodes.values():
            counts[node.status.value] += 1
        counts["total"] = len(self._nodes)
        return counts

    def digest(self, limit: int = 12) -> str:
        """Compact tree rendering for the system prompt."""
        nodes = sorted(self._nodes.values(), key=lambda node: node.id)[:limit]
        lines = [node.summary() for node in nodes]
        stats = self.stats()
        lines.append(
            "tree_stats: total={total} open={open} confirmed={confirmed} pruned={pruned} "
            "exhausted={exhausted}".format(**stats)
        )
        return "\n".join(lines)


__all__ = [
    "MAX_NODE_ATTEMPTS",
    "AttackNode",
    "AttackTree",
    "ExpansionProposal",
    "NodeStatus",
]
