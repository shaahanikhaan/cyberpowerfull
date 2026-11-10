"""Orchestration tests: role separation, scope gating, stop conditions, traces."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from cyberpowerfull.brain.attack_tree import AttackTree
from cyberpowerfull.brain.orchestrator import (
    WORKER_TOOL_ALLOWLIST,
    DelegationRequest,
    Orchestrator,
    RootAgent,
    WorkerAgent,
)
from cyberpowerfull.config import RunConfig
from cyberpowerfull.errors import PolicyViolation
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, ToolResult, ToolStatus
from tests.conftest import FailingLLM, FakeLLM


class StubTool(BaseTool):
    """Deterministic stand-in for a real tool; never spawns a process."""

    name = "tcp_probe"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = None
    description = "stub tool for orchestrator tests"
    input_model = HostInput

    def __init__(
        self,
        findings: list[Finding] | None = None,
        status: ToolStatus = ToolStatus.OK,
    ) -> None:
        self._findings = findings or []
        self._status = status
        self.calls: list[dict[str, Any]] = []

    def build_argv(self, args, out_file=None):
        return ["stub", args.target]

    def run(self, raw_args, *, dry_run=False, policy=None):
        args = self.validate(raw_args)
        self.calls.append(dict(raw_args))
        return ToolResult(
            tool=self.name,
            status=ToolStatus.SKIPPED if dry_run else self._status,
            argv=self.build_argv(args),
            findings=[] if dry_run else list(self._findings),
            observations=["stub executed"],
        )


def make_finding(severity: Severity = Severity.HIGH, verified: bool = True) -> Finding:
    return Finding(
        title="Sensitive service port exposed: 6379/tcp (redis)",
        severity=severity,
        confidence=0.8,
        target="127.0.0.1",
        endpoint="127.0.0.1:6379",
        tool="tcp_probe",
        skill="information_disclosure",
        verified=verified,
    )


def delegate(tool: str = "tcp_probe", target: str = "127.0.0.1", **extra) -> dict:
    args = {"agent": "recon", "tool": tool, "args": {"target": target}}
    args.update(extra)
    return {"tool": "delegate", "args": args, "reason": "test delegation"}


def build(
    scope,
    decisions: list[dict],
    *,
    tools: dict[str, BaseTool] | None = None,
    config: RunConfig | None = None,
    memory: MemoryStore | None = None,
):
    client = FakeLLM(decisions)
    store = memory or MemoryStore(":memory:", run_id="test")
    orchestrator = Orchestrator(
        scope=scope,
        config=config or RunConfig(max_iterations=6),
        client=client,
        memory=store,
        target="127.0.0.1",
        tools=tools if tools is not None else {"tcp_probe": StubTool([make_finding()])},
    )
    return orchestrator, client, store


class TestRoleSeparation:
    def test_root_agent_has_no_executor(self) -> None:
        root = RootAgent(FakeLLM())
        assert not hasattr(root, "execute")
        assert not hasattr(root, "_tools")
        assert frozenset({"delegate", "terminate"}) == RootAgent.ALLOWED_ACTIONS

    def test_root_agent_rejects_tool_action(self) -> None:
        client = FakeLLM([{"tool": "nmap", "args": {"target": "127.0.0.1"}}])
        with pytest.raises(PolicyViolation, match="root agent attempted action"):
            RootAgent(client).act("system", "step", step=1)

    def test_root_agent_normalises_action(self) -> None:
        client = FakeLLM([{"tool": "  TERMINATE ", "reason": "done"}])
        assert RootAgent(client).act("s", "p", step=1).tool == "terminate"

    def test_worker_allowlist(self, scope) -> None:
        worker = WorkerAgent("validate", scope=scope)
        assert worker.allowlist is WORKER_TOOL_ALLOWLIST["validate"]
        result = worker.execute(
            DelegationRequest(agent="validate", tool="nmap", args={"target": "127.0.0.1"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert "may not run" in (result.error or "")

    def test_worker_requires_target(self, scope) -> None:
        worker = WorkerAgent("recon", scope=scope)
        result = worker.execute(DelegationRequest(agent="recon", tool="nmap", args={}))
        assert result.status is ToolStatus.ERROR
        assert "must include a string 'target'" in (result.error or "")

    def test_worker_blocks_out_of_scope(self, scope) -> None:
        stub = StubTool([make_finding()])
        worker = WorkerAgent("recon", scope=scope, tools={"tcp_probe": stub})
        result = worker.execute(
            DelegationRequest(agent="recon", tool="tcp_probe", args={"target": "8.8.8.8"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert stub.calls == []

    def test_worker_blocks_disallowed_phase(self, scope_payload) -> None:
        from cyberpowerfull.scope import Scope

        scope_payload["allowed_phases"] = ["recon"]
        restricted = Scope.model_validate(scope_payload)
        worker = WorkerAgent("scan", scope=restricted)
        result = worker.execute(
            DelegationRequest(agent="scan", tool="nmap", args={"target": "127.0.0.1"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert "not permitted by scope" in (result.error or "")

    def test_worker_unknown_tool(self, scope) -> None:
        worker = WorkerAgent("scan", scope=scope)
        result = worker.execute(
            DelegationRequest(agent="scan", tool="metasploit", args={"target": "127.0.0.1"})
        )
        assert result.status is ToolStatus.BLOCKED

    def test_worker_dry_run(self, scope) -> None:
        stub = StubTool([make_finding()])
        worker = WorkerAgent("recon", scope=scope, tools={"tcp_probe": stub})
        result = worker.execute(
            DelegationRequest(agent="recon", tool="tcp_probe", args={"target": "127.0.0.1"}),
            dry_run=True,
        )
        assert result.status is ToolStatus.SKIPPED
        assert result.findings == []


class TestRunLoop:
    def test_happy_path_produces_trace_and_findings(self, scope) -> None:
        orchestrator, client, memory = build(scope, [delegate(), {"tool": "terminate"}])
        result = orchestrator.run()

        assert result.stop_reason == "agent_terminated"
        assert len(result.trace.steps) == 2
        assert result.trace.steps[0].tool == "tcp_probe"
        assert result.trace.steps[0].result["status"] == "ok"
        assert len(result.findings) == 1
        assert result.findings[0].severity is Severity.HIGH
        assert memory.stats()["findings"] == 1
        assert memory.stats()["attempts"] == 1
        assert len(client.calls) == 2
        assert result.trace.attack_tree["total"] >= 1

    def test_prompt_contains_scope_and_skills(self, scope) -> None:
        orchestrator, client, _ = build(scope, [{"tool": "terminate"}])
        orchestrator.run()
        system_prompt, step_prompt = client.calls[0]
        assert "authorized_scope" in system_prompt
        assert "## Skill: SQL Injection" in system_prompt
        assert "127.0.0.1" in step_prompt

    def test_policy_violation_stops_run(self, scope) -> None:
        orchestrator, _, _ = build(scope, [{"tool": "nmap", "args": {"target": "127.0.0.1"}}])
        result = orchestrator.run()
        assert result.stop_reason == "policy_violation"
        assert result.trace.steps[0].action == "policy_violation"
        assert "permitted actions" in (result.trace.error or "")

    def test_invalid_delegation_is_rejected_then_continues(self, scope) -> None:
        bad = {"tool": "delegate", "args": {"agent": "recon", "args": {"target": "127.0.0.1"}}}
        orchestrator, _, _ = build(scope, [bad, {"tool": "terminate"}])
        result = orchestrator.run()
        assert result.stop_reason == "agent_terminated"
        assert result.trace.steps[0].error
        assert "invalid delegation" in (result.trace.steps[0].error or "")

    def test_scope_violation_is_blocked(self, scope) -> None:
        orchestrator, _, memory = build(scope, [delegate(target="8.8.8.8"), {"tool": "terminate"}])
        result = orchestrator.run()
        assert result.findings == []
        assert result.trace.steps[0].result["status"] == "blocked"
        assert memory.stats()["attempts"] == 1

    def test_duplicate_findings_deduplicated(self, scope) -> None:
        stub = StubTool([make_finding(), make_finding()])
        orchestrator, _, memory = build(
            scope, [delegate(), delegate(), {"tool": "terminate"}], tools={"tcp_probe": stub}
        )
        result = orchestrator.run()
        assert len(result.findings) == 1
        assert memory.stats()["findings"] == 1

    def test_critical_finding_stops_run(self, scope) -> None:
        stub = StubTool([make_finding(Severity.CRITICAL)])
        orchestrator, _, _ = build(scope, [delegate(), delegate()], tools={"tcp_probe": stub})
        result = orchestrator.run()
        assert result.stop_reason == "critical_finding_confirmed"
        assert len(result.trace.steps) == 1

    def test_attack_tree_exhaustion(self, scope) -> None:
        orchestrator, _, _ = build(scope, [delegate()], tools={"tcp_probe": StubTool([])})
        result = orchestrator.run()
        assert result.stop_reason == "attack_tree_exhausted"
        assert len(result.trace.steps) == 1

    def test_iteration_budget(self, scope) -> None:
        orchestrator, _, _ = build(
            scope, [delegate(), delegate(), delegate()], config=RunConfig(max_iterations=1)
        )
        result = orchestrator.run()
        assert result.stop_reason == "budget_exhausted:iterations"
        assert len(result.trace.steps) == 1

    def test_token_budget(self, scope) -> None:
        orchestrator, _, _ = build(
            scope, [delegate(), delegate()], config=RunConfig(max_iterations=6, max_tokens=1)
        )
        result = orchestrator.run()
        assert result.stop_reason == "budget_exhausted:tokens"
        assert len(result.trace.steps) == 0

    def test_seconds_budget(self, scope) -> None:
        orchestrator, _, _ = build(
            scope, [delegate()], config=RunConfig(max_iterations=6, max_seconds=0)
        )
        result = orchestrator.run()
        assert result.stop_reason == "budget_exhausted:seconds"
        assert result.trace.steps == []

    def test_inference_failure_stops_run(self, scope) -> None:
        memory = MemoryStore(":memory:", run_id="test")
        orchestrator = Orchestrator(
            scope=scope,
            config=RunConfig(max_iterations=3),
            client=FailingLLM(),
            memory=memory,
            target="127.0.0.1",
        )
        result = orchestrator.run()
        assert result.stop_reason == "inference_failed"
        assert "unreachable" in (result.trace.error or "")

    def test_progress_callback(self, scope) -> None:
        seen = []
        orchestrator, _, _ = build(scope, [delegate(), {"tool": "terminate"}])
        orchestrator.run(progress=seen.append)
        assert len(seen) == 2
        assert seen[0].action == "delegate"

    def test_expansion_proposals_are_applied(self, scope) -> None:
        proposal = {
            "hypothesis": "Test IDOR on /api/users/1",
            "skill": "idor",
            "phase": "validation",
            "prior": 0.7,
        }
        orchestrator, _, _ = build(
            scope,
            [delegate(expand=[proposal]), {"tool": "terminate"}],
        )
        result = orchestrator.run()
        assert any("IDOR" in node.hypothesis for node in orchestrator.tree.nodes())
        assert result.trace.attack_tree["total"] >= 2

    def test_dry_run_executes_nothing(self, scope) -> None:
        stub = StubTool([make_finding()])
        orchestrator, _, _ = build(
            scope,
            [delegate(), {"tool": "terminate"}],
            tools={"tcp_probe": stub},
            config=RunConfig(dry_run=True),
        )
        result = orchestrator.run()
        assert stub.calls  # args validated
        assert result.findings == []
        assert result.trace.steps[0].result["status"] == "skipped"

    def test_memory_records_negative_attempts(self, scope) -> None:
        stub = StubTool([], status=ToolStatus.ERROR)
        orchestrator, _, memory = build(
            scope, [delegate(), {"tool": "terminate"}], tools={"tcp_probe": stub}
        )
        orchestrator.run()
        assert memory.negative_cache_hit("tcp_probe", {"target": "127.0.0.1"}) is not None


class TestDelegationRequestSchema:
    def test_defaults(self) -> None:
        request = DelegationRequest(tool="nmap")
        assert request.agent == "recon"
        assert request.args == {}

    def test_rejects_unknown_agent(self) -> None:
        with pytest.raises(ValidationError):
            DelegationRequest.model_validate({"agent": "exploit", "tool": "nmap"})

    def test_rejects_extra_keys(self) -> None:
        with pytest.raises(ValidationError):
            DelegationRequest.model_validate({"tool": "nmap", "surprise": 1})


def test_run_id_is_propagated(scope) -> None:
    memory = MemoryStore(":memory:", run_id="fixed-run")
    orchestrator = Orchestrator(
        scope=scope,
        config=RunConfig(max_iterations=2),
        client=FakeLLM([{"tool": "terminate"}]),
        memory=memory,
        target="127.0.0.1",
        run_id="fixed-run",
    )
    result = orchestrator.run()
    assert result.trace.run_id == "fixed-run"


def test_tree_injection(scope) -> None:
    tree = AttackTree(target="127.0.0.1")
    tree.add(hypothesis="preloaded hypothesis", parent=tree.root_id)
    orchestrator = Orchestrator(
        scope=scope,
        config=RunConfig(max_iterations=1),
        client=FakeLLM([{"tool": "terminate"}]),
        memory=MemoryStore(":memory:"),
        target="127.0.0.1",
        tree=tree,
    )
    result = orchestrator.run()
    assert result.trace.attack_tree["total"] == 2
