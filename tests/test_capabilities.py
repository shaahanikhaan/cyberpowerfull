"""Capability gating: nothing aggressive runs without an explicit scope grant."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cyberpowerfull.brain.orchestrator import DelegationRequest, WorkerAgent
from cyberpowerfull.models import Capability
from cyberpowerfull.scope import Scope
from cyberpowerfull.tools.base import ToolStatus
from cyberpowerfull.tools.hydra import HydraTool
from cyberpowerfull.tools.masscan import MasscanTool
from cyberpowerfull.tools.pentagi import PentagiTool
from cyberpowerfull.tools.strix import StrixTool


def _scope(**overrides) -> Scope:
    payload = {
        "engagement": "cap-test",
        "authorized": True,
        "targets": ["127.0.0.1"],
        "capabilities": [],
    }
    payload.update(overrides)
    return Scope.model_validate(payload)


class TestScopeCapabilities:
    def test_default_is_nothing_granted(self) -> None:
        scope = _scope()
        assert scope.capabilities == []
        assert scope.allows(Capability.AGGRESSIVE) is False
        assert scope.allows(None) is True

    def test_granted_capability_is_allowed(self) -> None:
        scope = _scope(capabilities=["aggressive"])
        assert scope.allows(Capability.AGGRESSIVE) is True
        assert scope.allows("credential_testing") is False

    def test_unknown_capability_string_is_denied(self) -> None:
        assert _scope().allows("root_everything") is False

    def test_unknown_capability_name_is_rejected_by_schema(self) -> None:
        with pytest.raises(ValidationError):
            Scope.model_validate(
                {"engagement": "x", "authorized": True, "targets": ["a"], "capabilities": ["god"]}
            )

    def test_fingerprint_changes_when_capabilities_change(self) -> None:
        base = _scope().fingerprint()
        assert _scope(capabilities=["aggressive"]).fingerprint() != base

    def test_prompt_block_lists_capabilities(self) -> None:
        assert (
            "granted_capabilities: aggressive" in _scope(capabilities=["aggressive"]).prompt_block()
        )
        assert "granted_capabilities: none" in _scope().prompt_block()


class TestWorkerCapabilityGate:
    @pytest.mark.parametrize(
        ("tool", "capability"),
        [
            ("masscan", Capability.AGGRESSIVE),
            ("hydra", Capability.CREDENTIAL_TESTING),
            ("strix", Capability.EXTERNAL_AGENTS),
        ],
    )
    def test_tool_is_blocked_without_capability(self, tool: str, capability: Capability) -> None:
        worker = WorkerAgent("scan", scope=_scope())
        if tool == "hydra":
            worker = WorkerAgent("validate", scope=_scope())
        if tool == "strix":
            worker = WorkerAgent("external", scope=_scope())
        result = worker.execute(
            DelegationRequest(agent="scan", tool=tool, args={"target": "127.0.0.1"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert capability.value in (result.error or "")
        assert "scope.json" in (result.error or "")

    def test_instances_declare_their_capability(self) -> None:
        assert MasscanTool.required_capability is Capability.AGGRESSIVE
        assert HydraTool.required_capability is Capability.CREDENTIAL_TESTING
        assert StrixTool.required_capability is Capability.EXTERNAL_AGENTS
        assert PentagiTool.required_capability is Capability.EXTERNAL_AGENTS

    def test_catalog_exposes_capability_and_external_flags(self) -> None:
        from cyberpowerfull.tools.registry import catalog

        entries = {entry["name"]: entry for entry in catalog()}
        assert entries["masscan"]["capability"] == "aggressive"
        assert entries["strix"]["external"] is True
        assert entries["nmap"]["capability"] is None
        assert entries["nmap"]["external"] is False

    def test_dry_run_still_requires_capability(self) -> None:
        worker = WorkerAgent("scan", scope=_scope())
        result = worker.execute(
            DelegationRequest(agent="scan", tool="masscan", args={"target": "127.0.0.1"}),
            dry_run=True,
        )
        assert result.status is ToolStatus.BLOCKED


class TestOrchestratorGuards:
    """The reasoning loop must honour capability and cache guardrails too."""

    def _orchestrator(self, scope: Scope, decisions: list[dict], tools: dict | None = None):
        from cyberpowerfull.brain.orchestrator import Orchestrator
        from cyberpowerfull.config import RunConfig
        from cyberpowerfull.memory.store import MemoryStore
        from tests.conftest import FakeLLM

        memory = MemoryStore(":memory:", run_id="guard-test")
        orchestrator = Orchestrator(
            scope=scope,
            config=RunConfig(max_iterations=len(decisions) + 1),
            client=FakeLLM(decisions),
            memory=memory,
            target="127.0.0.1",
            tools=tools,
        )
        return orchestrator, memory

    def test_capability_is_enforced_in_the_loop(self) -> None:
        scope = _scope()
        orchestrator, _ = self._orchestrator(
            scope,
            [
                {
                    "tool": "delegate",
                    "args": {"agent": "validate", "tool": "hydra", "args": {"target": "127.0.0.1"}},
                },
                {"tool": "terminate"},
            ],
        )
        result = orchestrator.run()
        assert result.trace.steps[0].result["status"] == "blocked"
        assert "credential_testing" in (result.trace.steps[0].error or "")

    def test_negative_cache_prevents_a_second_identical_failure(self) -> None:
        from cyberpowerfull.tools.base import ToolStatus
        from tests.test_playbook import StubTool

        stub = StubTool(name="tcp_probe", status=ToolStatus.ERROR)
        delegate = {
            "tool": "delegate",
            "args": {"agent": "recon", "tool": "tcp_probe", "args": {"target": "127.0.0.1"}},
        }
        orchestrator, _ = self._orchestrator(
            _scope(),
            [delegate, dict(delegate), {"tool": "terminate"}],
            tools={"tcp_probe": stub},
        )
        result = orchestrator.run()
        assert len(stub.calls) == 1, "identical failing invocation must not be retried"
        assert "negative cache" in (result.trace.steps[1].error or "")

    def test_external_worker_only_accepts_external_tools(self) -> None:
        worker = WorkerAgent("external", scope=_scope(capabilities=["external_agents"]))
        assert worker.allowlist == frozenset({"strix", "pentagi", "sn1per"})
        result = worker.execute(
            DelegationRequest(agent="external", tool="nmap", args={"target": "127.0.0.1"})
        )
        assert result.status is ToolStatus.BLOCKED
