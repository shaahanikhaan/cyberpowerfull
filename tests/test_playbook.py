"""Playbook engine tests: real execution paths, guardrails, and adaptivity."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberpowerfull.errors import PlaybookNotFound
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.models import Capability, Finding, Phase, Severity
from cyberpowerfull.playbook import (
    COMMON_TCP_PORTS,
    Facts,
    PlaybookRunner,
    describe_playbooks,
    get_playbook,
    playbook_names,
    run_playbook,
)
from cyberpowerfull.reporting import render_markdown, write_reports
from cyberpowerfull.scope import Scope
from cyberpowerfull.tools.base import ToolResult, ToolStatus

TCP_ARGS = {"target": "127.0.0.1", "ports": list(COMMON_TCP_PORTS), "timeout_s": 1.0}


def make_finding(severity: Severity = Severity.INFO, **overrides) -> Finding:
    payload = {
        "title": "Open TCP port 22",
        "severity": severity,
        "target": "127.0.0.1",
        "endpoint": "127.0.0.1:22",
        "evidence": "tcp_probe state=open port=22",
        "tool": "tcp_probe",
        "phase": Phase.RECON,
        "confidence": 0.9,
    }
    payload.update(overrides)
    return Finding(**payload)


class StubTool:
    """Minimal worker-facing tool double (no subprocess, no binaries)."""

    def __init__(
        self,
        findings: list[Finding] | None = None,
        *,
        name: str = "tcp_probe",
        phase: Phase = Phase.RECON,
        status: ToolStatus = ToolStatus.OK,
        capability: Capability | None = None,
        installed: bool = True,
    ) -> None:
        self.name = name
        self.phase = phase
        self.status = status
        self.findings = list(findings or [])
        self.required_capability = capability
        self.external = False
        self.calls: list[dict] = []
        self._installed = installed

    def validate(self, raw_args: dict):
        """Mirror BaseTool.validate: the worker re-checks the canonical target."""
        return SimpleNamespace(target=str(raw_args.get("target", "127.0.0.1")))

    def describe(self) -> dict:
        return {
            "name": self.name,
            "phase": self.phase.value,
            "skill": "information_disclosure",
            "binary": "stub",
            "resolved_binary": "stub" if self._installed else None,
            "installed": self._installed,
            "destructive": False,
            "external": False,
            "capability": self.required_capability.value if self.required_capability else None,
            "description": "stub",
            "input_schema": {},
        }

    def run(self, raw_args: dict, *, dry_run: bool = False, policy=None) -> ToolResult:
        self.calls.append(dict(raw_args))
        if dry_run:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED, argv=["stub"])
        return ToolResult(
            tool=self.name,
            status=self.status,
            argv=["stub"],
            exit_code=0 if self.status is ToolStatus.OK else 1,
            findings=list(self.findings),
            observations=["stub observation"],
            duration_ms=1,
        )


@pytest.fixture
def scope() -> Scope:
    return Scope(
        engagement="playbook-test",
        authorized=True,
        targets=["127.0.0.1"],
        capabilities=["aggressive"],
    )


@pytest.fixture
def memory():
    store = MemoryStore(":memory:", run_id="play-test")
    yield store
    store.close()


def build(scope: Scope, memory: MemoryStore, tools: dict | None = None, **kwargs) -> PlaybookRunner:
    return PlaybookRunner(
        scope=scope,
        target="127.0.0.1",
        memory=memory,
        tools=tools,
        toolchain=_empty_toolchain(),
        **kwargs,
    )


def _empty_toolchain():
    from cyberpowerfull.inventory import Toolchain

    return Toolchain(operating_system={"name": "test"})


class TestCatalogue:
    def test_playbooks_are_registered(self) -> None:
        assert set(playbook_names()) == {"recon", "web", "network", "stealth", "api", "full"}
        assert all(row["steps"] > 0 for row in describe_playbooks())

    def test_unknown_playbook_exits_8(self) -> None:
        with pytest.raises(PlaybookNotFound) as excinfo:
            get_playbook("mega-nuke")
        assert excinfo.value.exit_code == 8

    def test_every_step_names_a_registered_tool(self) -> None:
        from cyberpowerfull.tools.registry import tool_names

        for name in playbook_names():
            for step in get_playbook(name).steps:
                assert step.tool in tool_names(), f"{name}:{step.id} -> {step.tool}"

    def test_steps_have_unique_ids(self) -> None:
        playbook = get_playbook("full")
        ids = [step.id for step in playbook.steps]
        assert len(ids) == len(set(ids))


class TestFacts:
    def test_absorb_ports_urls_and_tech(self) -> None:
        facts = Facts(target="127.0.0.1")
        facts.absorb(
            "nmap",
            [
                make_finding(title="Open TCP port 80 (http)", endpoint="127.0.0.1:80"),
                make_finding(
                    title="Technology fingerprint: Nginx, PHP",
                    endpoint="https://127.0.0.1/",
                ),
            ],
            ["http 200 https://127.0.0.1/login title=Login"],
        )
        assert 80 in facts.open_ports
        assert "https://127.0.0.1/login" in facts.urls
        assert "Nginx" in facts.tech
        assert facts.primary_url.startswith("https://127.0.0.1")

    def test_subdomains_and_host_urls(self) -> None:
        facts = Facts(target="lab.test")
        facts.absorb(
            "subfinder",
            [make_finding(title="Subdomain discovered: api.lab.test", endpoint="api.lab.test")],
            [],
        )
        assert facts.subdomains == ["api.lab.test"]
        assert facts.domain == "lab.test"
        plain = Facts(target="lab.test")
        assert plain.http_url == "http://lab.test"

    def test_ip_target_has_no_domain(self) -> None:
        facts = Facts(target="192.0.2.10")
        assert facts.domain is None

    def test_web_and_tls_port_views(self) -> None:
        facts = Facts(target="x")
        facts.add_port(8080)
        facts.add_port(443)
        assert facts.web_ports() == [443, 8080]
        assert facts.tls_ports() == [443]

    def test_default_web_ports_when_unknown(self) -> None:
        assert Facts(target="x").web_ports() == [80, 443]


class TestSkipDisclosure:
    def test_skips_are_recorded_in_the_trace_and_report(
        self, scope, memory, tmp_path: Path
    ) -> None:
        # nmap is not installed in the test environment: the step must be skipped
        # with a reason that reaches both the trace and the markdown report.
        runner = build(scope, memory, {"tcp_probe": StubTool([make_finding()])})
        result = runner.run(get_playbook("network"))
        assert result.trace.skipped, "no skip recorded"
        assert any("net-nmap" in entry for entry in result.trace.skipped)
        assert any("not installed" in entry for entry in result.trace.skipped)

        from cyberpowerfull.reporting import render_markdown

        report = render_markdown(result.trace)
        assert "## Skipped steps" in report
        assert "net-nmap" in report


class TestRunner:
    def test_native_step_produces_evidence_and_report(self, scope, memory, tmp_path: Path) -> None:
        stub = StubTool(
            [
                make_finding(),
                make_finding(endpoint="127.0.0.1:111", title="Open TCP port 111"),
            ]
        )
        runner = build(scope, memory, {"tcp_probe": stub})
        result = runner.run(get_playbook("network"))
        assert result.stop_reason == "playbook_complete"
        assert "net-tcp" in result.executed
        assert len(result.findings) == 2
        assert stub.calls and stub.calls[0]["target"] == "127.0.0.1"
        assert 22 in runner.facts.open_ports

        record = result.trace.steps[0]
        assert record.action == "playbook"
        assert record.result["status"] == "ok"
        assert record.node == "net-tcp"

        paths = write_reports(result.trace, tmp_path)
        report = paths["report"].read_text(encoding="utf-8")
        assert "Open TCP port 22" in report
        assert "backend: playbook:network" in report
        assert "Basic Run Assertions" not in report  # no placeholder sections
        assert "net-tcp" in render_markdown(result.trace)

    def test_missing_binaries_are_skipped_with_reason(self, scope, memory) -> None:
        result = build(scope, memory).run(get_playbook("web"))
        assert result.executed == []
        assert any("binary not installed" in line for line in result.skipped)

    def test_capability_gate_skips_aggressive_tools(self, memory) -> None:
        restricted = Scope(engagement="x", authorized=True, targets=["127.0.0.1"], capabilities=[])
        masscan = StubTool(name="masscan", phase=Phase.SCANNING, capability=Capability.AGGRESSIVE)
        result = build(restricted, memory, {"masscan": masscan}).run(get_playbook("network"))
        assert masscan.calls == []
        assert any("requires capability 'aggressive'" in line for line in result.skipped)

    def test_capability_grant_lets_aggressive_tool_run(self, scope, memory) -> None:
        masscan = StubTool(
            [
                make_finding(
                    severity=Severity.INFO,
                    endpoint="127.0.0.1:8443",
                    title="Open tcp port 8443 (masscan)",
                )
            ],
            name="masscan",
            phase=Phase.SCANNING,
            capability=Capability.AGGRESSIVE,
        )
        result = build(scope, memory, {"masscan": masscan}).run(get_playbook("network"))
        assert "net-masscan" in result.executed
        assert masscan.calls[0]["ports"] == "1-65535"

    def test_parallel_group_runs_every_step(self, scope, memory) -> None:
        n = StubTool(name="nmap", phase=Phase.SCANNING)
        b = StubTool(name="naabu", phase=Phase.SCANNING)
        result = build(
            scope,
            memory,
            {"nmap": n, "naabu": b, "tcp_probe": StubTool([])},
            parallel=4,
        ).run(get_playbook("network"))
        assert {"net-nmap", "net-naabu"}.issubset(set(result.executed))
        assert len(n.calls) == 1 and len(b.calls) == 1

    def test_discovered_ports_drive_the_next_group(self, scope, memory) -> None:
        nmap = StubTool(name="nmap", phase=Phase.SCANNING)
        probe = StubTool(
            [
                make_finding(endpoint="127.0.0.1:22"),
                make_finding(endpoint="127.0.0.1:111", title="Open TCP port 111"),
            ]
        )
        result = build(scope, memory, {"nmap": nmap, "tcp_probe": probe}).run(
            get_playbook("network")
        )
        assert "net-services" in result.executed
        service_call = [call for call in nmap.calls if call["ports"] != "top-1000"]
        assert service_call and service_call[0]["ports"] == "22,111"
        assert "http-headers" in service_call[0]["scripts"]

    def test_duplicate_findings_are_deduplicated(self, scope, memory) -> None:
        stub = StubTool([make_finding()])
        result = build(scope, memory, {"tcp_probe": stub}).run(get_playbook("network"))
        assert len(result.findings) == 1
        assert memory.stats()["findings"] == 1

    def test_failures_are_recorded_not_raised(self, scope, memory) -> None:
        failing = StubTool(name="tcp_probe", status=ToolStatus.ERROR)
        result = build(scope, memory, {"tcp_probe": failing}).run(get_playbook("network"))
        assert "net-tcp" in result.executed
        assert result.trace.steps[0].result["status"] == "error"
        assert memory.negative_cache_hit(
            "tcp_probe", TCP_ARGS
        ), "a failed invocation must be cached"

    def test_negative_cache_prevents_repeat(self, scope, memory) -> None:
        memory.record_attempt(
            tool="tcp_probe", args=TCP_ARGS, target="127.0.0.1", ok=False, error="timed out"
        )
        stub = StubTool([make_finding()])
        result = build(scope, memory, {"tcp_probe": stub}).run(get_playbook("network"))
        assert stub.calls == []
        assert any("negative cache" in line and "timed out" in line for line in result.skipped)

    def test_dry_run_executes_nothing(self, scope, memory) -> None:
        stub = StubTool([make_finding()])
        result = build(scope, memory, {"tcp_probe": stub}, dry_run=True).run(
            get_playbook("network")
        )
        assert stub.calls, "arguments are still validated"
        assert result.findings == []
        assert result.trace.steps[0].result["status"] == "skipped"

    def test_step_budget_stops_the_run(self, scope, memory) -> None:
        n = StubTool(name="nmap", phase=Phase.SCANNING)
        b = StubTool(name="naabu", phase=Phase.SCANNING)
        result = build(scope, memory, {"nmap": n, "naabu": b}, max_steps=1).run(
            get_playbook("network")
        )
        assert result.stop_reason == "budget_exhausted:steps"

    def test_progress_callback_receives_steps(self, scope, memory) -> None:
        seen = []
        stub = StubTool([make_finding()])
        build(scope, memory, {"tcp_probe": stub}).run(get_playbook("network"), progress=seen.append)
        assert seen and seen[0].tool == "tcp_probe"
        assert seen[0].index == 1

    def test_scope_enforcement_holds_for_playbooks(self, memory) -> None:
        scope = Scope(engagement="x", authorized=True, targets=["192.0.2.1"])
        runner = PlaybookRunner(
            scope=scope, target="127.0.0.1", memory=memory, toolchain=_empty_toolchain()
        )
        result = runner.run(get_playbook("network"))
        assert result.executed == []
        assert any("not inside the authorized scope" in line for line in result.skipped)

    def test_run_playbook_helper(self, scope, memory) -> None:
        stub = StubTool([make_finding()])
        result = run_playbook(
            "network",
            scope=scope,
            target="127.0.0.1",
            memory=memory,
            tools={"tcp_probe": stub},
            toolchain=_empty_toolchain(),
        )
        assert "net-tcp" in result.executed

    def test_trace_is_serialisable(self, scope, memory) -> None:
        stub = StubTool([make_finding()])
        result = build(scope, memory, {"tcp_probe": stub}).run(get_playbook("network"))
        payload = json.loads(result.trace.model_dump_json())
        assert payload["backend"] == "playbook:network"
        assert payload["model"] == "none"
        assert payload["steps"][0]["action"] == "playbook"

    def test_conditional_steps_need_discovered_facts(self, scope, memory) -> None:
        result = build(scope, memory).run(get_playbook("web"))
        assert any(
            "precondition not met" in line or "binary not installed" in line
            for line in result.skipped
        )
