"""Built-in auto agent: ladder order, escalation, eligibility, termination."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from cyberpowerfull.brain.agent import AutoAgent
from cyberpowerfull.brain.llm import build_client
from cyberpowerfull.brain.orchestrator import Orchestrator
from cyberpowerfull.config import RunConfig
from cyberpowerfull.memory.store import MemoryStore


def _state(
    *,
    step: int,
    target: str = "127.0.0.1",
    last: dict[str, Any] | None = None,
    max_iterations: int = 12,
) -> str:
    return (
        "STATE\n"
        + json.dumps(
            {
                "step": step,
                "target": target,
                "phase": "recon",
                "attack_node": None,
                "difficulty": {},
                "last_tool_result": last,
                "known_failures": [],
                "budget": {"max_iterations": max_iterations, "tokens_left": 32000},
            }
        )
        + "\n\nEmit exactly one decision JSON object."
    )


def _result(
    tool: str,
    status: str = "ok",
    observations: list[str] | None = None,
    titles: list[str] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "tool": tool,
        "status": status,
        "exit_code": 0 if status == "ok" else 1,
        "observations": observations or [],
        "finding_titles": titles or [],
        "error": error,
    }


@pytest.fixture
def agent(monkeypatch) -> AutoAgent:
    """An agent on a host where every tool is installed but no wordlists exist."""
    monkeypatch.setattr(AutoAgent, "_installed_ok", lambda self, tool: True)
    monkeypatch.setattr("cyberpowerfull.brain.agent.pick_wordlist", lambda kind, **kw: None)
    return AutoAgent()


def _drive(agent: AutoAgent, steps: int, **kwargs: Any) -> list:
    """Drive decisions, feeding empty ok results back each time."""
    decisions = []
    last: dict[str, Any] | None = None
    for step in range(1, steps + 1):
        decision = agent.decide("system", _state(step=step, last=last, **kwargs), step=step)
        decisions.append(decision)
        if decision.tool == "terminate":
            break
        last = _result(decision.args["tool"])
    return decisions


class TestLadder:
    def test_first_decision_maps_the_surface(self, agent: AutoAgent) -> None:
        decision = agent.decide("system", _state(step=1), step=1)
        assert decision.tool == "delegate"
        assert decision.args["tool"] == "tcp_probe"
        assert decision.args["agent"] == "recon"
        assert decision.args["args"]["target"] == "127.0.0.1"
        assert 443 in decision.args["args"]["ports"]

    def test_ladder_progresses_without_repeats(self, agent: AutoAgent) -> None:
        decisions = _drive(agent, 8)
        tools = [d.args["tool"] for d in decisions if d.tool == "delegate"]
        assert tools[0] == "tcp_probe"
        assert "httpx" in tools[1:3]
        seen = {
            (d.args["tool"], json.dumps(d.args["args"], sort_keys=True))
            for d in decisions
            if d.tool == "delegate"
        }
        assert len(seen) == len(tools)

    def test_open_ports_steer_nmap_to_services(self, agent: AutoAgent) -> None:
        last = _result(
            "tcp_probe",
            observations=["tcp_probe open=[22, 80, 443]"],
            titles=["Open TCP port 22/tcp (ssh)"],
        )
        # Drain ladder until nmap is reached.
        tools: list[str] = []
        for step in range(2, 14):
            decision = agent.decide("system", _state(step=step, last=last), step=step)
            if decision.tool == "terminate":
                break
            tools.append(decision.args["tool"])
            if decision.args["tool"] == "nmap":
                assert "22" in decision.args["args"]["ports"]
                assert "443" in decision.args["args"]["ports"]
                assert "top-1000" not in decision.args["args"]["ports"]
                return
            last = _result(decision.args["tool"])
        pytest.fail(f"nmap never scheduled; saw {tools}")

    def test_domain_target_gets_dns_tools(self, agent: AutoAgent) -> None:
        decisions = _drive(agent, 8, target="lab.test")
        tools = [d.args["tool"] for d in decisions if d.tool == "delegate"]
        assert "subfinder" in tools
        assert "dnsrecon" in tools

    def test_ip_target_skips_dns_tools(self, agent: AutoAgent) -> None:
        decisions = _drive(agent, 20)
        tools = [d.args["tool"] for d in decisions if d.tool == "delegate"]
        assert "subfinder" not in tools
        assert "dnsrecon" not in tools

    def test_workers_match_tool_phases(self, agent: AutoAgent) -> None:
        decisions = _drive(agent, 20)
        by_tool = {d.args["tool"]: d.args["agent"] for d in decisions if d.tool == "delegate"}
        assert by_tool.get("tcp_probe") == "recon"
        assert by_tool.get("nmap") == "scan"
        # nuclei is skipped without templates, but the mapping is phase-driven.
        assert agent._worker_for("nuclei") == "validate"


class TestEscalation:
    def test_cve_becomes_searchsploit(self, agent: AutoAgent) -> None:
        agent.decide("system", _state(step=1), step=1)
        last = _result("nuclei", titles=["Apache Struts RCE (cve-2021-44228 template)"])
        decision = agent.decide("system", _state(step=2, last=last), step=2)
        assert decision.args["tool"] == "searchsploit"
        assert "CVE-2021-44228" in decision.args["args"]["query"]

    def test_wordpress_becomes_wpscan(self, agent: AutoAgent) -> None:
        agent.decide("system", _state(step=1), step=1)
        last = _result("whatweb", titles=["Technology fingerprint: WordPress 6.4"])
        decision = agent.decide("system", _state(step=2, last=last), step=2)
        assert decision.args["tool"] == "wpscan"

    def test_parameter_url_becomes_sqlmap_then_dalfox(self, agent: AutoAgent) -> None:
        agent.decide("system", _state(step=1), step=1)
        last = _result(
            "katana",
            observations=["http 200 https://127.0.0.1/search?q=x title=Search"],
        )
        first = agent.decide("system", _state(step=2, last=last), step=2)
        assert first.args["tool"] == "sqlmap"
        assert "?q=" in first.args["args"]["target"]
        second = agent.decide("system", _state(step=3, last=_result("sqlmap")), step=3)
        assert second.args["tool"] == "dalfox"

    def test_tls_port_becomes_testssl(self, agent: AutoAgent) -> None:
        agent.decide("system", _state(step=1), step=1)
        last = _result("tcp_probe", observations=["tcp_probe open=[443]"])
        decision = agent.decide("system", _state(step=2, last=last), step=2)
        assert decision.args["tool"] == "testssl"
        assert decision.args["args"]["target"].startswith("https://")

    def test_login_port_becomes_hydra_with_wordlist(
        self, agent: AutoAgent, monkeypatch, tmp_path
    ) -> None:
        wordlist = tmp_path / "pw.txt"
        wordlist.write_text("a\nb\n", encoding="utf-8")
        monkeypatch.setattr(
            "cyberpowerfull.brain.agent.pick_wordlist",
            lambda kind, **kw: str(wordlist) if kind == "passwords" else None,
        )
        fresh = AutoAgent()
        fresh.decide("system", _state(step=1), step=1)
        last = _result("tcp_probe", observations=["tcp_probe open=[22]"])
        decision = fresh.decide("system", _state(step=2, last=last), step=2)
        assert decision.args["tool"] == "hydra"
        assert decision.args["args"]["service"] == "ssh"
        assert decision.args["args"]["username"] == "root"

    def test_escalation_beats_ladder(self, agent: AutoAgent) -> None:
        # Even on step 2, fresh CVE evidence outranks the httpx ladder step.
        agent.decide("system", _state(step=1), step=1)
        last = _result("tcp_probe", titles=["Tomcat exposure CVE-2020-9484"])
        decision = agent.decide("system", _state(step=2, last=last), step=2)
        assert decision.args["tool"] == "searchsploit"


class TestEligibility:
    def test_missing_binary_is_retired(self, agent: AutoAgent) -> None:
        agent.decide("system", _state(step=1), step=1)
        agent.decide("system", _state(step=2, last=_result("nmap", status="missing")), step=2)
        decisions = _drive(agent, 20)
        tools = [d.args["tool"] for d in decisions if d.tool == "delegate"]
        assert "nmap" not in tools

    def test_two_strikes_retire_a_tool(self, agent: AutoAgent) -> None:
        agent.decide("system", _state(step=1), step=1)
        agent.decide("system", _state(step=2, last=_result("nikto", status="error")), step=2)
        agent.decide("system", _state(step=3, last=_result("nikto", status="error")), step=3)
        decisions = _drive(agent, 20)
        tools = [d.args["tool"] for d in decisions if d.tool == "delegate"]
        assert "nikto" not in tools

    def test_blocked_is_retired_immediately(self, agent: AutoAgent) -> None:
        agent.decide("system", _state(step=1), step=1)
        agent.decide("system", _state(step=2, last=_result("masscan", status="blocked")), step=2)
        assert "masscan" in agent._dead_tools

    def test_capability_gates_prefilter(self, agent: AutoAgent, scope) -> None:
        agent.attach_context(scope=scope)
        assert agent._capable("naabu") is False
        assert agent._capable("nmap") is True
        decisions = _drive(agent, 20)
        tools = [d.args["tool"] for d in decisions if d.tool == "delegate"]
        assert "naabu" not in tools
        assert "masscan" not in tools

    def test_slow_tools_need_a_deep_budget(self, agent: AutoAgent) -> None:
        shallow = _drive(agent, 30, max_iterations=12)
        tools = [d.args["tool"] for d in shallow if d.tool == "delegate"]
        assert "feroxbuster" not in tools
        assert "masscan" not in tools

    def test_slow_tools_join_a_deep_pass(self, agent: AutoAgent) -> None:
        deep = _drive(agent, 40, max_iterations=40)
        tools = [d.args["tool"] for d in deep if d.tool == "delegate"]
        assert "feroxbuster" in tools or "masscan" in tools


class TestTermination:
    def test_exhausted_ladder_terminates_with_summary(self, agent: AutoAgent) -> None:
        decisions = _drive(agent, 40)
        assert decisions[-1].tool == "terminate"
        assert decisions[-1].done is True
        assert "coverage complete" in decisions[-1].reason

    def test_budget_terminates(self, agent: AutoAgent) -> None:
        decision = agent.decide("system", _state(step=12, max_iterations=12), step=12)
        assert decision.tool == "terminate"

    def test_deadline_terminates(self, agent: AutoAgent) -> None:
        agent.set_deadline(time.monotonic() - 1)
        decision = agent.decide("system", _state(step=1), step=1)
        assert decision.tool == "terminate"
        assert "budget" in decision.reason

    def test_garbage_state_never_crashes(self) -> None:
        fresh = AutoAgent()
        decision = fresh.decide("system", "STATE\n{oops", step=1)
        assert decision.tool in {"delegate", "terminate"}


class TestOrchestratorWiring:
    def test_orchestrator_attaches_context(self, scope) -> None:
        agent = build_client("auto")
        assert isinstance(agent, AutoAgent)
        memory = MemoryStore(":memory:", run_id="attach")
        Orchestrator(
            scope=scope,
            config=RunConfig(max_iterations=1),
            client=agent,
            memory=memory,
            target="127.0.0.1",
        )
        assert agent._scope is scope
        assert agent._memory is memory
        assert agent._toolchain is not None
        memory.close()

    def test_auto_burns_no_tokens(self, scope) -> None:
        from tests.test_orchestrator import StubTool

        agent = AutoAgent()
        memory = MemoryStore(":memory:", run_id="notokens")
        orchestrator = Orchestrator(
            scope=scope,
            config=RunConfig(max_iterations=2, max_tokens=10),
            client=agent,
            memory=memory,
            target="127.0.0.1",
            tools={"tcp_probe": StubTool([])},
        )
        result = orchestrator.run()
        assert result.trace.budget.tokens_used == 0
        assert result.stop_reason != "budget_exhausted:tokens"
        memory.close()
