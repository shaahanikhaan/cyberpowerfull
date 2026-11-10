"""CLI tests, including a real end-to-end run against a local mock TCP service."""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path
from unittest import mock
from urllib.error import URLError

import pytest

from cyberpowerfull.cli import main
from cyberpowerfull.models import BudgetState, Finding, Phase, Severity
from cyberpowerfull.trace import StepRecord, TraceRecorder, save_trace


class TestHelpAndListing:
    def test_help_is_pentest_only(self, capsys) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        help_text = capsys.readouterr().out
        assert "penetration-testing agent" in help_text
        assert "No chat mode" in help_text
        assert "scope.json" in help_text
        assert "--chat" not in help_text
        assert "recon" in help_text and "validation" in help_text

    def test_version(self, capsys) -> None:
        with pytest.raises(SystemExit):
            main(["--version"])
        assert "cyberpowerfull 3.3.0" in capsys.readouterr().out
        assert "cyberpowerfull 4.0.0" in capsys.readouterr().out

    def test_list_tools(self, capsys) -> None:
        assert main(["--list-tools"]) == 0
        out = capsys.readouterr().out
        assert "tcp_probe" in out
        from cyberpowerfull.tools.registry import tool_names

        assert f"{len(tool_names())} typed tools registered" in out

    def test_list_skills(self, capsys) -> None:
        assert main(["--list-skills"]) == 0
        out = capsys.readouterr().out
        assert "sql_injection" in out
        from cyberpowerfull.skills import skill_names

        assert f"{len(skill_names())} skill packs registered" in out


class TestScopeGating:
    def test_missing_scope_refuses_to_run(self, tmp_path: Path, capsys) -> None:
        code = main(["--scope", str(tmp_path / "nope.json"), "--target", "127.0.0.1"])
        assert code == 3
        assert "refuses to run" in capsys.readouterr().err

    def test_unauthorized_scope_refuses(self, workdir: Path, scope_payload: dict, capsys) -> None:
        scope_payload["authorized"] = False
        path = workdir / "scope.json"
        path.write_text(json.dumps(scope_payload), encoding="utf-8")
        assert main(["--scope", str(path), "--target", "127.0.0.1"]) == 3
        assert "not marked authorized" in capsys.readouterr().err

    def test_out_of_scope_target(self, workdir: Path, capsys) -> None:
        code = main(["--scope", str(workdir / "scope.json"), "--target", "8.8.8.8"])
        assert code == 4
        assert "not inside the authorized scope" in capsys.readouterr().err

    def test_missing_target_uses_usage_error(self, workdir: Path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--scope", str(workdir / "scope.json")])
        assert excinfo.value.code == 2


class TestRenderPrompt:
    def test_renders_system_prompt(self, workdir: Path, capsys) -> None:
        code = main(
            [
                "--render-prompt",
                "--scope",
                str(workdir / "scope.json"),
                "--target",
                "127.0.0.1",
            ]
        )
        assert code == 0
        prompt = capsys.readouterr().out
        assert "root_agent_directive" in prompt
        assert "## Skill: Insecure Direct Object Reference" in prompt
        assert "authorized_scope" in prompt


class TestCheck:
    def test_check_with_replay_backend(self, workdir: Path, capsys) -> None:
        stream = workdir / "decisions.json"
        stream.write_text("[]", encoding="utf-8")
        code = main(
            [
                "--check",
                "--scope",
                str(workdir / "scope.json"),
                "--target",
                "127.0.0.1",
                "--llm",
                f"replay:{stream}",
            ]
        )
        out = capsys.readouterr().out
        assert "scope: ok" in out
        assert "target: in scope" in out
        assert code == 0

    def test_check_reports_unreachable_model(self, workdir: Path, capsys) -> None:
        with mock.patch("cyberpowerfull.brain.llm._local_open", side_effect=URLError("refused")):
            code = main(["--check", "--scope", str(workdir / "scope.json")])
        assert code == 5
        assert "model error" in capsys.readouterr().out


class TestReplay:
    def test_replay_trace(self, workdir: Path, capsys) -> None:
        trace = TraceRecorder(
            target="127.0.0.1",
            engagement="replay",
            model="qwen3:4b",
            backend="ollama",
            scope_fingerprint="abc123",
            run_id="run-replay",
        )
        trace.add_step(
            StepRecord(
                index=1,
                action="delegate",
                phase=Phase.RECON,
                tool="tcp_probe",
                reason="map surface",
                result={"status": "ok"},
            )
        )
        trace.add_findings(
            [
                Finding(
                    title="Open TCP port 8000",
                    severity=Severity.INFO,
                    target="127.0.0.1",
                    endpoint="127.0.0.1:8000",
                    tool="tcp_probe",
                )
            ]
        )
        trace.set_budget(BudgetState(iterations=1))
        path = save_trace(
            trace.finish(stop_reason="agent_terminated"), workdir / "traces" / "latest.json"
        )

        code = main(["--replay", str(path), "--out", str(workdir / "reports")])
        out = capsys.readouterr().out
        assert code == 0
        assert "replayed trace" in out
        assert "step 01" in out
        assert list((workdir / "reports").glob("report-*.md"))

    def test_replay_json_output(self, workdir: Path, capsys) -> None:
        path = save_trace(
            TraceRecorder(
                target="127.0.0.1",
                engagement="replay",
                model="m",
                backend="b",
                scope_fingerprint="f",
            ).finish(stop_reason="agent_terminated"),
            workdir / "trace.json",
        )
        assert main(["--replay", str(path), "--json", "--out", str(workdir / "out")]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["stop_reason"] == "agent_terminated"

    def test_replay_missing_trace(self, tmp_path: Path, capsys) -> None:
        assert main(["--replay", str(tmp_path / "none.json")]) == 1
        assert "trace not found" in capsys.readouterr().err


class TestEndToEndRun:
    """Acceptance test: a real run against a local mock service produces a JSON trace."""

    def test_run_produces_structured_trace(self, workdir: Path, capsys) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def accept_loop() -> None:
            while not stop.is_set():
                try:
                    listener.settimeout(0.2)
                    connection, _ = listener.accept()
                    connection.close()
                except OSError:
                    continue

        thread = threading.Thread(target=accept_loop, daemon=True)
        thread.start()

        stream = workdir / "decisions.json"
        stream.write_text(
            json.dumps(
                {
                    "decisions": [
                        {
                            "tool": "delegate",
                            "args": {
                                "agent": "recon",
                                "tool": "tcp_probe",
                                "args": {"target": "127.0.0.1", "ports": [port]},
                                "reason": "confirm the mock service is reachable",
                            },
                        },
                        {"tool": "terminate", "reason": "surface mapped"},
                    ]
                }
            ),
            encoding="utf-8",
        )

        try:
            code = main(
                [
                    "--scope",
                    str(workdir / "scope.json"),
                    "--target",
                    "127.0.0.1",
                    "--llm",
                    f"replay:{stream}",
                    "--out",
                    str(workdir / "artifacts"),
                    "--trace",
                    str(workdir / "traces" / "latest.json"),
                    "--memory",
                    str(workdir / "artifacts" / "memory.sqlite3"),
                    "--quiet",
                ]
            )
        finally:
            stop.set()
            listener.close()
            thread.join(timeout=2)

        assert code == 0
        trace = json.loads((workdir / "traces" / "latest.json").read_text())
        assert trace["target"] == "127.0.0.1"
        assert trace["stop_reason"] == "agent_terminated"
        assert trace["steps"] and trace["steps"][0]["tool"] == "tcp_probe"
        assert trace["steps"][0]["result"]["status"] == "ok"
        assert trace["steps"][0]["tda"]["level"] in {"low", "medium", "high", "critical"}
        assert trace["findings"], "the mock service must produce at least one finding"
        assert str(port) in json.dumps(trace["findings"])
        assert trace["schema_version"] == "1.0"
        assert list((workdir / "artifacts").glob("report-*.md"))

        out = capsys.readouterr().out
        assert "findings:" in out

    def test_dry_run_executes_nothing(self, workdir: Path, capsys) -> None:
        stream = workdir / "decisions.json"
        stream.write_text(
            json.dumps(
                {
                    "decisions": [
                        {
                            "tool": "delegate",
                            "args": {
                                "agent": "recon",
                                "tool": "tcp_probe",
                                "args": {"target": "127.0.0.1", "ports": [80]},
                            },
                        },
                        {"tool": "terminate"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        code = main(
            [
                "--scope",
                str(workdir / "scope.json"),
                "--target",
                "127.0.0.1",
                "--llm",
                f"replay:{stream}",
                "--dry-run",
                "--out",
                str(workdir / "artifacts"),
                "--trace",
                str(workdir / "trace.json"),
                "--memory",
                str(workdir / "memory.sqlite3"),
                "--quiet",
            ]
        )
        assert code == 0
        trace = json.loads((workdir / "trace.json").read_text())
        assert trace["steps"][0]["result"]["status"] == "skipped"
        assert trace["findings"] == []
        capsys.readouterr()

    def test_inference_failure_exit_code(self, workdir: Path, capsys) -> None:
        with mock.patch("cyberpowerfull.brain.llm._local_open", side_effect=URLError("refused")):
            code = main(
                [
                    "--scope",
                    str(workdir / "scope.json"),
                    "--target",
                    "127.0.0.1",
                    "--out",
                    str(workdir / "artifacts"),
                    "--trace",
                    str(workdir / "trace.json"),
                    "--memory",
                    str(workdir / "memory.sqlite3"),
                    "--max-iterations",
                    "1",
                    "--quiet",
                ]
            )
        assert code == 5  # failure is surfaced even though the trace is saved
        trace = json.loads((workdir / "trace.json").read_text())
        assert trace["stop_reason"] == "inference_failed"
        assert "unreachable" in trace["error"]
        capsys.readouterr()

    def test_json_flag(self, workdir: Path, capsys) -> None:
        stream = workdir / "decisions.json"
        stream.write_text(json.dumps({"decisions": [{"tool": "terminate"}]}), encoding="utf-8")
        code = main(
            [
                "--scope",
                str(workdir / "scope.json"),
                "--target",
                "127.0.0.1",
                "--llm",
                f"replay:{stream}",
                "--json",
                "--out",
                str(workdir / "artifacts"),
                "--trace",
                str(workdir / "trace.json"),
                "--memory",
                str(workdir / "memory.sqlite3"),
                "--quiet",
            ]
        )
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["stop_reason"] == "agent_terminated"


class TestToolchainAndPlaybooks:
    """New 3.0 commands: live inventory, playbooks, agents, local knowledge."""

    def test_list_playbooks(self, capsys) -> None:
        assert main(["--list-playbooks"]) == 0
        out = capsys.readouterr().out
        assert "playbook" in out
        assert "network" in out and "stealth" in out
        assert "playbooks registered" in out

    def test_agents_listing(self, capsys) -> None:
        assert main(["--agents"]) == 0
        out = capsys.readouterr().out
        assert "pentagi" in out and "strix" in out and "sn1per" in out
        assert "external_agents" in out

    def test_toolchain_json_is_machine_readable(self, capsys) -> None:
        assert main(["--toolchain", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert "binaries" in payload
        assert "operating_system" in payload
        assert payload["installed_count"] + payload["missing_count"] == len(payload["binaries"])

    def test_toolchain_table(self, capsys) -> None:
        assert main(["--toolchain"]) == 0
        out = capsys.readouterr().out
        assert "host toolchain (probed live)" in out
        assert "family" in out

    def test_wordlists_json(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr(
            "cyberpowerfull.cli.wordlist_summary",
            lambda kind: [
                {
                    "path": "/x/common.txt",
                    "kind": "discovery",
                    "size_bytes": 1024,
                    "compressed": False,
                }
            ],
        )
        assert main(["--wordlists", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)[0]["path"] == "/x/common.txt"

    def test_missing_templates_exit_6(self, capsys, monkeypatch) -> None:
        from cyberpowerfull.knowledge import KnowledgeUnavailable

        def boom(*args, **kwargs):
            raise KnowledgeUnavailable("nuclei-templates is not installed")

        monkeypatch.setattr("cyberpowerfull.cli.nuclei_template_paths", boom)
        assert main(["--templates"]) == 6
        assert "nuclei-templates" in capsys.readouterr().err

    def test_search_exploits(self, capsys, monkeypatch) -> None:
        from cyberpowerfull.knowledge import ExploitRecord

        monkeypatch.setattr(
            "cyberpowerfull.cli.search_exploit_db",
            lambda query: [
                ExploitRecord(
                    "50383", "Apache RCE", "/x/50383.py", "2021-10-05", "remote", "multiple"
                )
            ],
        )
        assert main(["--search-exploits", "apache"]) == 0
        out = capsys.readouterr().out
        assert "EDB-50383" in out and "Apache RCE" in out

    def test_nse_listing(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr(
            "cyberpowerfull.cli.nmap_script_paths",
            lambda pattern, limit=200: ["http-title.nse"],
        )
        assert main(["--nse", "http"]) == 0
        assert "http-title.nse" in capsys.readouterr().out

    def test_playbook_requires_target(self, workdir: Path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--scope", str(workdir / "scope.json"), "--playbook", "network"])
        assert excinfo.value.code == 2

    def test_unknown_playbook_exit_8(self, workdir: Path, capsys) -> None:
        assert (
            main(
                [
                    "--scope",
                    str(workdir / "scope.json"),
                    "--target",
                    "127.0.0.1",
                    "--playbook",
                    "nuke-all",
                ]
            )
            == 8
        )
        assert "unknown playbook" in capsys.readouterr().err

    def test_playbook_dry_run_end_to_end(self, workdir: Path, capsys) -> None:
        code = main(
            [
                "--scope",
                str(workdir / "scope.json"),
                "--target",
                "127.0.0.1",
                "--playbook",
                "network",
                "--dry-run",
                "--out",
                str(workdir / "artifacts"),
                "--trace",
                str(workdir / "trace.json"),
                "--memory",
                str(workdir / "memory.sqlite3"),
                "--quiet",
            ]
        )
        assert code == 0
        trace = json.loads((workdir / "trace.json").read_text(encoding="utf-8"))
        assert trace["backend"] == "playbook:network"
        assert trace["steps"], "dry-run still records the planned calls"
        assert list((workdir / "artifacts").glob("report-*.md"))

    def test_playbook_refuses_out_of_scope_target(self, workdir: Path) -> None:
        code = main(
            [
                "--scope",
                str(workdir / "scope.json"),
                "--target",
                "8.8.8.8",
                "--playbook",
                "recon",
            ]
        )
        assert code == 4

    def test_doctor_reports_readiness(self, workdir: Path, capsys, monkeypatch) -> None:
        monkeypatch.setattr(
            "cyberpowerfull.brain.llm.build_client",
            lambda spec: type(
                "C",
                (),
                {"health": lambda self: {"ok": True, "backend": "ollama", "endpoint": "local"}},
            )(),
        )
        assert main(["--doctor", "--scope", str(workdir / "scope.json")]) == 0
        out = capsys.readouterr().out
        assert "readiness check" in out
        assert "capabilities:" in out
        assert "agent/strix" in out

    def test_doctor_rejects_remote_endpoint(self, workdir: Path, monkeypatch, capsys) -> None:
        monkeypatch.setenv("CYBERPOWERFULL_LLM_ENDPOINT", "http://api.example.com:11434")
        code = main(["--doctor", "--scope", str(workdir / "scope.json")])
        assert code == 5
        assert "non-local inference endpoint" in capsys.readouterr().err

    def test_endpoint_as_model_is_reported(self, workdir: Path, capsys) -> None:
        code = main(
            [
                "--doctor",
                "--scope",
                str(workdir / "scope.json"),
                "--llm",
                "ollama:http://127.0.0.1:11434",
            ]
        )
        assert code == 5
        assert "is an endpoint, not a model id" in capsys.readouterr().err

    def test_doctor_reports_model_failure(self, workdir: Path, capsys, monkeypatch) -> None:
        monkeypatch.setattr(
            "cyberpowerfull.brain.llm.build_client",
            lambda spec: type(
                "C",
                (),
                {"health": lambda self: {"ok": False, "backend": "ollama", "error": "down"}},
            )(),
        )
        assert main(["--doctor", "--scope", str(workdir / "scope.json")]) == 5
        assert "down" in capsys.readouterr().out
