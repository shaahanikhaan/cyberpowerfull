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


@pytest.fixture
def workdir(tmp_path: Path, scope_payload: dict) -> Path:
    (tmp_path / "scope.json").write_text(json.dumps(scope_payload), encoding="utf-8")
    return tmp_path


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
        assert "cyberpowerfull 2.0.0" in capsys.readouterr().out

    def test_list_tools(self, capsys) -> None:
        assert main(["--list-tools"]) == 0
        out = capsys.readouterr().out
        assert "tcp_probe" in out
        assert "9 typed tools registered" in out

    def test_list_skills(self, capsys) -> None:
        assert main(["--list-skills"]) == 0
        out = capsys.readouterr().out
        assert "sql_injection" in out
        assert "16 skill packs registered" in out


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
        with mock.patch("cyberpowerfull.brain.llm.urlopen", side_effect=URLError("refused")):
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
        with mock.patch("cyberpowerfull.brain.llm.urlopen", side_effect=URLError("refused")):
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
        assert code == 0  # run itself completed with stop_reason=inference_failed
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
