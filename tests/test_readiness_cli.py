"""End-to-end readiness checks using loopback-only services and test doubles."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import threading
from contextlib import contextmanager
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.error import URLError

import pytest

from cyberpowerfull.brain.llm import LlamaCppClient, build_client
from cyberpowerfull.brain.orchestrator import Orchestrator
from cyberpowerfull.cli import main
from cyberpowerfull.config import RunConfig
from cyberpowerfull.errors import LLMError
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.models import Decision, Finding, Phase
from tests.conftest import FakeLLM
from tests.test_orchestrator import StubTool, delegate


def stream(path: Path, decisions: list[dict]) -> Path:
    path.write_text(json.dumps({"decisions": decisions}), encoding="utf-8")
    return path


def run_args(tmp_path: Path, scope_file: Path, decision_file: Path) -> list[str]:
    return [
        "--scope",
        str(scope_file),
        "--target",
        "127.0.0.1",
        "--llm",
        f"replay:{decision_file}",
        "--out",
        str(tmp_path / "out"),
        "--trace",
        str(tmp_path / "trace.json"),
        "--memory",
        str(tmp_path / "memory.sqlite3"),
    ]


@contextmanager
def local_server(handler: type[BaseHTTPRequestHandler]):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.parametrize(
    ("decisions", "expected"),
    [
        ([{"tool": "nmap", "args": {"target": "127.0.0.1"}}], 7),
        (
            [
                {
                    "tool": "delegate",
                    "args": {"agent": "recon", "tool": "tcp_probe", "args": {"target": "8.8.8.8"}},
                },
                {"tool": "terminate"},
            ],
            7,
        ),
        (
            [
                {
                    "tool": "delegate",
                    "args": {
                        "agent": "recon",
                        "tool": "tcp_probe",
                        "args": {"target": "127.0.0.1", "ports": [70000]},
                    },
                },
                {"tool": "terminate"},
            ],
            6,
        ),
        ([{"tool": "delegate", "args": {"agent": "recon"}}, {"tool": "terminate"}], 6),
    ],
)
def test_failed_and_blocked_actions_return_nonzero_and_keep_trace(
    tmp_path: Path, scope_file: Path, decisions: list[dict], expected: int, capsys
) -> None:
    path = stream(tmp_path / "decisions.json", decisions)
    assert main([*run_args(tmp_path, scope_file, path), "--quiet"]) == expected
    payload = json.loads((tmp_path / "trace.json").read_text())
    assert payload["steps"]
    assert list((tmp_path / "out").glob("report-*.md"))
    capsys.readouterr()


def test_inference_failure_returns_five_and_saves_trace(
    tmp_path: Path, scope_file: Path, capsys
) -> None:
    path = stream(tmp_path / "decisions.json", [])
    args = run_args(tmp_path, scope_file, path)
    args[args.index("--llm") + 1] = "llamacpp:lab-model"
    with mock.patch("cyberpowerfull.brain.llm._local_open", side_effect=URLError("refused")):
        assert main([*args, "--quiet"]) == 5
    assert json.loads((tmp_path / "trace.json").read_text())["stop_reason"] == "inference_failed"
    capsys.readouterr()


@pytest.mark.parametrize("flag", ["--max-iterations", "--max-tokens", "--max-seconds"])
def test_zero_budget_is_usage_error(tmp_path: Path, scope_file: Path, flag: str) -> None:
    path = stream(tmp_path / "decisions.json", [{"tool": "terminate"}])
    with pytest.raises(SystemExit) as exc:
        main([*run_args(tmp_path, scope_file, path), flag, "0"])
    assert exc.value.code == 2


def test_cli_preserves_original_target_url(tmp_path: Path, scope_file: Path, capsys) -> None:
    path = stream(tmp_path / "decisions.json", [{"tool": "terminate"}])
    args = run_args(tmp_path, scope_file, path)
    args[args.index("--target") + 1] = "http://127.0.0.1:8000/api?q=1"
    assert main([*args, "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["target"] == "http://127.0.0.1:8000/api?q=1"
    assert "[01/12]" in captured.err  # progress never pollutes JSON stdout


def test_repeated_runs_share_database_without_sharing_evidence(
    tmp_path: Path, scope_file: Path, capsys
) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        path = stream(
            tmp_path / "decisions.json",
            [
                {
                    "tool": "delegate",
                    "args": {
                        "agent": "recon",
                        "tool": "tcp_probe",
                        "args": {"target": "127.0.0.1", "ports": [port]},
                    },
                },
                {"tool": "terminate"},
            ],
        )
        traces = []
        for _ in range(2):
            assert main([*run_args(tmp_path, scope_file, path), "--json"]) == 0
            captured = capsys.readouterr()
            traces.append(json.loads(captured.out))
            assert "[01/12]" in captured.err
    assert traces[0]["run_id"] != traces[1]["run_id"]
    assert len(traces[0]["findings"]) == len(traces[1]["findings"]) == 1
    assert traces[1]["memory_stats"]["findings"] == 1
    with sqlite3.connect(tmp_path / "memory.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
    if os.name == "posix":
        paths = [
            tmp_path / "memory.sqlite3",
            tmp_path / "trace.json",
            *list((tmp_path / "out").iterdir()),
        ]
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in paths)


def test_memory_read_methods_are_run_isolated(tmp_path: Path) -> None:
    path = tmp_path / "shared.sqlite3"
    with MemoryStore(path, run_id="first") as first:
        first.append_finding(Finding(title="first only", target="127.0.0.1"))
        first.append_step(step=1, phase=Phase.RECON, tool="nmap")
        first.record_attempt(
            tool="nmap", args={"target": "127.0.0.1"}, target="127.0.0.1", ok=False, error="failed"
        )
    with MemoryStore(path, run_id="second") as second:
        assert second.findings() == []
        assert second.steps() == []
        assert second.negative_cache_hit("nmap", {"target": "127.0.0.1"}) is None
        assert second.stats()["attempts"] == 0
        assert "first only" not in second.digest()
    with MemoryStore(path, run_id="first") as first:
        assert len(first.findings()) == 1
        assert first.consecutive_failures("nmap", {"target": "127.0.0.1"}) == 1


def test_dry_run_never_resolves_or_connects(tmp_path: Path, scope_file: Path, capsys) -> None:
    path = stream(
        tmp_path / "decisions.json",
        [
            {
                "tool": "delegate",
                "args": {
                    "agent": "recon",
                    "tool": "tcp_probe",
                    "args": {"target": "127.0.0.1", "ports": [80]},
                },
            },
            {"tool": "terminate"},
        ],
    )
    with (
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.getaddrinfo") as resolve,
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.create_connection") as connect,
    ):
        assert main([*run_args(tmp_path, scope_file, path), "--dry-run", "--quiet"]) == 0
    resolve.assert_not_called()
    connect.assert_not_called()
    assert (
        json.loads((tmp_path / "trace.json").read_text())["steps"][0]["result"]["status"]
        == "skipped"
    )
    capsys.readouterr()


def test_replay_rejects_unsafe_run_id_and_invalid_schema(tmp_path: Path, capsys) -> None:
    path = tmp_path / "untrusted.json"
    path.write_text(json.dumps({"run_id": "x/../../outside", "schema_version": "1.0"}))
    assert main(["--replay", str(path), "--out", str(tmp_path / "out")]) == 1
    assert "validation" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
    path.write_text(json.dumps({"run_id": "safe", "schema_version": "99.0"}))
    assert main(["--replay", str(path), "--out", str(tmp_path / "out")]) == 1
    assert "unsupported trace schema" in capsys.readouterr().err


def test_cli_respects_replay_backend_environment(
    tmp_path: Path, scope_file: Path, monkeypatch, capsys
) -> None:
    path = stream(tmp_path / "decisions.json", [{"tool": "terminate"}])
    monkeypatch.setenv("CYBERPOWERFULL_LLM", f"replay:{path}")
    args = run_args(tmp_path, scope_file, path)
    index = args.index("--llm")
    del args[index : index + 2]
    assert main([*args, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["backend"] == "replay"


def test_llamacpp_alias_and_custom_endpoint_are_honored(monkeypatch) -> None:
    monkeypatch.setenv("CYBERPOWERFULL_LLM_ENDPOINT", "http://127.0.0.1:9999")
    client = build_client("llama.cpp:my-model")
    assert isinstance(client, LlamaCppClient)
    assert client.endpoint == "http://127.0.0.1:9999"
    assert client.model == "my-model"


def test_llamacpp_health_rejects_an_invalid_model_list() -> None:
    with mock.patch("cyberpowerfull.brain.llm._get_json", return_value={"data": "nope"}):
        health = LlamaCppClient().health()
    assert health["ok"] is False
    assert "invalid llama.cpp model list" in health["error"]


def test_invalid_model_output_is_retried() -> None:
    responses = [
        {"choices": [{"message": {"content": "not JSON"}}]},
        {"choices": [{"message": {"content": '{"tool":"terminate"}'}}]},
    ]
    with mock.patch("cyberpowerfull.brain.llm._post_json", side_effect=responses) as post:
        decision = LlamaCppClient(max_retries=2).decide("system", "state")
    assert decision.tool == "terminate"
    assert post.call_count == 2
    assert post.call_args.args[1]["response_format"] == {"type": "json_object"}


def test_loopback_model_redirect_is_never_followed() -> None:
    escaped: list[str] = []

    class Sink(QuietHandler):
        def do_POST(self):
            escaped.append(self.path)
            self.reply({"choices": [{"message": {"content": '{"tool":"terminate"}'}}]})

    with local_server(Sink) as sink_port:

        class Redirect(QuietHandler):
            def do_POST(self):
                self.send_response(307)
                self.send_header("Location", f"http://127.0.0.1:{sink_port}/leak")
                self.end_headers()

        with local_server(Redirect) as redirect_port:
            client = LlamaCppClient(endpoint=f"http://127.0.0.1:{redirect_port}", max_retries=1)
            with pytest.raises(LLMError, match="HTTP error 307"):
                client.decide("private scope", "private evidence")
    assert escaped == []


def test_model_requests_ignore_proxy_environment(monkeypatch) -> None:
    proxy_hits: list[str] = []
    model_hits: list[str] = []

    class Proxy(QuietHandler):
        def do_GET(self):
            proxy_hits.append(self.path)
            self.reply({"models": []})

    class Model(QuietHandler):
        def do_GET(self):
            model_hits.append(self.path)
            self.reply({"data": [{"id": "lab-model"}]})

    with local_server(Proxy) as proxy_port, local_server(Model) as model_port:
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy_port}")
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy_port}")
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        assert LlamaCppClient(endpoint=f"http://127.0.0.1:{model_port}").health()["ok"]
    assert model_hits == ["/v1/models"]
    assert proxy_hits == []


def test_real_http_model_and_tcp_service_complete_run(
    tmp_path: Path, scope_file: Path, monkeypatch, capsys
) -> None:
    requests: list[dict] = []
    port_holder: list[int] = []

    class Model(QuietHandler):
        def do_GET(self):
            self.reply({"data": [{"id": "lab-model"}]})

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(payload)
            if len(requests) == 1:
                decision = {
                    "tool": "delegate",
                    "args": {
                        "agent": "recon",
                        "tool": "tcp_probe",
                        "args": {"target": "127.0.0.1", "ports": [port_holder[0]]},
                    },
                }
            else:
                decision = {"tool": "terminate", "reason": "lab check complete"}
            self.reply({"choices": [{"message": {"content": json.dumps(decision)}}]})

    with local_server(Model) as port:
        port_holder.append(port)
        monkeypatch.setenv("CYBERPOWERFULL_LLM_ENDPOINT", f"http://127.0.0.1:{port}")
        monkeypatch.delenv("CYBERPOWERFULL_LLM", raising=False)
        path = stream(tmp_path / "unused.json", [])
        args = run_args(tmp_path, scope_file, path)
        args[args.index("--llm") + 1] = "llamacpp:lab-model"
        assert main([*args, "--json"]) == 0
        trace = json.loads(capsys.readouterr().out)
    assert len(requests) == 2
    assert requests[0]["response_format"] == {"type": "json_object"}
    assert requests[0]["stream"] is False
    assert trace["stop_reason"] == "agent_terminated"
    assert trace["steps"][0]["result"]["status"] == "ok"
    assert trace["findings"] and str(port) in trace["findings"][0]["endpoint"]


def test_budget_is_checked_before_using_decision(scope) -> None:
    stub = StubTool([])
    memory = MemoryStore(":memory:", run_id="budget")
    orchestrator = Orchestrator(
        scope=scope,
        config=RunConfig(max_tokens=50),
        client=FakeLLM([delegate()]),
        memory=memory,
        target="127.0.0.1",
        tools={"tcp_probe": stub},
    )
    with mock.patch("cyberpowerfull.brain.orchestrator.estimate_tokens", side_effect=[40, 5, 20]):
        result = orchestrator.run()
    assert result.stop_reason == "budget_exhausted:tokens"
    assert result.trace.steps[0].action == "budget_exhausted"
    assert stub.calls == []
    memory.close()


def test_no_tool_runs_when_inference_exceeds_deadline(scope) -> None:
    clock = [100.0]
    stub = StubTool([])

    class LateModel(FakeLLM):
        def decide(self, system_prompt, step_prompt, *, step=0):
            clock[0] = 102.0
            return Decision.model_validate(delegate() | {"step": step})

    memory = MemoryStore(":memory:", run_id="deadline")
    orchestrator = Orchestrator(
        scope=scope,
        config=RunConfig(max_seconds=1),
        client=LateModel(),
        memory=memory,
        target="127.0.0.1",
        tools={"tcp_probe": stub},
    )
    with mock.patch(
        "cyberpowerfull.brain.orchestrator.time.monotonic", side_effect=lambda: clock[0]
    ):
        result = orchestrator.run()
    assert result.stop_reason == "budget_exhausted:seconds"
    assert stub.calls == []
    memory.close()


def test_render_prompt_preserves_target_url(scope_file: Path, capsys) -> None:
    target = "http://127.0.0.1:8000/search?q=test"
    assert main(["--render-prompt", "--scope", str(scope_file), "--target", target]) == 0
    assert target in capsys.readouterr().out


@pytest.mark.parametrize("error", [ConnectionResetError("reset"), IncompleteRead(b"x")])
def test_interrupted_model_response_is_recorded_as_inference_failure(
    tmp_path: Path, scope_file: Path, capsys, error: Exception
) -> None:
    path = stream(tmp_path / "decisions.json", [])
    args = run_args(tmp_path, scope_file, path)
    args[args.index("--llm") + 1] = "llamacpp:lab-model"
    response = mock.MagicMock()
    response.__enter__.return_value = response
    response.read.side_effect = error
    with mock.patch("cyberpowerfull.brain.llm._local_open", return_value=response):
        assert main([*args, "--quiet"]) == 5
    assert json.loads((tmp_path / "trace.json").read_text())["stop_reason"] == "inference_failed"
    assert list((tmp_path / "out").glob("report-*.md"))
    capsys.readouterr()


def test_help_and_version_survive_invalid_environment_budgets(monkeypatch, capsys) -> None:
    monkeypatch.setenv("CYBERPOWERFULL_MAX_TOKENS", "not-a-number")
    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    assert "usage: cyberpowerfull" in capsys.readouterr().out
    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == 0
    assert "cyberpowerfull" in capsys.readouterr().out


def test_cli_budget_override_wins_over_invalid_environment(
    tmp_path: Path, scope_file: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("CYBERPOWERFULL_MAX_TOKENS", "not-a-number")
    path = stream(tmp_path / "decisions.json", [{"tool": "terminate"}])
    args = run_args(tmp_path, scope_file, path)
    assert main([*args, "--max-tokens", "500", "--json"]) == 0
    trace = json.loads(capsys.readouterr().out)
    assert trace["budget"]["max_tokens"] == 500


def test_unused_invalid_environment_budget_is_reported_when_needed(
    tmp_path: Path, scope_file: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("CYBERPOWERFULL_MAX_SECONDS", "-5")
    path = stream(tmp_path / "decisions.json", [{"tool": "terminate"}])
    args = run_args(tmp_path, scope_file, path)
    with pytest.raises(SystemExit) as exited:
        main(args)
    assert exited.value.code == 2
    assert "CYBERPOWERFULL_MAX_SECONDS" in capsys.readouterr().err
