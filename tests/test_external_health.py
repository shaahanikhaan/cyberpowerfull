"""External-agent health: env passthrough, timeouts, install hints, live proofs.

Regression tests for the systemic failures behind "strix / pentagi / sn1per
don't work": subprocess sanitization stripped the credentials those tools
authenticate with, and the 300s default worker policy SIGKILLed every tool
declaring a longer ceiling.
"""

from __future__ import annotations

import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cyberpowerfull.brain.orchestrator import DelegationRequest, WorkerAgent
from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.scope import Scope
from cyberpowerfull.tools.base import ToolResult, ToolStatus


def _fake_binary(tmp_path: Path, name: str, body: str) -> None:
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    script.chmod(0o755)


class TestEnvPassthrough:
    def test_sanitized_env_keep_wins_over_deny_rules(self) -> None:
        clean = ToolPolicy().sanitized_env(
            {
                "LLM_API_KEY": "sk-test",
                "OPENAI_API_KEY": "sk-oai",
                "AWS_SECRET_ACCESS_KEY": "aws-secret",
                "PATH": "/usr/bin",
            },
            keep=("LLM_API_KEY",),
        )
        assert clean == {"LLM_API_KEY": "sk-test", "PATH": "/usr/bin"}

    def test_passthrough_declared(self) -> None:
        from cyberpowerfull.tools.prowler import ProwlerTool
        from cyberpowerfull.tools.strix import StrixTool
        from cyberpowerfull.tools.uncover import _ENGINE_ENV, UncoverTool

        assert set(StrixTool.env_passthrough) == {"STRIX_LLM", "LLM_API_KEY", "OPENAI_API_KEY"}
        assert {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"}.issubset(
            ProwlerTool.env_passthrough
        )
        assert {"AZURE_CLIENT_ID", "GOOGLE_APPLICATION_CREDENTIALS"}.issubset(
            ProwlerTool.env_passthrough
        )
        wanted = {var for names in _ENGINE_ENV.values() for var in names}
        assert wanted.issubset(set(UncoverTool.env_passthrough))
        assert "SHODAN_API_KEY" in UncoverTool.env_passthrough

    def test_strix_subprocess_receives_model_keys(self, tmp_path: Path, monkeypatch) -> None:
        from cyberpowerfull.tools.strix import StrixTool

        _fake_binary(
            tmp_path,
            "strix",
            'echo "LLM=${LLM_API_KEY:-absent} OPENAI=${OPENAI_API_KEY:-absent} '
            'AWS=${AWS_SECRET_ACCESS_KEY:-absent}"',
        )
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        monkeypatch.setenv("LLM_API_KEY", "sk-test")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-oai")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
        result = StrixTool().run({"target": "https://lab.test"})
        assert result.status is ToolStatus.OK
        assert "LLM=sk-test OPENAI=sk-oai AWS=absent" in (result.stdout or "")

    def test_uncover_subprocess_receives_engine_keys(self, tmp_path: Path, monkeypatch) -> None:
        from cyberpowerfull.tools.uncover import UncoverTool

        _fake_binary(
            tmp_path,
            "uncover",
            'echo "SHODAN=${SHODAN_API_KEY:-absent} AWS=${AWS_PROFILE:-absent}"',
        )
        monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
        monkeypatch.setenv("SHODAN_API_KEY", "shodan-test")
        monkeypatch.setenv("AWS_PROFILE", "prod")
        result = UncoverTool().run({"target": "lab.test", "engines": ["shodan"]})
        assert result.status is ToolStatus.OK
        assert "SHODAN=shodan-test AWS=absent" in (result.stdout or "")

    def test_prowler_missing_creds_returns_missing(self, monkeypatch) -> None:
        from cyberpowerfull.tools.prowler import ProwlerTool

        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"):
            monkeypatch.delenv(name, raising=False)
        result = ProwlerTool().run({"target": "aws-account", "provider": "aws"})
        assert result.status is ToolStatus.MISSING
        assert "ambient credentials" in (result.error or "")


class TestWorkerTimeout:
    def test_execute_honors_tool_timeout_ceiling(self, scope: Scope, monkeypatch) -> None:
        from cyberpowerfull.tools.registry import get_tool

        captured: dict[str, float] = {}
        tool = get_tool("enum4linux")
        assert tool.timeout_s > 300

        def _spy(raw_args, *, dry_run=False, policy=None, announce=None):
            captured["timeout_s"] = policy.timeout_s
            return ToolResult(tool="enum4linux", status=ToolStatus.OK)

        monkeypatch.setattr(tool, "run", _spy)
        worker = WorkerAgent("scan", scope=scope)
        worker.execute(
            DelegationRequest(agent="scan", tool="enum4linux", args={"target": "127.0.0.1"}),
            dry_run=True,
        )
        assert captured["timeout_s"] == tool.timeout_s

    def test_explicit_caller_timeout_still_caps(self, scope: Scope, monkeypatch) -> None:
        from cyberpowerfull.tools.registry import get_tool

        captured: dict[str, float] = {}
        tool = get_tool("enum4linux")

        def _spy(raw_args, *, dry_run=False, policy=None, announce=None):
            captured["timeout_s"] = policy.timeout_s
            return ToolResult(tool="enum4linux", status=ToolStatus.OK)

        monkeypatch.setattr(tool, "run", _spy)
        worker = WorkerAgent("scan", scope=scope)
        worker.execute(
            DelegationRequest(agent="scan", tool="enum4linux", args={"target": "127.0.0.1"}),
            dry_run=True,
            timeout_s=60,
        )
        assert captured["timeout_s"] == 60


class TestMissingHints:
    def test_strix_missing_error_carries_install_hint(self, monkeypatch) -> None:
        from cyberpowerfull.tools.strix import StrixTool

        monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: None)
        result = StrixTool().run({"target": "https://lab.test"})
        assert result.status is ToolStatus.MISSING
        assert "pipx install strix-agent" in (result.error or "")

    def test_sn1per_hint_found_via_binary_name(self, monkeypatch) -> None:
        from cyberpowerfull.tools.sn1per import Sn1perTool

        monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: None)
        result = Sn1perTool().run({"target": "127.0.0.1"})
        assert result.status is ToolStatus.MISSING
        assert "Sn1per" in (result.error or "")


class _PentagiHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        query = str(payload.get("query", ""))
        if "createFlow" in query:
            data = {"createFlow": {"id": "flow-1", "title": "t", "status": "running"}}
        elif "tasks(" in query:
            data = {
                "tasks": [
                    {
                        "id": "task-1",
                        "title": "web scan",
                        "status": "done",
                        "result": "High severity reflected XSS at /search",
                    }
                ]
            }
        else:
            data = {"flow": {"id": "flow-1", "title": "t", "status": "finished"}}
        body = json.dumps({"data": data}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


class TestPentagiLive:
    def test_flow_completes_against_fake_server(self, monkeypatch) -> None:
        from cyberpowerfull.tools.pentagi import PentagiTool

        server = HTTPServer(("127.0.0.1", 0), _PentagiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            monkeypatch.setenv("PENTAGI_URL", f"http://127.0.0.1:{port}")
            result = PentagiTool().run(
                {"target": "https://lab.test", "poll_s": 1, "max_wait_s": 30}
            )
        finally:
            server.shutdown()
            thread.join(timeout=10)
        assert result.status is ToolStatus.OK
        assert any("XSS" in finding.title for finding in result.findings)
