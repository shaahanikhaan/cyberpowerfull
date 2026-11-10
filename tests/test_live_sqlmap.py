"""Opt-in SQLMap integration: every target is an ephemeral, self-owned loopback lab.

Run with CYBERPOWERFULL_RUN_SQLMAP_TEST=1 and a real ``sqlmap`` on PATH. Normal
unit/CI runs do not install or execute third-party scanners.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from cyberpowerfull.cli import main

pytestmark = pytest.mark.skipif(
    os.environ.get("CYBERPOWERFULL_RUN_SQLMAP_TEST") != "1" or not shutil.which("sqlmap"),
    reason="set CYBERPOWERFULL_RUN_SQLMAP_TEST=1 and install sqlmap to run the loopback lab",
)


@contextmanager
def _lab(vulnerable: bool):
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

        def do_GET(self) -> None:
            requests.append(self.path)
            text = "no database is attached"
            if vulnerable:
                # Deliberately vulnerable fixture. The database is recreated in
                # memory for every request and contains only this dummy row.
                value = parse_qs(urlsplit(self.path).query).get("id", ["1"])[0]
                with sqlite3.connect(":memory:") as database:
                    database.execute("CREATE TABLE products (id INTEGER, name TEXT)")
                    database.execute("INSERT INTO products VALUES (1, 'test product')")
                    try:
                        rows = database.execute(
                            "SELECT name FROM products WHERE id = " + value
                        ).fetchall()
                        text = "product found: " + rows[0][0] if rows else "product not found"
                    except sqlite3.Error:
                        text = "database error"
            body = f"<html><body>Local training service: {text}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _run_scan(tmp_path: Path, port: int, vulnerable: bool, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    target = f"http://127.0.0.1:{port}/?id=1"
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "engagement": "self-owned-sqlmap-test",
                "authorized": True,
                "targets": ["127.0.0.1"],
                "allowed_phases": ["validation"],
                "max_rps": 20,
            }
        ),
        encoding="utf-8",
    )
    tool_args = {
        "target": target,
        "technique": "B" if vulnerable else "E",
        "parameter": "id",
        "level": 1,
        "risk": 1,
        "timeout_s": 10,
    }
    if vulnerable:
        tool_args["dbms"] = "SQLite"
    stream = tmp_path / "decisions.json"
    stream.write_text(
        json.dumps(
            {
                "decisions": [
                    {
                        "tool": "delegate",
                        "args": {"agent": "validate", "tool": "sqlmap", "args": tool_args},
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
            str(scope),
            "--target",
            target,
            "--llm",
            f"replay:{stream}",
            "--max-seconds",
            "60",
            "--out",
            str(tmp_path / "out"),
            "--trace",
            str(tmp_path / "trace.json"),
            "--memory",
            str(tmp_path / "memory.sqlite3"),
            "--quiet",
            "--json",
        ]
    )
    trace = json.loads(capsys.readouterr().out)
    assert list((tmp_path / "out").glob("report-*.md"))
    return code, trace


@pytest.mark.parametrize("vulnerable", [False, True], ids=["clean", "injection"])
def test_real_sqlmap_against_loopback_fixture(tmp_path: Path, capsys, monkeypatch, vulnerable):
    with _lab(vulnerable) as (port, requests):
        code, trace = _run_scan(tmp_path, port, vulnerable, capsys, monkeypatch)
    assert requests
    assert code == 0
    assert trace["steps"][0]["result"]["status"] == "ok"
    if vulnerable:
        assert any(f["verified"] and f["cwe"] == "CWE-89" for f in trace["findings"])
    else:
        assert trace["findings"] == []


def test_real_sqlmap_connection_failure_is_not_success(tmp_path: Path, capsys, monkeypatch):
    # Reserve a loopback port but do not listen, giving a deterministic refusal.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        code, trace = _run_scan(tmp_path, reserved.getsockname()[1], False, capsys, monkeypatch)
    assert code == 6
    result = trace["steps"][0]["result"]
    assert result["status"] == "error"
    assert "exit code" in result["error"]
    if result["exit_code"] == 0:
        assert "despite exit code 0" in result["error"]
    assert trace["findings"] == []
