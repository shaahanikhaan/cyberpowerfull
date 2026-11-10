"""The bash toolkit behaves like a product: scope-gated, offline, scriptable."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BASH_DIR = REPO_ROOT / "tools" / "bash"


class _VulnerableHandler(BaseHTTPRequestHandler):
    """A deliberately banner-lying lab service so correlation has input."""

    server_version = "Apache/2.4.49"

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        body = b"<html>lab</html>"
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def lab_server() -> Iterator[int]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def env(tmp_path: Path) -> dict[str, str]:
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "engagement": "bash-toolkit",
                "authorized": True,
                "authorization_ref": "test-sow",
                "targets": ["127.0.0.1"],
                "domains": ["lab.test"],
                "exclude": [],
                "allowed_phases": ["recon", "scanning", "validation"],
                "max_rps": 5,
                "expires": "2099-12-31",
                "contact": "tester@lab.test",
            }
        ),
        encoding="utf-8",
    )
    return {
        **os.environ,
        "CPF_PYTHON": sys.executable,
        "CPF_ARTIFACTS": str(tmp_path / "artifacts"),
        "CPF_INTEL_STORE": str(tmp_path / "intel.sqlite3"),
        "SCOPE": str(scope),
        "OUT": str(tmp_path / "out"),
    }


def _run(script: str, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(BASH_DIR / script), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )


def test_scripts_are_executable() -> None:
    for name in ("cve_hunt.sh", "payload_run.sh", "scan_cycle.sh"):
        path = BASH_DIR / name
        assert path.exists(), name
        assert os.access(path, os.X_OK), name


def test_scope_is_mandatory(env: dict[str, str]) -> None:
    result = _run("cve_hunt.sh", "--target", "127.0.0.1", env=env)
    assert result.returncode == 2
    assert "scope" in result.stderr.lower()

    missing = _run("cve_hunt.sh", "--scope", "/nonexistent/scope.json", "--target", "x", env=env)
    assert missing.returncode == 2
    assert "not found" in missing.stderr


def test_out_of_scope_target_is_refused(env: dict[str, str]) -> None:
    result = _run("cve_hunt.sh", "--scope", env["SCOPE"], "--target", "example.org", env=env)
    assert result.returncode != 0
    assert "scope" in (result.stderr + result.stdout).lower()
    assert not Path(env["OUT"]).exists()


def test_cve_hunt_finds_candidates_for_a_lab_banner(env: dict[str, str], lab_server: int) -> None:
    out_dir = Path(env["OUT"])
    result = _run(
        "cve_hunt.sh",
        "--scope",
        env["SCOPE"],
        "--target",
        "127.0.0.1",
        "--ports",
        str(lab_server),
        "--out",
        str(out_dir),
        env=env,
    )
    assert "scanning" in result.stderr
    assert result.returncode == 1, result.stderr + result.stdout
    findings = json.loads(next(out_dir.glob("*.findings.json")).read_text(encoding="utf-8"))
    cves = {item["cve"] for item in findings}
    assert "CVE-2021-41773" in cves
    assert all(item["verified"] is False for item in findings)

    components = json.loads(next(out_dir.glob("*.components.json")).read_text(encoding="utf-8"))
    assert components["count"] == 1
    assert components["components"][0]["product"].lower() == "apache"


def test_cve_hunt_json_mode(env: dict[str, str], lab_server: int) -> None:
    result = _run(
        "cve_hunt.sh",
        "--scope",
        env["SCOPE"],
        "--target",
        "127.0.0.1",
        "--ports",
        str(lab_server),
        "--out",
        env["OUT"],
        "--json",
        env=env,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload and payload[0]["tool"] == "cve_correlate"


def test_payload_run_dry_run_and_send(env: dict[str, str], lab_server: int) -> None:
    url = f"http://127.0.0.1:{lab_server}/search"
    dry = _run(
        "payload_run.sh",
        "--scope",
        env["SCOPE"],
        "--url",
        url,
        "--skill",
        "xss",
        "--out",
        env["OUT"],
        env=env,
    )
    assert dry.returncode == 0, dry.stderr
    assert "dry run" in dry.stderr
    plan = list(Path(env["OUT"]).glob("xss-*.json"))
    assert plan, "the payload plan must be written to disk"
    assert json.loads(plan[0].read_text(encoding="utf-8"))

    sent = _run(
        "payload_run.sh",
        "--scope",
        env["SCOPE"],
        "--url",
        url,
        "--skill",
        "xss",
        "--out",
        env["OUT"],
        "--send",
        env=env,
    )
    assert sent.returncode == 0, sent.stderr + sent.stdout
    results = list(Path(env["OUT"]).glob("*.result.json"))
    assert results
    payload = json.loads(results[0].read_text(encoding="utf-8"))
    assert payload["payload"] == "xss_html_script"
    assert payload["status"] == "ok"


def test_payload_run_out_of_scope_url(env: dict[str, str]) -> None:
    result = _run(
        "payload_run.sh",
        "--scope",
        env["SCOPE"],
        "--url",
        "http://example.org/",
        "--skill",
        "xss",
        "--out",
        env["OUT"],
        env=env,
    )
    assert result.returncode != 0
    assert "scope" in (result.stderr + result.stdout).lower()


def test_scan_cycle_writes_a_summary(env: dict[str, str], lab_server: int) -> None:
    out_dir = Path(env["OUT"])
    result = _run(
        "scan_cycle.sh",
        "--scope",
        env["SCOPE"],
        "--target",
        "127.0.0.1",
        "--ports",
        str(lab_server),
        "--out",
        str(out_dir),
        env=env,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    summaries = list(out_dir.glob("*/summary.md"))
    assert summaries, result.stdout
    text = summaries[0].read_text(encoding="utf-8")
    assert "Offline scan summary" in text
    assert "CVE candidates" in text
