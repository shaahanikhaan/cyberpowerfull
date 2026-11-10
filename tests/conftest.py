"""Shared fixtures: scopes, fake inference clients, and tool output samples."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from cyberpowerfull.brain.llm import LLMClient
from cyberpowerfull.models import Decision
from cyberpowerfull.scope import Scope

SCOPE_PAYLOAD = {
    "engagement": "test-engagement",
    "authorized": True,
    "authorization_ref": "unit-test-sow",
    "targets": ["127.0.0.1", "localhost"],
    "domains": ["lab.test"],
    "exclude": ["169.254.169.254"],
    "allowed_phases": ["recon", "scanning", "validation"],
    "max_rps": 5,
    "expires": "2099-12-31",
    "contact": "tester@lab.test",
}


@pytest.fixture
def scope_payload() -> dict:
    return json.loads(json.dumps(SCOPE_PAYLOAD))


@pytest.fixture
def scope_file(tmp_path: Path, scope_payload: dict) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(scope_payload), encoding="utf-8")
    return path


@pytest.fixture
def workdir(tmp_path: Path, scope_payload: dict) -> Path:
    """A temp directory holding a valid, authorized scope.json."""
    (tmp_path / "scope.json").write_text(json.dumps(scope_payload), encoding="utf-8")
    return tmp_path


@pytest.fixture
def scope() -> Scope:
    return Scope.model_validate(SCOPE_PAYLOAD)


class FakeLLM(LLMClient):
    """Test double for the local model. Never used outside tests."""

    backend = "fake"
    model = "fake-model"

    def __init__(self, decisions: list[dict] | None = None) -> None:
        self.decisions = list(decisions or [])
        self.calls: list[tuple[str, str]] = []

    def decide(self, system_prompt: str, step_prompt: str, *, step: int = 0) -> Decision:
        self.calls.append((system_prompt, step_prompt))
        if not self.decisions:
            return Decision(step=step, tool="terminate", reason="script exhausted", done=True)
        payload = dict(self.decisions.pop(0))
        payload["step"] = step
        return Decision.model_validate(payload)

    def health(self) -> dict:
        return {"ok": True, "backend": self.backend, "model": self.model}


class FailingLLM(LLMClient):
    backend = "fake"
    model = "fake-model"

    def decide(self, system_prompt: str, step_prompt: str, *, step: int = 0) -> Decision:
        from cyberpowerfull.errors import LLMError

        raise LLMError("model server unreachable")

    def health(self) -> dict:
        return {"ok": False, "backend": self.backend, "error": "unreachable"}


def completed(
    stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["mock"], returncode=returncode, stdout=stdout, stderr=stderr
    )


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1">
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
    <hostscript>
      <script id="http-title" output="Lab Landing Page"/>
    </hostscript>
  </host>
</nmaprun>
"""

HTTPX_JSONL = "\n".join(
    [
        json.dumps(
            {
                "url": "http://127.0.0.1:8080/",
                "status_code": 403,
                "title": "Admin",
                "tech": ["Nginx", "PHP"],
                "webserver": "nginx/1.24.0",
                "content_length": 512,
            }
        ),
        "not json at all",
        json.dumps({"url": "http://127.0.0.1:8080/health", "status_code": 200, "title": "ok"}),
    ]
)

NUCLEI_JSONL = json.dumps(
    {
        "template-id": "CVE-2021-41773",
        "info": {
            "name": "Apache Path Traversal",
            "severity": "critical",
            "classification": {
                "cwe-id": ["cwe-22"],
                "cve-id": ["cve-2021-41773"],
                "cvss-score": 7.5,
            },
        },
        "matched-at": "http://127.0.0.1/cgi-bin/.%2e/.%2e/etc/passwd",
        "matcher-name": "word",
        "extracted-results": ["root:x:0:0"],
    }
)

FFUF_JSON = json.dumps(
    {
        "results": [
            {
                "input": {"FUZZ": "admin"},
                "url": "http://127.0.0.1/admin",
                "status": 200,
                "length": 1234,
                "words": 40,
                "lines": 20,
            },
            {
                "input": {"FUZZ": ".git"},
                "url": "http://127.0.0.1/.git/config",
                "status": 403,
                "length": 200,
                "words": 5,
                "lines": 5,
            },
            {
                "input": {"FUZZ": "old"},
                "url": "http://127.0.0.1/old",
                "status": 301,
                "length": 0,
                "words": 0,
                "lines": 0,
            },
        ]
    }
)

SQLMAP_STDOUT = """
[12:00:01] [INFO] testing connection to the target URL
[12:00:04] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
sqlmap identified the following injection point(s) with a total of 41 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3419=3419
---
[12:00:09] [INFO] the back-end DBMS is MySQL
"""

NIKTO_STDOUT = """
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    127.0.0.1
+ Target Port:        80
+ Start Time:         2026-11-10 12:00:00
---------------------------------------------------------------------------
+ Server: nginx/1.24.0
+ /admin/: Admin login page/section found.
+ /backup.zip: Backup file found, may expose source code.
+ OSVDB-3092: /phpinfo.php: PHPinfo file is publicly accessible.
+ 8102 requests: 0 error(s) and 3 item(s) reported
"""

SUBFINDER_STDOUT = "api.lab.test\nwww.lab.test\nwww.lab.test\nnot-a-host\nother.example.com\n"

DALFOX_JSON = json.dumps(
    [
        {
            "type": "V",
            "inject_type": "inHTML",
            "param": "q",
            "payload": '"><script>alert(1)</script>',
            "evidence": '"><script>alert(1)</script>',
            "method": "GET",
            "url": "http://127.0.0.1/search?q=test",
        },
        {
            "type": "G",
            "inject_type": "inJS",
            "param": "lang",
            "payload": "';alert(1);//",
            "url": "http://127.0.0.1/search?lang=en",
        },
    ]
)
