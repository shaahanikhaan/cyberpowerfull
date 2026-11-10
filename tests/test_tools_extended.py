"""Extended tool layer: argv construction, parsers, and execution paths.

Every wrapper added in 3.0 is covered here: real argv shapes, tolerant parsers,
and the guardrails (capability, bounded wordlists, no shell) that make them safe
to expose to a model.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Capability, Phase, Severity
from cyberpowerfull.tools.amass import AmassTool
from cyberpowerfull.tools.arjun import ArjunTool
from cyberpowerfull.tools.base import ToolStatus
from cyberpowerfull.tools.dnsrecon import DnsreconTool
from cyberpowerfull.tools.extract import (
    extract_report_findings,
    findings_from_json_records,
    merge_findings,
)
from cyberpowerfull.tools.feroxbuster import FeroxbusterTool
from cyberpowerfull.tools.gobuster import GobusterTool
from cyberpowerfull.tools.hydra import HydraTool
from cyberpowerfull.tools.katana import KatanaTool
from cyberpowerfull.tools.masscan import MasscanTool
from cyberpowerfull.tools.naabu import NaabuTool
from cyberpowerfull.tools.pentagi import PentagiTool
from cyberpowerfull.tools.searchsploit import SearchsploitTool
from cyberpowerfull.tools.sn1per import Sn1perTool
from cyberpowerfull.tools.strix import StrixTool
from cyberpowerfull.tools.testssl import TestsslTool
from cyberpowerfull.tools.wafw00f import Wafw00fTool
from cyberpowerfull.tools.whatweb import WhatwebTool
from cyberpowerfull.tools.wpscan import WpscanTool
from tests.conftest import completed

MASSCAN_JSON = """[INFO] starting masscan
[
  {"ip": "127.0.0.1", "timestamp": "1", "ports": [
    {"port": 22, "proto": "tcp", "status": "open", "service": "ssh"},
    {"port": 443, "proto": "tcp", "status": "closed"}
  ]}
]
"""

NAABU_JSONL = "\n".join(
    [
        json.dumps({"host": "127.0.0.1", "ip": "127.0.0.1", "port": 80}),
        json.dumps({"host": "127.0.0.1", "ip": "127.0.0.1", "port": 8000, "tls": False}),
        "warning: not json",
    ]
)

DNSRECON_JSON = json.dumps(
    [
        {"type": "SOA", "name": "127.0.0.1", "mname": "ns1"},
        {"type": "A", "name": "api.lab.test", "address": "10.0.0.5"},
        {"type": "TXT", "name": "lab.test", "strings": ["v=spf1 -all"]},
        {"type": "Zone Transfer", "name": "ns1.lab.test", "address": "zone data"},
    ]
)

KATANA_JSONL = "\n".join(
    [
        json.dumps(
            {
                "request": {"method": "GET", "endpoint": "https://127.0.0.1/.git/config"},
                "response": {"status_code": 200},
                "source": "https://127.0.0.1/",
            }
        ),
        json.dumps(
            {
                "request": {"method": "GET", "endpoint": "https://127.0.0.1/search?q=x"},
                "response": {"status_code": 200},
            }
        ),
        json.dumps(
            {
                "request": {"method": "GET", "endpoint": "https://127.0.0.1/static/app.js"},
                "response": {"status_code": 200},
            }
        ),
    ]
)

WHATWEB_JSONL = "\n".join(
    [
        json.dumps(
            [
                "https://127.0.0.1/",
                {
                    "plugins": {
                        "WordPress": {"version": ["6.4.2"], "certainty": "100"},
                        "Nginx": {"version": [], "certainty": "100"},
                    }
                },
            ]
        )
    ]
)

WPSCAN_JSON = json.dumps(
    {
        "version": {
            "number": "6.4.2",
            "status": "insecure",
            "vulnerabilities": [
                {
                    "title": "WordPress Core < 6.4.3 - SQL Injection",
                    "cve": "CVE-2024-0001",
                    "fixed_in": "6.4.3",
                }
            ],
        },
        "plugins": {
            "contact-form-7": {
                "version": {"number": "5.0"},
                "vulnerabilities": [
                    {
                        "title": "Contact Form 7 < 5.1 - Unauthenticated File Upload",
                        "fixed_in": "5.1",
                    }
                ],
            }
        },
        "themes": {},
        "users": {"admin": {"id": 1}, "editor": {"id": 2}},
        "interesting_findings": [
            {"url": "https://127.0.0.1/xmlrpc.php", "type": "XML-RPC seems to be enabled"}
        ],
    }
)

FEROX_JSONL = "\n".join(
    [
        json.dumps(
            {
                "type": "response",
                "url": "https://127.0.0.1/.env",
                "status": 200,
                "content_length": 300,
                "word_count": 10,
            }
        ),
        json.dumps(
            {"type": "response", "url": "https://127.0.0.1/random", "status": 200, "wildcard": True}
        ),
        json.dumps({"type": "stats", "url": "https://127.0.0.1/"}),
    ]
)

ARJUN_JSON = json.dumps({"https://127.0.0.1/api": ["debug", "id", "page"]})

WAF_JSON = json.dumps(
    [
        {
            "url": "https://127.0.0.1",
            "detected": True,
            "firewall": "Cloudflare",
            "manufacturer": "Cloudflare Inc.",
        }
    ]
)

TESTSSL_JSON = json.dumps(
    [
        {"id": "SSLv3", "severity": "HIGH", "finding": "SSLv3 is offered", "ip": "127.0.0.1"},
        {"id": "cipherlist", "severity": "OK", "finding": "no NULL ciphers"},
        {"id": "cert_chain", "severity": "MEDIUM", "finding": "chain incomplete"},
    ]
)

SEARCHSPLOIT_JSON = json.dumps(
    {
        "RESULTS_EXPLOIT": [
            {
                "Title": "Apache 2.4.49 - Remote Code Execution",
                "EDB-ID": "50383",
                "Type": "remote",
                "Date": "2021-10-05",
                "Path": "/x/50383.py",
            }
        ],
        "RESULTS_SHELLCODE": [],
    }
)

HYDRA_STDOUT = """Hydra v9.5 starting
[DATA] attacking ssh://127.0.0.1:22/
[22][ssh] host: 127.0.0.1   login: root   password: toor
1 of 1 target successfully completed, 1 valid password found
"""

STRIX_STDOUT = """[HIGH] SQL Injection in /login (CVE-2024-0002)
[INFO] crawl finished
"""


def _run_with(stdout: str, returncode: int = 0):
    return (
        mock.patch(
            "cyberpowerfull.tools.base.subprocess.run",
            return_value=completed(stdout, "", returncode),
        ),
        mock.patch(
            "cyberpowerfull.tools.base.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ),
    )


class TestMasscan:
    def test_argv_and_parse(self) -> None:
        tool = MasscanTool()
        args = tool.validate({"target": "127.0.0.1", "ports": "1-1024", "rate": 800})
        argv = tool.build_argv(args)
        assert argv[:4] == ["masscan", "127.0.0.1", "-p", "1-1024"]
        assert "--rate" in argv and "-oJ" in argv
        findings = tool.parse(args, MASSCAN_JSON)
        assert len(findings) == 1, "closed ports are not findings"
        assert findings[0].endpoint == "127.0.0.1:22"
        assert findings[0].severity is Severity.INFO

    def test_rejects_bad_ports(self) -> None:
        with pytest.raises(InvalidToolArguments):
            MasscanTool().validate({"target": "127.0.0.1", "ports": "1; rm -rf /"})

    def test_run_mocked(self) -> None:
        run_mock, which_mock = _run_with(MASSCAN_JSON)
        with run_mock as run, which_mock:
            result = MasscanTool().run({"target": "127.0.0.1"})
        assert result.status is ToolStatus.OK
        assert len(result.findings) == 1
        assert run.call_args.kwargs["shell"] is False


class TestNaabu:
    def test_argv_top_ports_and_ports(self) -> None:
        tool = NaabuTool()
        argv = tool.build_argv(tool.validate({"target": "127.0.0.1", "top_ports": 100}))
        assert argv[argv.index("-top-ports") + 1] == "100"
        argv = tool.build_argv(tool.validate({"target": "127.0.0.1", "ports": [80, 443]}))
        assert argv[argv.index("-p") + 1] == "80,443"

    def test_parse_dedupes(self) -> None:
        tool = NaabuTool()
        args = tool.validate({"target": "127.0.0.1"})
        findings = tool.parse(args, NAABU_JSONL)
        assert [f.endpoint for f in findings] == ["127.0.0.1:80", "127.0.0.1:8000"]

    def test_rejects_bad_port(self) -> None:
        with pytest.raises(InvalidToolArguments):
            NaabuTool().validate({"target": "127.0.0.1", "ports": [70000]})


class TestAmass:
    def test_requires_dns_name(self) -> None:
        with pytest.raises(InvalidToolArguments):
            AmassTool().validate({"target": "127.0.0.1"})

    def test_argv_and_parse(self) -> None:
        tool = AmassTool()
        args = tool.validate({"target": "lab.test"})
        argv = tool.build_argv(args)
        assert "-passive" in argv
        findings = tool.parse(args, "api.lab.test\nwww.lab.test\nlab.test\nnot a host\n")
        assert [f.endpoint for f in findings] == ["api.lab.test", "www.lab.test"]
        assert all(f.phase is Phase.RECON for f in findings)


class TestDnsrecon:
    def test_argv(self) -> None:
        tool = DnsreconTool()
        argv = tool.build_argv(tool.validate({"target": "lab.test"}), "/tmp/out.json")
        assert argv[:3] == ["dnsrecon", "-d", "lab.test"]
        assert "-j" in argv

    def test_parse_records(self) -> None:
        tool = DnsreconTool()
        args = tool.validate({"target": "lab.test"})
        findings = tool.parse(args, DNSRECON_JSON)
        titles = [f.title for f in findings]
        assert "DNS A record for api.lab.test" in titles
        zone = [f for f in findings if "Zone transfer" in f.title]
        assert zone and zone[0].severity is Severity.MEDIUM
        assert not any("SOA" in title for title in titles)

    def test_parse_garbage(self) -> None:
        tool = DnsreconTool()
        assert tool.parse(tool.validate({"target": "lab.test"}), "@@@") == []


class TestKatana:
    def test_argv(self) -> None:
        tool = KatanaTool()
        argv = tool.build_argv(tool.validate({"target": "https://127.0.0.1", "depth": 3}))
        assert "-jsonl" in argv and "-crawl" not in argv
        assert argv[argv.index("-d") + 1] == "3"

    def test_parse_keeps_interesting_and_parameterised(self) -> None:
        tool = KatanaTool()
        args = tool.validate({"target": "https://127.0.0.1"})
        findings = tool.parse(args, KATANA_JSONL)
        endpoints = {f.endpoint for f in findings}
        assert "https://127.0.0.1/.git/config" in endpoints
        assert "https://127.0.0.1/search?q=x" in endpoints
        assert "https://127.0.0.1/static/app.js" not in endpoints
        git = [f for f in findings if ".git" in (f.endpoint or "")]
        assert git[0].severity is Severity.LOW


class TestWhatweb:
    def test_argv_uses_json_log(self) -> None:
        tool = WhatwebTool()
        argv = tool.build_argv(tool.validate({"target": "https://127.0.0.1"}), "/tmp/w.json")
        assert "--log-json=/tmp/w.json" in argv

    def test_parse_versions(self) -> None:
        tool = WhatwebTool()
        args = tool.validate({"target": "https://127.0.0.1"})
        findings = tool.parse(args, WHATWEB_JSONL)
        titles = [f.title for f in findings]
        assert any("WordPress 6.4.2" in title for title in titles)
        version = [f for f in findings if "version disclosed" in f.title]
        assert version[0].severity is Severity.LOW
        assert any(f.title.startswith("Technology fingerprint:") for f in findings)

    def test_parse_garbage(self) -> None:
        tool = WhatwebTool()
        assert tool.parse(tool.validate({"target": "https://127.0.0.1"}), "{oops") == []


class TestWpscan:
    def test_argv(self) -> None:
        tool = WpscanTool()
        argv = tool.build_argv(tool.validate({"target": "https://127.0.0.1"}), "/tmp/wp.json")
        assert "--format" in argv and "json" in argv
        assert argv[argv.index("--plugins-detection") + 1] == "passive"

    def test_rejects_unknown_enumeration(self) -> None:
        with pytest.raises(InvalidToolArguments):
            WpscanTool().validate({"target": "https://127.0.0.1", "enumerate": ["shell"]})

    def test_parse_core_plugin_users(self) -> None:
        tool = WpscanTool()
        args = tool.validate({"target": "https://127.0.0.1"})
        findings = tool.parse(args, WPSCAN_JSON)
        titles = " | ".join(f.title for f in findings)
        assert "WordPress core version disclosed: 6.4.2" in titles
        assert "public" not in titles.lower()
        assert "user enumeration succeeded" in titles
        core_vuln = [f for f in findings if "SQL Injection" in f.title]
        assert core_vuln and core_vuln[0].severity is Severity.HIGH
        assert core_vuln[0].cve == "CVE-2024-0001"
        plugin = [f for f in findings if "Contact Form" in f.title]
        assert plugin and plugin[0].severity is Severity.MEDIUM

    def test_parse_garbage(self) -> None:
        tool = WpscanTool()
        assert tool.parse(tool.validate({"target": "https://127.0.0.1"}), "nope") == []


class TestGobuster:
    def _wordlist(self, tmp_path: Path) -> str:
        path = tmp_path / "common.txt"
        path.write_text("admin\n", encoding="utf-8")
        return str(path)

    def test_dir_argv_and_parse(self, tmp_path: Path) -> None:
        tool = GobusterTool()
        wordlist = self._wordlist(tmp_path)
        args = tool.validate({"target": "https://127.0.0.1", "mode": "dir", "wordlist": wordlist})
        argv = tool.build_argv(args, "/tmp/g.txt")
        assert argv[:2] == ["gobuster", "dir"]
        assert "-o" in argv
        findings = tool.parse(
            args,
            "https://127.0.0.1/.git   [Status: 200, Size: 12]\n"
            "https://127.0.0.1/admin  [Status: 403, Size: 12]\n"
            "[ERROR] noise line\n",
        )
        assert len(findings) == 2
        assert findings[0].severity is Severity.LOW
        assert findings[1].severity is Severity.LOW

    def test_dns_parse(self, tmp_path: Path) -> None:
        tool = GobusterTool()
        args = tool.validate(
            {
                "target": "lab.test",
                "mode": "dns",
                "wordlist": self._wordlist(tmp_path),
            }
        )
        findings = tool.parse(args, "Found: api.lab.test\n")
        assert findings[0].endpoint == "api.lab.test"

    def test_fuzz_requires_keyword(self, tmp_path: Path) -> None:
        tool = GobusterTool()
        args = tool.validate(
            {"target": "https://127.0.0.1/", "mode": "fuzz", "wordlist": self._wordlist(tmp_path)}
        )
        with pytest.raises(InvalidToolArguments, match="FUZZ"):
            tool.build_argv(args)

    def test_missing_wordlist_is_an_argument_error(self, monkeypatch) -> None:
        monkeypatch.setattr("cyberpowerfull.inventory.pick_wordlist", lambda kind: None)
        tool = GobusterTool()
        args = tool.validate({"target": "https://127.0.0.1"})
        with pytest.raises(InvalidToolArguments, match="wordlist"):
            tool.build_argv(args)

    def test_resolves_wordlist_from_inventory(self, tmp_path: Path, monkeypatch) -> None:
        resolved = self._wordlist(tmp_path)
        monkeypatch.setattr("cyberpowerfull.inventory.pick_wordlist", lambda kind: resolved)
        tool = GobusterTool()
        argv = tool.build_argv(tool.validate({"target": "https://127.0.0.1"}))
        assert resolved in argv


class TestFeroxbuster:
    def test_parse(self, tmp_path: Path) -> None:
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("a\n", encoding="utf-8")
        tool = FeroxbusterTool()
        args = tool.validate({"target": "https://127.0.0.1", "wordlist": str(wordlist)})
        argv = tool.build_argv(args)
        assert "--json" in argv and "--auto-tune" in argv
        findings = tool.parse(args, FEROX_JSONL)
        assert [f.endpoint for f in findings] == ["https://127.0.0.1/.env"]
        assert findings[0].severity is Severity.LOW

    def test_missing_wordlist(self, monkeypatch) -> None:
        monkeypatch.setattr("cyberpowerfull.inventory.pick_wordlist", lambda kind: None)
        tool = FeroxbusterTool()
        with pytest.raises(InvalidToolArguments, match="wordlist"):
            tool.build_argv(tool.validate({"target": "https://127.0.0.1"}))


class TestArjun:
    def test_argv_and_parse(self) -> None:
        tool = ArjunTool()
        args = tool.validate({"target": "https://127.0.0.1/api", "method": "JSON"})
        argv = tool.build_argv(args, "/tmp/a.json")
        assert argv[argv.index("-m") + 1] == "JSON"
        findings = tool.parse(args, ARJUN_JSON)
        assert len(findings) == 3
        debug = [f for f in findings if "debug" in f.title]
        assert debug[0].severity is Severity.LOW
        page = [f for f in findings if "page" in f.title]
        assert page[0].severity is Severity.INFO

    def test_parse_garbage(self) -> None:
        tool = ArjunTool()
        assert tool.parse(tool.validate({"target": "https://127.0.0.1"}), "[]") == []


class TestWafw00f:
    def test_argv_and_parse(self) -> None:
        tool = Wafw00fTool()
        args = tool.validate({"target": "https://127.0.0.1"})
        argv = tool.build_argv(args, "/tmp/waf.json")
        assert argv[argv.index("-f") + 1] == "json"
        findings = tool.parse(args, WAF_JSON)
        assert findings and "Cloudflare" in findings[0].title
        assert findings[0].severity is Severity.INFO
        assert "Cloudflare" in tool.observations(args, WAF_JSON)[0]

    def test_not_detected(self) -> None:
        tool = Wafw00fTool()
        args = tool.validate({"target": "https://127.0.0.1"})
        assert tool.parse(args, json.dumps([{"detected": False}])) == []


class TestTestssl:
    def test_argv(self) -> None:
        tool = TestsslTool()
        argv = tool.build_argv(tool.validate({"target": "https://127.0.0.1"}), "/tmp/t.json")
        assert "--jsonfile" in argv
        assert argv[argv.index("--severity") + 1] == "LOW"

    def test_parse_skips_ok(self) -> None:
        tool = TestsslTool()
        args = tool.validate({"target": "https://127.0.0.1"})
        findings = tool.parse(args, TESTSSL_JSON)
        assert [f.title.split(":")[0] for f in findings] == [
            "TLS issue SSLv3",
            "TLS issue cert_chain",
        ]
        assert findings[0].severity is Severity.HIGH
        assert findings[1].severity is Severity.MEDIUM

    def test_alternate_binary_name_is_used(self) -> None:
        tool = TestsslTool()

        def which(name: str):
            return "/usr/bin/testssl" if name == "testssl" else None

        with (
            mock.patch("cyberpowerfull.tools.base.shutil.which", side_effect=which),
            mock.patch(
                "cyberpowerfull.tools.base.subprocess.run",
                return_value=completed(TESTSSL_JSON),
            ) as run,
        ):
            result = tool.run({"target": "https://127.0.0.1"})
            assert result.status is ToolStatus.OK
            assert run.call_args.args[0][0] == "testssl"
            assert tool.describe()["resolved_binary"] == "testssl"


class TestSearchsploit:
    def test_argv_and_parse(self) -> None:
        tool = SearchsploitTool()
        args = tool.validate({"target": "127.0.0.1", "query": "apache 2.4"})
        assert tool.build_argv(args) == ["searchsploit", "--json", "apache 2.4"]
        findings = tool.parse(args, SEARCHSPLOIT_JSON)
        assert findings and findings[0].severity is Severity.MEDIUM
        assert "edb_id=50383" in findings[0].evidence

    def test_rejects_shell_metacharacters(self) -> None:
        with pytest.raises(InvalidToolArguments):
            SearchsploitTool().validate({"target": "127.0.0.1", "query": "apache; id"})

    def test_parse_empty(self) -> None:
        tool = SearchsploitTool()
        assert tool.parse(tool.validate({"target": "127.0.0.1", "query": "zzz"}), "") == []


class TestHydra:
    def _list(self, tmp_path: Path, lines: int = 3) -> str:
        path = tmp_path / "passwords.txt"
        path.write_text("\n".join(f"pass{index}" for index in range(lines)), encoding="utf-8")
        return str(path)

    def test_capability_is_declared(self) -> None:
        assert HydraTool.required_capability is Capability.CREDENTIAL_TESTING

    def test_argv_and_redacted_parse(self, tmp_path: Path) -> None:
        tool = HydraTool()
        args = tool.validate(
            {
                "target": "127.0.0.1",
                "service": "ssh",
                "username": "root",
                "password_list": self._list(tmp_path),
                "tasks": 8,
            }
        )
        argv = tool.build_argv(args)
        assert "-f" in argv
        assert argv[argv.index("-t") + 1] == "8", "task cap is enforced"
        findings = tool.parse(args, HYDRA_STDOUT)
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH
        assert findings[0].verified is True
        assert "toor" not in findings[0].evidence
        assert "t**r" in findings[0].evidence

    def test_rejects_oversized_wordlist(self, tmp_path: Path) -> None:
        tool = HydraTool()
        args = tool.validate(
            {
                "target": "127.0.0.1",
                "username": "root",
                "password_list": self._list(tmp_path, lines=50),
                "max_password_candidates": 10,
            }
        )
        with pytest.raises(InvalidToolArguments, match="candidate cap"):
            tool.build_argv(args)

    def test_missing_wordlist_is_a_validation_error(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidToolArguments):
            HydraTool().validate(
                {
                    "target": "127.0.0.1",
                    "username": "root",
                    "password_list": str(tmp_path / "absent.txt"),
                }
            )

    def test_rejects_unsafe_username(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidToolArguments):
            HydraTool().validate(
                {
                    "target": "127.0.0.1",
                    "username": "root; id",
                    "password_list": self._list(tmp_path),
                }
            )

    def test_no_findings_observation(self, tmp_path: Path) -> None:
        tool = HydraTool()
        args = tool.validate(
            {"target": "127.0.0.1", "username": "root", "password_list": self._list(tmp_path)}
        )
        assert "no valid credential" in tool.observations(args, "0 valid passwords found")[0]


class TestSn1per:
    def test_argv(self) -> None:
        tool = Sn1perTool()
        argv = tool.build_argv(
            tool.validate({"target": "127.0.0.1", "mode": "stealth", "workspace": "lab"})
        )
        assert argv == ["sniper", "-t", "127.0.0.1", "-m", "stealth", "-w", "lab"]

    def test_rejects_unsafe_workspace(self) -> None:
        with pytest.raises(InvalidToolArguments):
            Sn1perTool().validate({"target": "127.0.0.1", "workspace": "../etc"})

    def test_parses_real_loot_files(self, tmp_path: Path) -> None:
        loot = tmp_path / "loot" / "127.0.0.1"
        (loot / "vulnerabilities").mkdir(parents=True)
        (loot / "vulnerabilities" / "nikto.txt").write_text(
            "Critical: Remote code execution in admin panel\n"
            "Low: information disclosure in /server-status\n",
            encoding="utf-8",
        )
        (loot / "notes.txt").write_text("nothing interesting", encoding="utf-8")
        tool = Sn1perTool()
        args = tool.validate({"target": "127.0.0.1", "loot_dir": str(tmp_path / "loot")})
        findings = tool.parse(args, "HIGH: exposed git repository on /.git/\n")
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities
        assert Severity.CRITICAL in severities
        assert any("loot file" in f.evidence for f in findings)
        notes = tool.observations(args, "")
        assert any("loot roots" in note for note in notes)

    def test_missing_loot_is_reported(self, tmp_path: Path) -> None:
        tool = Sn1perTool()
        args = tool.validate({"target": "127.0.0.1", "loot_dir": str(tmp_path / "absent")})
        assert tool.parse(args, "") == []
        assert any("no loot workspace" in note for note in tool.observations(args, ""))


class TestStrix:
    def test_argv_is_headless_and_budgeted(self) -> None:
        tool = StrixTool()
        args = tool.validate(
            {"target": "https://127.0.0.1", "scan_mode": "standard", "max_budget_usd": 3.5}
        )
        argv = tool.build_argv(args)
        assert argv[:2] == ["strix", "-n"]
        assert argv[argv.index("--max-budget") + 1] == "3.5"
        instruction = argv[argv.index("--instruction") + 1]
        assert "Authorized engagement" in instruction
        assert "\n" not in instruction

    def test_instruction_is_single_line(self) -> None:
        tool = StrixTool()
        args = tool.validate({"target": "https://127.0.0.1", "instruction": "line1\nline2"})
        assert "line1 line2" in tool.build_argv(args)[-1]

    def test_parse_console_and_run_directory(self, tmp_path: Path, monkeypatch) -> None:
        runs = tmp_path / "strix_runs" / "run-1"
        runs.mkdir(parents=True)
        (runs / "report.md").write_text(
            "- **Critical**: authentication bypass in admin API\n", encoding="utf-8"
        )
        monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "strix_runs"))
        monkeypatch.chdir(tmp_path)
        tool = StrixTool()
        args = tool.validate({"target": "https://127.0.0.1"})
        findings = tool.parse(args, STRIX_STDOUT)
        titles = [f.title for f in findings]
        assert any("SQL Injection" in title for title in titles)
        assert any("authentication bypass" in title for title in titles)
        assert tool.observations(args, "")[1].startswith("strix run directories:")


class TestPentagi:
    def _args(self, tool: PentagiTool, **extra):
        payload = {"target": "https://127.0.0.1", "max_wait_s": 10, "poll_s": 1}
        payload.update(extra)
        return tool.validate(payload)

    def test_argv(self) -> None:
        tool = PentagiTool()
        assert tool.build_argv(self._args(tool))[:2] == ["pentagi", "--target"]

    def test_missing_endpoint_is_reported(self, monkeypatch) -> None:
        monkeypatch.delenv("PENTAGI_URL", raising=False)
        monkeypatch.delenv("PENTAGI_BASE_URL", raising=False)
        tool = PentagiTool()
        result = tool.run({"target": "https://127.0.0.1"})
        assert result.status is ToolStatus.MISSING
        assert "PENTAGI_URL" in (result.error or "")

    def test_full_flow(self, monkeypatch) -> None:
        monkeypatch.setenv("PENTAGI_URL", "https://127.0.0.1:8443")
        monkeypatch.setenv("PENTAGI_API_TOKEN", "token")
        calls: list[tuple[str, str]] = []

        def fake_http(method, path, payload, *, timeout):
            calls.append((method, path))
            body = payload or {}
            query = str(body.get("query", ""))
            if "CreateFlow" in query:
                return 200, json.dumps(
                    {"data": {"createFlow": {"id": "flow-1", "status": "created"}}}
                )
            if "FlowStatus" in query:
                return 200, json.dumps({"data": {"flow": {"id": "flow-1", "status": "finished"}}})
            if "FlowReport" in query:
                return 200, json.dumps(
                    {"data": {"flow": {"report": "HIGH: SQL injection in /login"}}}
                )
            return 404, "not found"

        monkeypatch.setattr(PentagiTool, "_http", staticmethod(fake_http))
        tool = PentagiTool()
        result = tool.run({"target": "https://127.0.0.1", "max_wait_s": 5, "poll_s": 1})
        assert result.status is ToolStatus.OK
        assert any(path == "/api/v1/graphql" for _method, path in calls)
        assert "SQL injection" in " ".join(f.title for f in result.findings)

    def test_flow_creation_failure_is_surfaced(self, monkeypatch) -> None:
        monkeypatch.setenv("PENTAGI_URL", "https://127.0.0.1:8443")
        monkeypatch.setattr(
            PentagiTool,
            "_http",
            staticmethod(lambda method, path, payload, *, timeout: (500, "upstream down")),
        )
        tool = PentagiTool()
        result = tool.run({"target": "https://127.0.0.1", "max_wait_s": 5, "poll_s": 1})
        assert result.status is ToolStatus.ERROR
        assert "could not create a PentAGI flow" in (result.error or "")

    def test_unfinished_flow_times_out(self, monkeypatch) -> None:
        monkeypatch.setenv("PENTAGI_URL", "http://127.0.0.1:8443")
        monkeypatch.setattr(
            PentagiTool,
            "_http",
            staticmethod(
                lambda method, path, payload, *, timeout: (
                    200,
                    json.dumps({"data": {"createFlow": {"id": "f1", "status": "new"}}}),
                )
            ),
        )
        clock = iter(range(0, 10_000, 10))
        monkeypatch.setattr("cyberpowerfull.tools.pentagi.time.monotonic", lambda: next(clock))
        monkeypatch.setattr("cyberpowerfull.tools.pentagi.time.sleep", lambda _s: None)
        tool = PentagiTool()
        result = tool.run({"target": "http://127.0.0.1", "max_wait_s": 5, "poll_s": 1})
        assert result.status is ToolStatus.TIMEOUT
        assert "did not finish" in (result.error or "")

    def test_parse_json_records(self) -> None:
        tool = PentagiTool()
        args = self._args(tool)
        payload = json.dumps(
            [{"title": "IDOR in /api/users", "severity": "high", "endpoint": "/api/users/1"}]
        )
        findings = tool.parse(args, payload)
        assert findings and findings[0].severity is Severity.HIGH
        assert findings[0].endpoint == "/api/users/1"

    def test_http_transport_error_is_reported(self, monkeypatch) -> None:
        import urllib.error

        monkeypatch.setenv("PENTAGI_URL", "https://127.0.0.1:8443")
        tool = PentagiTool()

        def boom(*args, **kwargs):
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr("cyberpowerfull.tools.pentagi.urllib.request.urlopen", boom)
        assert tool._http("GET", "/x", None, timeout=1)[0] == 0

    def test_rejects_bad_provider(self) -> None:
        with pytest.raises(InvalidToolArguments):
            PentagiTool().validate({"target": "https://127.0.0.1", "provider": "bad provider!"})


class TestReportExtraction:
    def test_severity_tags_become_findings(self) -> None:
        text = (
            "Starting scan\n"
            "[CRITICAL] Remote code execution in /debug\n"
            "## High: SSRF via image_url\n"
            "info: only three words\n"
            "no severity here at all\n"
        )
        findings = extract_report_findings(text, tool="strix", target="127.0.0.1")
        assert len(findings) == 2
        assert findings[0].severity is Severity.CRITICAL
        assert findings[1].severity is Severity.HIGH
        assert findings[0].verified is True

    def test_cve_is_extracted(self) -> None:
        findings = extract_report_findings(
            "HIGH: CVE-2024-12345 deserialization",
            tool="pentagi",
            target="127.0.0.1",
        )
        assert findings[0].cve == "CVE-2024-12345"

    def test_duplicates_are_merged(self) -> None:
        a = extract_report_findings("HIGH: same title here", tool="a", target="x")
        b = extract_report_findings("HIGH: same title here", tool="b", target="x")
        assert len(merge_findings(a, b)) == 1

    def test_json_records(self) -> None:
        findings = findings_from_json_records(
            [{"title": "XSS in search", "severity": "medium", "url": "/search"}],
            tool="strix",
            target="127.0.0.1",
        )
        assert findings[0].severity is Severity.MEDIUM
        assert findings[0].endpoint == "/search"

    def test_noise_is_ignored(self) -> None:
        assert extract_report_findings("warning\n-----\nshort\n", tool="x", target="y") == []


class TestPolicyStillApplies:
    def test_sanitised_env_reaches_new_tools(self) -> None:
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "secret", "PATH": "/usr/bin"}):
            env = ToolPolicy().sanitized_env()
        assert "OPENAI_API_KEY" not in env
        assert env["PATH"] == "/usr/bin"
