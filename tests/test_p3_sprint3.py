"""Pillar 1 Sprint 3: assetfinder, fierce, whois, wfuzz, droopescan."""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

from cyberpowerfull.brain.orchestrator import DelegationRequest, WorkerAgent
from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.scope import Scope
from cyberpowerfull.tools.base import ToolStatus

ASSETFINDER_OUT = "www.lab.test\nmail.lab.test\nmail.lab.test\nlab.test\nevillab.test\n"

FIERCE_OUT = """NS: ns1.lab.test ns2.lab.test
SOA: ns1.lab.test (127.0.0.1)
Zone: failure
Wildcard: failure
Found: www.lab.test. (127.0.0.2)
Found: mail.lab.test. (127.0.0.3)
"""

FIERCE_AXFR = "NS: ns1.lab.test\nSOA: ns1.lab.test (127.0.0.1)\nZone: success\n"

FIERCE_FATAL = "NS: failure\nSOA: failure\nFailed to lookup NS/SOA, Domain does not exist\n"


def _whois_record(expires: str) -> str:
    return f"""Domain Name: LAB.TEST
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-15T00:00:00Z
Registry Expiry Date: {expires}T00:00:00Z
Updated Date: 2025-01-15T00:00:00Z
Name Server: NS1.LAB.TEST
Name Server: NS2.LAB.TEST
DNSSEC: unsigned
Domain Status: clientTransferProhibited
"""


def _wfuzz_result(code: int, payload: str, url: str) -> dict:
    return {
        "chars": 123,
        "code": code,
        "payload": payload,
        "lines": 10,
        "location": "",
        "method": "GET",
        "post_data": [],
        "server": "nginx",
        "url": url,
        "words": 20,
    }


WFUZZ_JSON = json.dumps(
    [
        _wfuzz_result(200, "admin", "https://lab.test/admin"),
        _wfuzz_result(200, "backup.zip", "https://lab.test/backup.zip"),
        _wfuzz_result(403, "secret", "https://lab.test/secret"),
    ]
)

DROOPESCAN_JSON = json.dumps(
    {
        "themes": {"is_empty": True, "finds": []},
        "interesting urls": {
            "is_empty": False,
            "finds": [{"url": "https://lab.test/user/login", "description": "Default admin."}],
        },
        "version": {"is_empty": False, "finds": ["7.29", "7.30"]},
        "plugins": {
            "is_empty": False,
            "finds": [{"url": "https://lab.test/sites/all/modules/views/", "name": "views"}],
        },
    }
)


class TestAssetfinder:
    def test_argv_defaults_to_subs_only(self) -> None:
        from cyberpowerfull.tools.assetfinder import AssetfinderTool

        tool = AssetfinderTool()
        assert tool.build_argv(tool.validate({"target": "lab.test"})) == [
            "assetfinder",
            "--subs-only",
            "lab.test",
        ]

    def test_argv_without_subs_only(self) -> None:
        from cyberpowerfull.tools.assetfinder import AssetfinderTool

        tool = AssetfinderTool()
        argv = tool.build_argv(tool.validate({"target": "lab.test", "subs_only": False}))
        assert argv == ["assetfinder", "lab.test"]

    def test_validate_rejects_ip(self) -> None:
        from cyberpowerfull.tools.assetfinder import AssetfinderTool

        with pytest.raises(InvalidToolArguments):
            AssetfinderTool().validate({"target": "127.0.0.1"})

    def test_parse_enforces_dot_boundary(self) -> None:
        from cyberpowerfull.tools.assetfinder import AssetfinderTool

        tool = AssetfinderTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), ASSETFINDER_OUT)
        assert [finding.title for finding in findings] == [
            "Subdomain discovered: www.lab.test",
            "Subdomain discovered: mail.lab.test",
        ]
        assert findings[0].endpoint == "www.lab.test"

    def test_observations_count_in_scope(self) -> None:
        from cyberpowerfull.tools.assetfinder import AssetfinderTool

        tool = AssetfinderTool()
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), ASSETFINDER_OUT)
        assert "2 in-scope subdomain(s)" in note
        assert "3 duplicate/out-of-scope name(s) skipped" in note


class TestFierce:
    def test_argv_defaults(self) -> None:
        from cyberpowerfull.tools.fierce import FierceTool

        tool = FierceTool()
        argv = tool.build_argv(tool.validate({"target": "lab.test", "wordlist": "/tmp/w.txt"}))
        assert argv == [
            "fierce",
            "--domain",
            "lab.test",
            "--subdomain-file",
            "/tmp/w.txt",
            "--traverse",
            "5",
        ]

    def test_argv_delay_and_tcp(self) -> None:
        from cyberpowerfull.tools.fierce import FierceTool

        tool = FierceTool()
        argv = tool.build_argv(
            tool.validate(
                {"target": "lab.test", "wordlist": "/tmp/w.txt", "delay": 0.5, "tcp": True}
            )
        )
        assert argv[-3:] == ["--delay", "0.5", "--tcp"]

    def test_parse_found_lines(self) -> None:
        from cyberpowerfull.tools.fierce import FierceTool

        tool = FierceTool()
        findings = tool.parse(
            tool.validate({"target": "lab.test", "wordlist": "/tmp/w.txt"}), FIERCE_OUT
        )
        assert [finding.title for finding in findings] == [
            "Subdomain discovered: www.lab.test",
            "Subdomain discovered: mail.lab.test",
        ]
        assert findings[0].endpoint == "www.lab.test"
        assert "(127.0.0.2)" in (findings[0].evidence or "")

    def test_parse_zone_success_is_medium(self) -> None:
        from cyberpowerfull.tools.fierce import FierceTool

        tool = FierceTool()
        (finding,) = tool.parse(
            tool.validate({"target": "lab.test", "wordlist": "/tmp/w.txt"}), FIERCE_AXFR
        )
        assert finding.title == "DNS zone transfer allowed: lab.test"
        assert finding.severity.value == "medium"

    def test_parse_fatal_has_no_findings(self) -> None:
        from cyberpowerfull.tools.fierce import FierceTool

        tool = FierceTool()
        args = tool.validate({"target": "lab.test", "wordlist": "/tmp/w.txt"})
        assert tool.parse(args, FIERCE_FATAL) == []
        (note,) = tool.observations(args, FIERCE_FATAL)
        assert "does not exist" in note

    def test_observations_count_hits(self) -> None:
        from cyberpowerfull.tools.fierce import FierceTool

        tool = FierceTool()
        (note,) = tool.observations(
            tool.validate({"target": "lab.test", "wordlist": "/tmp/w.txt"}), FIERCE_OUT
        )
        assert "2 subdomain(s), zone=failure" in note


class TestWhois:
    def test_argv_hides_disclaimers(self) -> None:
        from cyberpowerfull.tools.whois import WhoisTool

        tool = WhoisTool()
        assert tool.build_argv(tool.validate({"target": "lab.test"})) == [
            "whois",
            "-H",
            "lab.test",
        ]

    def test_parse_registration_facts(self) -> None:
        from cyberpowerfull.tools.whois import WhoisTool

        tool = WhoisTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), _whois_record("2030-05-01"))
        assert [finding.title for finding in findings] == [
            "Domain registration details: lab.test",
            "DNSSEC not enabled: lab.test",
        ]
        assert "registrar=Example Registrar, Inc." in (findings[0].evidence or "")

    def test_parse_expiring_soon_is_low(self) -> None:
        from cyberpowerfull.tools.whois import WhoisTool

        soon = (date.today() + timedelta(days=10)).isoformat()
        tool = WhoisTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), _whois_record(soon))
        assert findings[1].title == "Domain expires within 30 days: lab.test"
        assert findings[1].severity.value == "low"

    def test_parse_expired(self) -> None:
        from cyberpowerfull.tools.whois import WhoisTool

        past = (date.today() - timedelta(days=5)).isoformat()
        tool = WhoisTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), _whois_record(past))
        assert findings[1].title == "Domain registration expiry date has passed: lab.test"
        assert findings[1].severity.value == "low"

    def test_parse_garbage_has_no_findings(self) -> None:
        from cyberpowerfull.tools.whois import WhoisTool

        tool = WhoisTool()
        args = tool.validate({"target": "lab.test"})
        assert tool.parse(args, "No match for LAB.TEST.\n") == []
        (note,) = tool.observations(args, "No match for LAB.TEST.\n")
        assert "no parseable record" in note

    def test_observations_summarize_record(self) -> None:
        from cyberpowerfull.tools.whois import WhoisTool

        tool = WhoisTool()
        (note,) = tool.observations(
            tool.validate({"target": "lab.test"}), _whois_record("2030-05-01")
        )
        assert "nameservers=2" in note
        assert "dnssec=unsigned" in note


class TestWfuzz:
    def test_argv_json_report(self) -> None:
        from cyberpowerfull.tools.wfuzz import WfuzzTool

        tool = WfuzzTool()
        argv = tool.build_argv(
            tool.validate({"target": "https://lab.test/FUZZ", "wordlist": "/tmp/w.txt"}),
            "/tmp/x/output.json",
        )
        assert argv == [
            "wfuzz",
            "-w",
            "/tmp/w.txt",
            "-t",
            "10",
            "-X",
            "GET",
            "--hc",
            "404",
            "-f",
            "/tmp/x/output.json,json",
            "https://lab.test/FUZZ",
        ]

    def test_argv_requires_out_file(self) -> None:
        from cyberpowerfull.tools.wfuzz import WfuzzTool

        tool = WfuzzTool()
        with pytest.raises(InvalidToolArguments):
            tool.build_argv(tool.validate({"target": "https://lab.test/FUZZ", "wordlist": "w"}))

    def test_validate_rejects_target_without_fuzz(self) -> None:
        from cyberpowerfull.tools.wfuzz import WfuzzTool

        with pytest.raises(InvalidToolArguments):
            WfuzzTool().validate({"target": "https://lab.test/", "wordlist": "w"})

    def test_validate_rejects_bad_options(self) -> None:
        from cyberpowerfull.tools.wfuzz import WfuzzTool

        tool = WfuzzTool()
        with pytest.raises(InvalidToolArguments):
            tool.validate({"target": "https://lab.test/FUZZ", "wordlist": "w", "method": "get;rm"})
        with pytest.raises(InvalidToolArguments):
            tool.validate(
                {"target": "https://lab.test/FUZZ", "wordlist": "w", "headers": ["no-colon"]}
            )
        with pytest.raises(InvalidToolArguments):
            tool.validate({"target": "https://lab.test/FUZZ", "wordlist": "w", "hide_codes": [99]})

    def test_parse_marks_sensitive_hits_low(self) -> None:
        from cyberpowerfull.tools.wfuzz import WfuzzTool

        tool = WfuzzTool()
        findings = tool.parse(
            tool.validate({"target": "https://lab.test/FUZZ", "wordlist": "/tmp/w.txt"}),
            WFUZZ_JSON,
        )
        assert [finding.title for finding in findings] == [
            "Discovered path: https://lab.test/admin",
            "Sensitive file exposure: https://lab.test/backup.zip",
            "Discovered path: https://lab.test/secret",
        ]
        assert findings[1].severity.value == "low"
        assert findings[0].endpoint == "https://lab.test/admin"

    def test_observations_count_codes(self) -> None:
        from cyberpowerfull.tools.wfuzz import WfuzzTool

        tool = WfuzzTool()
        (note,) = tool.observations(
            tool.validate({"target": "https://lab.test/FUZZ", "wordlist": "/tmp/w.txt"}),
            WFUZZ_JSON,
        )
        assert note == "wfuzz: 3 result(s) (200=2, 403=1)"


class TestDroopescan:
    def test_argv_defaults(self) -> None:
        from cyberpowerfull.tools.droopescan import DroopescanTool

        tool = DroopescanTool()
        assert tool.build_argv(tool.validate({"target": "https://lab.test"})) == [
            "droopescan",
            "scan",
            "-u",
            "https://lab.test",
            "-o",
            "json",
            "-e",
            "a",
            "-t",
            "4",
            "--timeout",
            "45",
            "--hide-progressbar",
        ]

    def test_argv_with_cms(self) -> None:
        from cyberpowerfull.tools.droopescan import DroopescanTool

        tool = DroopescanTool()
        argv = tool.build_argv(tool.validate({"target": "https://lab.test", "cms": "drupal"}))
        assert argv[:4] == ["droopescan", "scan", "drupal", "-u"]

    def test_validate_rejects_unknown_cms(self) -> None:
        from cyberpowerfull.tools.droopescan import DroopescanTool

        with pytest.raises(InvalidToolArguments):
            DroopescanTool().validate({"target": "https://lab.test", "cms": "blogger"})

    def test_parse_sections(self) -> None:
        from cyberpowerfull.tools.droopescan import DroopescanTool

        tool = DroopescanTool()
        findings = tool.parse(tool.validate({"target": "https://lab.test"}), DROOPESCAN_JSON)
        assert [finding.title for finding in findings] == [
            "CMS version identified: 7.29, 7.30",
            "CMS plugin detected: views",
            "Interesting URL exposed: https://lab.test/user/login",
        ]
        assert findings[2].severity.value == "low"
        assert findings[1].endpoint == "https://lab.test/sites/all/modules/views/"

    def test_parse_empty_and_garbage(self) -> None:
        from cyberpowerfull.tools.droopescan import DroopescanTool

        tool = DroopescanTool()
        args = tool.validate({"target": "https://lab.test"})
        assert tool.parse(args, "") == []
        assert tool.parse(args, "[+] fatal: connection refused") == []
        (empty_note,) = tool.observations(args, "")
        (error_note,) = tool.observations(args, "[+] fatal: connection refused")
        assert "nothing found" in empty_note
        assert "no machine-readable output" in error_note

    def test_observations_report_unidentified_cms(self) -> None:
        from cyberpowerfull.tools.droopescan import DroopescanTool

        tool = DroopescanTool()
        args = tool.validate({"target": "https://lab.test"})
        output = "\x1b[91m[+] 'https://lab.test/' not identified as a supported CMS. "
        output += "If you disagree, please specify a CMS manually.\x1b[0m\n"
        assert tool.parse(args, output) == []
        (note,) = tool.observations(args, output)
        assert note == "droopescan: host not identified as a supported CMS"

    def test_observations_count_sections(self) -> None:
        from cyberpowerfull.tools.droopescan import DroopescanTool

        tool = DroopescanTool()
        (note,) = tool.observations(tool.validate({"target": "https://lab.test"}), DROOPESCAN_JSON)
        assert "version=2, plugins=1, themes=0, interesting urls=1" in note


class TestSprint3Gates:
    def test_worker_blocks_assetfinder_without_passive_sources(self, scope: Scope) -> None:
        from cyberpowerfull.tools.assetfinder import AssetfinderTool

        worker = WorkerAgent("recon", scope=scope, tools={"assetfinder": AssetfinderTool()})
        result = worker.execute(
            DelegationRequest(agent="recon", tool="assetfinder", args={"target": "lab.test"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allow_passive_sources" in (result.error or "")

    def test_worker_blocks_whois_without_passive_sources(self, scope: Scope) -> None:
        from cyberpowerfull.tools.whois import WhoisTool

        worker = WorkerAgent("recon", scope=scope, tools={"whois": WhoisTool()})
        result = worker.execute(
            DelegationRequest(agent="recon", tool="whois", args={"target": "lab.test"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allow_passive_sources" in (result.error or "")

    def test_worker_blocks_fierce_without_allowlisted_wordlist(self, scope: Scope) -> None:
        from cyberpowerfull.tools.fierce import FierceTool

        worker = WorkerAgent("recon", scope=scope, tools={"fierce": FierceTool()})
        result = worker.execute(
            DelegationRequest(
                agent="recon",
                tool="fierce",
                args={"target": "lab.test", "wordlist": "/tmp/evil.txt"},
            )
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allowed_wordlists" in (result.error or "")

    def test_worker_blocks_wfuzz_without_allowlisted_wordlist(self, scope: Scope) -> None:
        from cyberpowerfull.tools.wfuzz import WfuzzTool

        worker = WorkerAgent("scan", scope=scope, tools={"wfuzz": WfuzzTool()})
        result = worker.execute(
            DelegationRequest(
                agent="scan",
                tool="wfuzz",
                args={"target": "https://lab.test/FUZZ", "wordlist": "/tmp/evil.txt"},
            )
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allowed_wordlists" in (result.error or "")
