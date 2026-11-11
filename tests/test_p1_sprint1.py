"""Pillar 1 Sprint 1: ssh_audit, sslscan, dnsenum, theharvester, gospider, shuffledns."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberpowerfull.brain.orchestrator import DelegationRequest, WorkerAgent
from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.scope import Scope
from cyberpowerfull.tools.base import ToolStatus

SSH_AUDIT_JSON = json.dumps(
    {
        "target": "lab.test:22",
        "banner": {
            "raw": "SSH-2.0-OpenSSH_7.4",
            "protocol": "2.0",
            "software": "OpenSSH_7.4",
            "comments": None,
        },
        "compression": ["none"],
        "kex": [
            {
                "algorithm": "diffie-hellman-group1-sha1",
                "notes": {"fail": ["using small 1024-bit modulus"]},
            },
            {"algorithm": "curve25519-sha256", "notes": {}},
        ],
        "key": [{"algorithm": "ssh-rsa", "notes": {"warn": ["using weak key type"]}}],
        "enc": [{"algorithm": "aes128-ctr", "notes": {}}],
        "mac": [{"algorithm": "hmac-sha1", "notes": {"warn": ["using weak MAC"]}}],
        "fingerprints": [],
        "cves": ["CVE-2016-0777", {"cve": "CVE-2020-14145"}],
        "recommendations": ["remove diffie-hellman-group1-sha1"],
        "additional_notes": [],
    }
)

SSLSCAN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<document title="SSLScan Results" version="2.1.5">
 <ssltest host="lab.test" sniname="lab.test" port="443">
  <protocol type="ssl" version="2" enabled="1" />
  <protocol type="tls" version="1.0" enabled="1" />
  <protocol type="tls" version="1.2" enabled="1" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="128" cipher="RC4-SHA"
      id="0x0005" strength="weak" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="DES-CBC3-SHA"
      id="0x000A" strength="medium" />
  <cipher status="preferred" sslversion="TLSv1.2" bits="128"
      cipher="ECDHE-RSA-AES128-GCM-SHA256" id="0xC02F" strength="strong" />
  <heartbleed sslversion="TLSv1.2" vulnerable="1" />
  <compression supported="1" />
 </ssltest>
</document>
"""

DNSENUM_XML = """<?xml version="1.0"?>
<magictree class="MtBranchObject">
<testdata class="MtBranchObject">
<host>93.184.216.34<hostname>www.lab.test</hostname></host>
<host>93.184.216.35<hostname>mail.lab.test</hostname></host>
<fqdn>www.lab.test.</fqdn>
<fqdn>vpn.lab.test.</fqdn>
</testdata>
</magictree>
"""

THEHARVESTER_JSONL = "\n".join(
    [
        json.dumps({"type": "summary", "domain": "lab.test"}),
        json.dumps(
            {
                "type": "hostname",
                "value": "www.lab.test",
                "sources": ["crtsh"],
                "actions": [],
            }
        ),
        json.dumps(
            {
                "type": "email",
                "value": "admin@lab.test",
                "sources": ["certspotter"],
                "actions": [],
            }
        ),
        json.dumps(
            {
                "type": "ip",
                "value": "93.184.216.34",
                "sources": ["hackertarget"],
                "actions": [],
            }
        ),
        json.dumps(
            {
                "type": "takeover",
                "value": "cdn.lab.test",
                "sources": ["crtsh"],
                "actions": [],
            }
        ),
    ]
)

THEHARVESTER_LEGACY = json.dumps(
    {
        "cmd": "-d lab.test -b crtsh",
        "hosts": ["93.184.216.34:www.lab.test", "mail.lab.test"],
        "emails": ["admin@lab.test"],
        "ips": ["93.184.216.34"],
        "asns": ["AS15133"],
    }
)

GOSPIDER_JSONL = "\n".join(
    [
        json.dumps(
            {
                "input": "https://lab.test",
                "source": "https://lab.test",
                "type": "url",
                "output": "https://lab.test/about",
                "status": 200,
                "length": 512,
            }
        ),
        json.dumps(
            {
                "input": "https://lab.test",
                "source": "https://lab.test/app.js",
                "type": "subdomain",
                "output": "api.lab.test",
                "status": 0,
                "length": 0,
            }
        ),
        json.dumps(
            {
                "input": "https://lab.test",
                "source": "https://lab.test/upload",
                "type": "upload-form",
                "output": "https://lab.test/upload",
                "status": 200,
                "length": 128,
            }
        ),
        json.dumps(
            {
                "input": "https://lab.test",
                "source": "https://lab.test/app.js",
                "type": "aws",
                "output": "AKIAIOSFODNN7EXAMPLE",
                "status": 0,
                "length": 0,
            }
        ),
        "not json at all",
    ]
)

SHUFFLEDNS_JSONL = "\n".join(
    [
        json.dumps({"hostname": "www.lab.test"}),
        json.dumps({"hostname": "api.lab.test"}),
        json.dumps({"hostname": "www.lab.test"}),
    ]
)


class TestSshAudit:
    def test_argv_explicit_port(self) -> None:
        from cyberpowerfull.tools.ssh_audit import SshAuditTool

        tool = SshAuditTool()
        argv = tool.build_argv(tool.validate({"target": "lab.test", "port": 2222}))
        assert argv == ["ssh-audit", "-j", "lab.test:2222"]

    def test_success_codes_include_warning_and_failure(self) -> None:
        from cyberpowerfull.tools.ssh_audit import SshAuditTool

        tool = SshAuditTool()
        assert tool.exit_succeeded(0, "", "")
        assert tool.exit_succeeded(2, "", "")
        assert tool.exit_succeeded(3, "", "")
        assert not tool.exit_succeeded(1, "", "")

    def test_parse_collects_algorithms_and_cves(self) -> None:
        from cyberpowerfull.tools.ssh_audit import SshAuditTool

        tool = SshAuditTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), SSH_AUDIT_JSON)
        by_title = {finding.title: finding for finding in findings}
        assert by_title["Weak SSH kex algorithm: diffie-hellman-group1-sha1"].severity == "medium"
        assert "KexAlgorithms" in (
            by_title["Weak SSH kex algorithm: diffie-hellman-group1-sha1"].remediation or ""
        )
        assert by_title["Weak SSH key algorithm: ssh-rsa"].severity == "low"
        assert by_title["Weak SSH mac algorithm: hmac-sha1"].severity == "low"
        assert "CVE-2016-0777" in by_title["SSH software may be affected by CVE-2016-0777"].title
        assert len(findings) == 5

    def test_parse_rejects_non_json(self) -> None:
        from cyberpowerfull.tools.ssh_audit import SshAuditTool

        tool = SshAuditTool()
        assert tool.parse(tool.validate({"target": "lab.test"}), "banner text") == []


class TestSslscan:
    def test_argv_uses_xml_file_and_sni(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.sslscan import SslscanTool

        tool = SslscanTool()
        out = tmp_path / "output.json"
        argv = tool.build_argv(tool.validate({"target": "lab.test", "sni": "lab.test"}), str(out))
        assert argv == [
            "sslscan",
            "--no-colour",
            f"--xml={out}",
            "--sni-name=lab.test",
            "lab.test:443",
        ]

    def test_parse_reports_protocols_ciphers_heartbleed(self) -> None:
        from cyberpowerfull.tools.sslscan import SslscanTool

        tool = SslscanTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), SSLSCAN_XML)
        by_title = {finding.title: finding for finding in findings}
        assert by_title["Legacy protocol enabled: SSLv2"].severity == "high"
        assert by_title["Legacy protocol enabled: TLSv1.0"].severity == "medium"
        assert by_title["Weak TLS cipher accepted: RC4-SHA"].severity == "medium"
        assert by_title["Weak TLS cipher accepted: DES-CBC3-SHA"].severity == "low"
        assert by_title["Heartbleed vulnerability detected (CVE-2014-0160)"].severity == "critical"
        assert by_title["TLS compression enabled (CRIME)"].severity == "low"
        assert len(findings) == 6

    def test_validate_rejects_bad_sni(self) -> None:
        from cyberpowerfull.tools.sslscan import SslscanTool

        with pytest.raises(InvalidToolArguments):
            SslscanTool().validate({"target": "lab.test", "sni": "not a host!"})


class TestDnsenum:
    def test_argv_orders_domain_last(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.dnsenum import DnsenumTool

        wordlist = tmp_path / "subs.txt"
        wordlist.write_text("www\n", encoding="utf-8")
        tool = DnsenumTool()
        out = tmp_path / "output.json"
        argv = tool.build_argv(
            tool.validate({"target": "lab.test", "bruteforce": True, "wordlist": str(wordlist)}),
            str(out),
        )
        assert argv[-1] == "lab.test"
        assert argv[:6] == ["dnsenum", "--threads", "5", "-t", "10", "--nocolor"]
        assert "-o" in argv and "-f" in argv

    def test_validate_enforces_wordlist_rules(self) -> None:
        from cyberpowerfull.tools.dnsenum import DnsenumTool

        with pytest.raises(InvalidToolArguments):
            DnsenumTool().validate({"target": "lab.test", "bruteforce": True})
        with pytest.raises(InvalidToolArguments):
            DnsenumTool().validate({"target": "lab.test", "recursion": True})

    def test_parse_collects_hosts_and_fqdns(self) -> None:
        from cyberpowerfull.tools.dnsenum import DnsenumTool

        tool = DnsenumTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), DNSENUM_XML)
        titles = [finding.title for finding in findings]
        assert titles == [
            "Subdomain discovered: www.lab.test",
            "Subdomain discovered: mail.lab.test",
            "Subdomain discovered: vpn.lab.test",
        ]
        assert "93.184.216.34" in (findings[0].evidence or "")


class TestTheharvester:
    def test_argv_caps_and_quiets(self) -> None:
        from cyberpowerfull.tools.theharvester import TheharvesterTool

        tool = TheharvesterTool()
        argv = tool.build_argv(tool.validate({"target": "lab.test"}), "/tmp/x/output.json")
        assert argv == [
            "theHarvester",
            "-d",
            "lab.test",
            "-b",
            "subdomains",
            "-l",
            "100",
            "-q",
            "-f",
            "/tmp/x/output.json",
        ]

    def test_validate_rejects_named_sources(self) -> None:
        from cyberpowerfull.tools.theharvester import TheharvesterTool

        with pytest.raises(InvalidToolArguments):
            TheharvesterTool().validate({"target": "lab.test", "sources": ["crtsh"]})

    def test_parse_jsonl_skips_summary(self) -> None:
        from cyberpowerfull.tools.theharvester import TheharvesterTool

        tool = TheharvesterTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), THEHARVESTER_JSONL)
        assert [finding.title for finding in findings] == [
            "Host discovered: www.lab.test",
            "Email address harvested: admin@lab.test",
            "IP address harvested: 93.184.216.34",
            "Possible subdomain takeover: cdn.lab.test",
        ]
        assert findings[3].severity == "medium"
        assert "crtsh" in (findings[0].evidence or "")

    def test_parse_prefers_jsonl_sibling(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.theharvester import TheharvesterTool

        out = tmp_path / "output.json"
        out.write_text(THEHARVESTER_LEGACY, encoding="utf-8")
        (tmp_path / "output.jsonl").write_text(THEHARVESTER_JSONL, encoding="utf-8")
        tool = TheharvesterTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), THEHARVESTER_LEGACY, str(out))
        assert any("takeover" in finding.title for finding in findings)

    def test_parse_legacy_json_splits_ip_host(self) -> None:
        from cyberpowerfull.tools.theharvester import TheharvesterTool

        tool = TheharvesterTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), THEHARVESTER_LEGACY)
        titles = [finding.title for finding in findings]
        assert "Host discovered: www.lab.test" in titles
        assert "Host discovered: mail.lab.test" in titles
        assert "Email address harvested: admin@lab.test" in titles


class TestGospider:
    def test_argv_defaults(self) -> None:
        from cyberpowerfull.tools.gospider import GospiderTool

        tool = GospiderTool()
        argv = tool.build_argv(tool.validate({"target": "https://lab.test"}))
        assert argv == [
            "gospider",
            "-s",
            "https://lab.test",
            "-d",
            "1",
            "-c",
            "5",
            "-m",
            "10",
            "-k",
            "0",
            "--json",
        ]

    def test_parse_types_and_aws_key(self) -> None:
        from cyberpowerfull.tools.gospider import GospiderTool

        tool = GospiderTool()
        findings = tool.parse(tool.validate({"target": "https://lab.test"}), GOSPIDER_JSONL)
        by_title = {finding.title: finding for finding in findings}
        assert by_title["Crawled URL: https://lab.test/about"].severity == "info"
        assert by_title["Subdomain discovered: api.lab.test"].severity == "info"
        assert by_title["File-upload form: https://lab.test/upload"].severity == "low"
        assert by_title["Possible AWS access key in crawled content"].severity == "high"
        assert len(findings) == 4


class TestShuffledns:
    def test_argv_stages_resolvers_next_to_output(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.shuffledns import ShufflednsTool

        wordlist = tmp_path / "subs.txt"
        wordlist.write_text("www\n", encoding="utf-8")
        out = tmp_path / "output.json"
        tool = ShufflednsTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": "lab.test",
                    "wordlist": str(wordlist),
                    "resolvers": ["1.1.1.1", "9.9.9.9"],
                    "verify_resolvers": ["8.8.8.8"],
                }
            ),
            str(out),
        )
        assert argv[:5] == ["shuffledns", "-d", "lab.test", "-mode", "bruteforce"]
        resolvers_file = tmp_path / "cpf-resolvers.txt"
        assert argv[argv.index("-r") + 1] == str(resolvers_file)
        assert resolvers_file.read_text(encoding="utf-8") == "1.1.1.1\n9.9.9.9\n"
        assert "-o" in argv and "-j" in argv and "-duc" in argv

    def test_argv_requires_out_file(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.shuffledns import ShufflednsTool

        wordlist = tmp_path / "subs.txt"
        wordlist.write_text("www\n", encoding="utf-8")
        tool = ShufflednsTool()
        with pytest.raises(InvalidToolArguments):
            tool.build_argv(
                tool.validate(
                    {
                        "target": "lab.test",
                        "wordlist": str(wordlist),
                        "resolvers": ["1.1.1.1"],
                    }
                )
            )

    def test_validate_enforces_mode_files(self) -> None:
        from cyberpowerfull.tools.shuffledns import ShufflednsTool

        with pytest.raises(InvalidToolArguments):
            ShufflednsTool().validate({"target": "lab.test", "resolvers": ["1.1.1.1"]})
        with pytest.raises(InvalidToolArguments):
            ShufflednsTool().validate(
                {
                    "target": "lab.test",
                    "mode": "resolve",
                    "subdomains_file": "/tmp/s.txt",
                    "wordlist": "/tmp/w.txt",
                    "resolvers": ["1.1.1.1"],
                }
            )

    def test_parse_dedupes_hostnames(self) -> None:
        from cyberpowerfull.tools.shuffledns import ShufflednsTool

        tool = ShufflednsTool()
        findings = tool.parse(
            tool.validate(
                {
                    "target": "lab.test",
                    "mode": "resolve",
                    "subdomains_file": "/tmp/s.txt",
                    "resolvers": ["1.1.1.1"],
                }
            ),
            SHUFFLEDNS_JSONL,
        )
        assert [finding.title for finding in findings] == [
            "Subdomain discovered: www.lab.test",
            "Subdomain discovered: api.lab.test",
        ]


class TestSprint1Gates:
    def test_worker_blocks_theharvester_without_passive_sources(self, scope: Scope) -> None:
        from cyberpowerfull.tools.theharvester import TheharvesterTool

        worker = WorkerAgent("recon", scope=scope, tools={"theharvester": TheharvesterTool()})
        result = worker.execute(
            DelegationRequest(agent="recon", tool="theharvester", args={"target": "lab.test"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allow_passive_sources" in (result.error or "")

    def test_worker_blocks_gospider_third_party_without_passive_sources(self, scope: Scope) -> None:
        from cyberpowerfull.tools.gospider import GospiderTool

        worker = WorkerAgent("recon", scope=scope, tools={"gospider": GospiderTool()})
        result = worker.execute(
            DelegationRequest(
                agent="recon",
                tool="gospider",
                args={"target": "https://lab.test", "other_source": True},
            )
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allow_passive_sources" in (result.error or "")

    def test_worker_blocks_dnsenum_scraping_without_passive_sources(self, scope: Scope) -> None:
        from cyberpowerfull.tools.dnsenum import DnsenumTool

        worker = WorkerAgent("recon", scope=scope, tools={"dnsenum": DnsenumTool()})
        result = worker.execute(
            DelegationRequest(
                agent="recon",
                tool="dnsenum",
                args={"target": "lab.test", "scrap_subdomains": 15},
            )
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allow_passive_sources" in (result.error or "")

    def test_worker_blocks_dnsenum_bruteforce_without_allowlisted_wordlist(
        self, scope: Scope
    ) -> None:
        from cyberpowerfull.tools.dnsenum import DnsenumTool

        worker = WorkerAgent("recon", scope=scope, tools={"dnsenum": DnsenumTool()})
        result = worker.execute(
            DelegationRequest(
                agent="recon",
                tool="dnsenum",
                args={"target": "lab.test", "bruteforce": True, "wordlist": "/tmp/evil.txt"},
            )
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allowed_wordlists" in (result.error or "")

    def test_worker_blocks_shuffledns_resolve_without_allowlisted_list(self, scope: Scope) -> None:
        from cyberpowerfull.tools.shuffledns import ShufflednsTool

        worker = WorkerAgent("recon", scope=scope, tools={"shuffledns": ShufflednsTool()})
        result = worker.execute(
            DelegationRequest(
                agent="recon",
                tool="shuffledns",
                args={
                    "target": "lab.test",
                    "mode": "resolve",
                    "subdomains_file": "/tmp/evil.txt",
                    "resolvers": ["1.1.1.1"],
                },
            )
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allowed_wordlists" in (result.error or "")


class TestSprint1Observations:
    def test_ssh_audit_observations_summarise(self) -> None:
        from cyberpowerfull.tools.ssh_audit import SshAuditTool

        tool = SshAuditTool()
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), SSH_AUDIT_JSON)
        assert "OpenSSH_7.4" in note
        assert "recommendations=1" in note
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), "garbage")
        assert "not JSON" in note

    def test_sslscan_observations_count_elements(self) -> None:
        from cyberpowerfull.tools.sslscan import SslscanTool

        tool = SslscanTool()
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), SSLSCAN_XML)
        assert "protocol=3" in note
        assert "cipher=3" in note
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), "garbage")
        assert "not XML" in note

    def test_dnsenum_observations_count_hosts(self) -> None:
        from cyberpowerfull.tools.dnsenum import DnsenumTool

        tool = DnsenumTool()
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), DNSENUM_XML)
        assert "4 hostname(s)" in note
        assert "2 with address(es)" in note

    def test_theharvester_observations_count_kinds(self) -> None:
        from cyberpowerfull.tools.theharvester import TheharvesterTool

        tool = TheharvesterTool()
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), THEHARVESTER_JSONL)
        assert "4 record(s)" in note
        assert "hostname=1" in note

    def test_gospider_observations_count_kinds(self) -> None:
        from cyberpowerfull.tools.gospider import GospiderTool

        tool = GospiderTool()
        (note,) = tool.observations(tool.validate({"target": "https://lab.test"}), GOSPIDER_JSONL)
        assert "4 record(s)" in note
        assert "aws=1" in note

    def test_shuffledns_observations_count_hosts(self) -> None:
        from cyberpowerfull.tools.shuffledns import ShufflednsTool

        tool = ShufflednsTool()
        args = tool.validate(
            {
                "target": "lab.test",
                "mode": "resolve",
                "subdomains_file": "/tmp/s.txt",
                "resolvers": ["1.1.1.1"],
            }
        )
        (note,) = tool.observations(args, SHUFFLEDNS_JSONL)
        assert "3 hostname(s)" in note


class TestSprint1Caps:
    def test_max_findings_caps_each_tool(self) -> None:
        from cyberpowerfull.tools.dnsenum import DnsenumTool
        from cyberpowerfull.tools.gospider import GospiderTool
        from cyberpowerfull.tools.shuffledns import ShufflednsTool
        from cyberpowerfull.tools.ssh_audit import SshAuditTool
        from cyberpowerfull.tools.sslscan import SslscanTool
        from cyberpowerfull.tools.theharvester import TheharvesterTool

        cases = [
            (SshAuditTool(), {"target": "lab.test", "max_findings": 2}, SSH_AUDIT_JSON),
            (SslscanTool(), {"target": "lab.test", "max_findings": 2}, SSLSCAN_XML),
            (DnsenumTool(), {"target": "lab.test", "max_findings": 1}, DNSENUM_XML),
            (
                TheharvesterTool(),
                {"target": "lab.test", "max_findings": 2},
                THEHARVESTER_JSONL,
            ),
            (
                GospiderTool(),
                {"target": "https://lab.test", "max_findings": 2},
                GOSPIDER_JSONL,
            ),
            (
                ShufflednsTool(),
                {
                    "target": "lab.test",
                    "mode": "resolve",
                    "subdomains_file": "/tmp/s.txt",
                    "resolvers": ["1.1.1.1"],
                    "max_findings": 1,
                },
                SHUFFLEDNS_JSONL,
            ),
        ]
        for tool, raw_args, output in cases:
            findings = tool.parse(tool.validate(raw_args), output)
            assert len(findings) == raw_args["max_findings"], tool.name
