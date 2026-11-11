"""Pillar 1 Sprint 2: sslyze, dirsearch, enum4linux, gau, exiftool, sherlock."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberpowerfull.brain.orchestrator import DelegationRequest, WorkerAgent
from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.scope import Scope
from cyberpowerfull.tools.base import ToolStatus


def _attempt(result: dict | None, status: str = "COMPLETED") -> dict:
    return {"status": status, "error_reason": None, "error_trace": None, "result": result}


def _cipher_result(supported: bool, suites: list) -> dict:
    return {
        "tls_version_used": "TLS 1.0",
        "is_tls_version_supported": supported,
        "accepted_cipher_suites": suites,
        "rejected_cipher_suites": [],
    }


def _suite(openssl_name: str, anonymous: bool, key_size: int) -> dict:
    return {
        "cipher_suite": {
            "name": openssl_name,
            "is_anonymous": anonymous,
            "key_size": key_size,
            "openssl_name": openssl_name,
        },
        "ephemeral_key": None,
    }


SSLYZE_JSON = json.dumps(
    {
        "invalid_server_strings": [],
        "server_scan_results": [
            {
                "uuid": "00000000-0000-0000-0000-000000000000",
                "scan_result": {
                    "ssl_2_0_cipher_suites": _attempt(
                        _cipher_result(True, [_suite("DES-CBC3-MD5", False, 112)])
                    ),
                    "ssl_3_0_cipher_suites": _attempt(_cipher_result(False, [])),
                    "tls_1_0_cipher_suites": _attempt(
                        _cipher_result(True, [_suite("ADH-AES256-SHA", True, 256)])
                    ),
                    "tls_1_1_cipher_suites": _attempt(_cipher_result(False, [])),
                    "tls_1_2_cipher_suites": _attempt(
                        _cipher_result(True, [_suite("ECDHE-RSA-AES128-GCM-SHA256", False, 128)])
                    ),
                    "tls_1_3_cipher_suites": _attempt(None, status="ERROR"),
                    "tls_compression": _attempt({"compression_name": "deflate"}),
                    "heartbleed": _attempt({"is_vulnerable_to_heartbleed": False}),
                    "openssl_ccs_injection": _attempt({"is_vulnerable_to_ccs_injection": True}),
                    "robot": _attempt({"robot_result": "VULNERABLE_WEAK_ORACLE"}),
                    "tls_fallback_scsv": _attempt({"supports_fallback_scsv": False}),
                    "session_renegotiation": _attempt(
                        {
                            "supports_secure_renegotiation": False,
                            "is_vulnerable_to_client_renegotiation_dos": False,
                        }
                    ),
                },
            }
        ],
        "date_scans_started": "2026-11-11T00:00:00",
        "date_scans_completed": "2026-11-11T00:01:00",
    }
)

DIRSEARCH_JSON = json.dumps(
    {
        "info": {"args": "dirsearch -u https://lab.test", "time": "2026-11-11"},
        "results": [
            {
                "url": "https://lab.test/admin/",
                "status": 200,
                "contentLength": 1024,
                "contentType": "text/html",
                "redirect": "",
            },
            {
                "url": "https://lab.test/backup.zip",
                "status": 200,
                "contentLength": 2048,
                "contentType": "application/zip",
                "redirect": "",
            },
            {
                "url": "https://lab.test/secret/",
                "status": 403,
                "contentLength": 512,
                "contentType": "text/html",
                "redirect": "",
            },
        ],
    }
)

ENUM4LINUX_JSON = json.dumps(
    {
        "sessions_possible": True,
        "null_session_possible": True,
        "user_session_possible": False,
        "random_user_session_possible": False,
        "users": {
            "500": {"username": "Administrator", "name": "Admin", "description": "Built-in"},
            "501": {"username": "Guest"},
        },
        "groups": {"Administrators": {}},
        "shares": {
            "IPC$": {"type": "IPC", "comment": "IPC Service"},
            "Public": {
                "type": "Disk",
                "comment": "",
                "access": {"mapping": "ok", "listing": "ok"},
            },
        },
        "policy": {"domain_password_information": {"min_pw_length": 6}},
        "os_info": {"os": "Windows 10 / Server 2019", "os_version": "10.0"},
        "errors": {},
    }
)

GAU_JSONL = "\n".join(
    [
        json.dumps({"url": "https://lab.test/about"}),
        json.dumps({"url": "https://api.lab.test/v1/users"}),
        json.dumps({"url": "https://lab.test/search?q=test"}),
        "not json",
    ]
)

EXIFTOOL_JSON = json.dumps(
    [
        {
            "SourceFile": "photo.jpg",
            "GPSLatitude": 24.8614622,
            "GPSLongitude": 67.0099388,
            "Author": "lab-tester",
            "Software": "GIMP 2.10",
            "FileName": "photo.jpg",
        },
        {"SourceFile": "plain.txt", "FileName": "plain.txt", "FileSize": 12},
    ]
)

SHERLOCK_CSV = "\n".join(
    [
        "username,name,url_main,url_user,exists,http_status,response_time_s",
        "labtester,GitHub,https://github.com,https://github.com/labtester,Claimed,200,0.4",
        "labtester,GitLab,https://gitlab.com,https://gitlab.com/labtester,Available,404,0.3",
    ]
)


class TestSslyze:
    def test_argv_uses_short_scan_flags(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.sslyze import SslyzeTool

        tool = SslyzeTool()
        out = tmp_path / "output.json"
        argv = tool.build_argv(tool.validate({"target": "lab.test"}), str(out))
        assert argv[0] == "sslyze"
        assert argv[-1] == "lab.test:443"
        for flag in ("--sslv2", "--tlsv1_1", "--compression", "--openssl_ccs", "--reneg"):
            assert flag in argv
        assert argv[argv.index("--json_out") + 1] == str(out)

    def test_parse_reports_versions_ciphers_and_probes(self) -> None:
        from cyberpowerfull.tools.sslyze import SslyzeTool

        tool = SslyzeTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), SSLYZE_JSON)
        by_title = {finding.title: finding for finding in findings}
        assert by_title["Legacy protocol enabled: SSLv2"].severity == "high"
        assert by_title["Legacy protocol enabled: TLSv1.0"].severity == "medium"
        assert by_title["Anonymous TLS cipher accepted: ADH-AES256-SHA"].severity == "high"
        assert by_title["Short-key TLS cipher accepted: DES-CBC3-MD5"].severity == "medium"
        assert by_title["TLS compression enabled (CRIME)"].severity == "low"
        assert by_title["OpenSSL CCS injection vulnerability (CVE-2014-0224)"].severity == "high"
        assert by_title["ROBOT oracle (weak): attack theoretically possible"].severity == "medium"
        assert by_title["TLS_FALLBACK_SCSV not supported (downgrade risk)"].severity == "low"
        assert by_title["Insecure TLS renegotiation (CVE-2009-3555)"].severity == "medium"
        assert len(findings) == 9

    def test_parse_skips_errored_attempts(self) -> None:
        from cyberpowerfull.tools.sslyze import SslyzeTool

        tool = SslyzeTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), SSLYZE_JSON)
        assert not [finding for finding in findings if "1.3" in finding.title]


class TestDirsearch:
    def test_argv_json_report_and_filters(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.dirsearch import DirsearchTool

        wordlist = tmp_path / "paths.txt"
        wordlist.write_text("admin\n", encoding="utf-8")
        out = tmp_path / "output.json"
        tool = DirsearchTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": "https://lab.test",
                    "wordlist": str(wordlist),
                    "extensions": ["php", "zip"],
                    "exclude_status": ["403", "500-599"],
                    "recursive": True,
                    "max_recursion_depth": 2,
                }
            ),
            str(out),
        )
        assert argv[:6] == ["dirsearch", "-u", "https://lab.test", "-w", str(wordlist), "-t"]
        assert "-e" in argv and "php,zip" in argv
        assert "-x" in argv and "403,500-599" in argv
        assert argv[-4:] == ["-O", "json", "-o", str(out)]

    def test_validate_rejects_bad_extension_and_status(self) -> None:
        from cyberpowerfull.tools.dirsearch import DirsearchTool

        with pytest.raises(InvalidToolArguments):
            DirsearchTool().validate(
                {"target": "https://lab.test", "wordlist": "/tmp/w.txt", "extensions": ["p/h/p"]}
            )
        with pytest.raises(InvalidToolArguments):
            DirsearchTool().validate(
                {"target": "https://lab.test", "wordlist": "/tmp/w.txt", "exclude_status": ["99"]}
            )
        with pytest.raises(InvalidToolArguments):
            DirsearchTool().validate(
                {
                    "target": "https://lab.test",
                    "wordlist": "/tmp/w.txt",
                    "max_recursion_depth": 2,
                }
            )

    def test_parse_flags_sensitive_extensions(self) -> None:
        from cyberpowerfull.tools.dirsearch import DirsearchTool

        tool = DirsearchTool()
        findings = tool.parse(
            tool.validate({"target": "https://lab.test", "wordlist": "/tmp/w.txt"}),
            DIRSEARCH_JSON,
        )
        by_title = {finding.title: finding for finding in findings}
        assert by_title["Discovered path: https://lab.test/admin/"].severity == "info"
        assert by_title["Sensitive file exposure: https://lab.test/backup.zip"].severity == "low"
        assert len(findings) == 3


class TestEnum4linux:
    def test_argv_strips_json_suffix_for_oj(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.enum4linux import Enum4linuxTool

        tool = Enum4linuxTool()
        out = tmp_path / "output.json"
        argv = tool.build_argv(tool.validate({"target": "10.0.0.8"}), str(out))
        assert argv[0] == "enum4linux-ng"
        assert argv[argv.index("-oJ") + 1] == str(tmp_path / "output")
        assert argv[-3:] == ["-t", "5", "10.0.0.8"]
        for flag in ("-U", "-G", "-S", "-P", "-O", "-N", "-I", "-L"):
            assert flag in argv

    def test_validate_rejects_unknown_module(self) -> None:
        from cyberpowerfull.tools.enum4linux import Enum4linuxTool

        with pytest.raises(InvalidToolArguments):
            Enum4linuxTool().validate({"target": "10.0.0.8", "modules": ["rid_cycle"]})

    def test_parse_sessions_users_shares_policy(self) -> None:
        from cyberpowerfull.tools.enum4linux import Enum4linuxTool

        tool = Enum4linuxTool()
        findings = tool.parse(tool.validate({"target": "10.0.0.8"}), ENUM4LINUX_JSON)
        by_title = {finding.title: finding for finding in findings}
        assert by_title["SMB null session allowed"].severity == "medium"
        assert by_title["SMB user enumerated: Administrator"].severity == "info"
        assert by_title["SMB group enumerated: Administrators"].severity == "info"
        assert by_title["Readable SMB share: Public"].severity == "low"
        assert by_title["SMB share enumerated: IPC$"].severity == "info"
        assert by_title["Weak domain password policy: minimum length 6"].severity == "low"
        assert "Windows" in by_title["OS fingerprint: Windows 10 / Server 2019"].title
        assert len(findings) == 8


class TestGau:
    def test_argv_all_providers_explicit(self) -> None:
        from cyberpowerfull.tools.gau import GauTool

        tool = GauTool()
        argv = tool.build_argv(tool.validate({"target": "lab.test"}))
        assert argv[:3] == ["gau", "--json", "--providers"]
        assert argv[3] == "wayback,commoncrawl,otx,urlscan"
        assert "--fp" in argv
        assert argv[-1] == "lab.test"

    def test_validate_rejects_unknown_provider(self) -> None:
        from cyberpowerfull.tools.gau import GauTool

        with pytest.raises(InvalidToolArguments):
            GauTool().validate({"target": "lab.test", "providers": ["bing"]})

    def test_parse_subdomains_and_parameterised_urls(self) -> None:
        from cyberpowerfull.tools.gau import GauTool

        tool = GauTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), GAU_JSONL)
        by_title = {finding.title: finding for finding in findings}
        assert by_title["Historical URL: https://lab.test/about"].severity == "info"
        assert by_title["Subdomain discovered: api.lab.test"].severity == "info"
        assert (
            by_title["Historical parameterised URL: https://lab.test/search?q=test"].severity
            == "low"
        )
        assert len(findings) == 3


class TestExiftool:
    def test_argv_json_short_names(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.exiftool import ExiftoolTool

        target = tmp_path / "photo.jpg"
        target.write_bytes(b"fake")
        tool = ExiftoolTool()
        argv = tool.build_argv(tool.validate({"target": str(target), "recursive": True}))
        assert argv == ["exiftool", "-j", "-s", "-r", str(target)]

    def test_validate_rejects_missing_path(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.exiftool import ExiftoolTool

        with pytest.raises(InvalidToolArguments):
            ExiftoolTool().validate({"target": str(tmp_path / "nope.jpg")})

    def test_parse_gps_author_and_software(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.exiftool import ExiftoolTool

        target = tmp_path / "photo.jpg"
        target.write_bytes(b"fake")
        tool = ExiftoolTool()
        findings = tool.parse(tool.validate({"target": str(target)}), EXIFTOOL_JSON)
        assert findings[0].severity == "medium"
        assert "GPS coordinates" in findings[0].title
        assert "24.8614622" in (findings[0].evidence or "")
        assert findings[1].severity == "info" and "Author" in findings[1].title
        assert findings[2].severity == "info" and "GIMP" in (findings[2].evidence or "")
        assert len(findings) == 3


class TestSherlock:
    def test_argv_csv_into_results_folder(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.sherlock import SherlockTool

        tool = SherlockTool()
        out = tmp_path / "output.json"
        argv = tool.build_argv(tool.validate({"target": "labtester"}), str(out))
        assert argv == [
            "sherlock",
            "labtester",
            "--csv",
            "--print-found",
            "--no-color",
            "--timeout",
            "60",
            "--folderoutput",
            str(tmp_path),
            "--local",
        ]

    def test_argv_requires_out_file(self) -> None:
        from cyberpowerfull.tools.sherlock import SherlockTool

        with pytest.raises(InvalidToolArguments):
            SherlockTool().build_argv(SherlockTool().validate({"target": "labtester"}))

    def test_validate_rejects_path_traversal_username(self) -> None:
        from cyberpowerfull.tools.sherlock import SherlockTool

        with pytest.raises(InvalidToolArguments):
            SherlockTool().validate({"target": "../evil"})
        with pytest.raises(InvalidToolArguments):
            SherlockTool().validate({"target": "-json"})

    def test_parse_claimed_rows_from_sibling_csv(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.sherlock import SherlockTool

        out = tmp_path / "output.json"
        (tmp_path / "labtester.csv").write_text(SHERLOCK_CSV, encoding="utf-8")
        tool = SherlockTool()
        findings = tool.parse(tool.validate({"target": "labtester"}), "console text", str(out))
        assert [finding.title for finding in findings] == ["Username found: GitHub"]
        assert findings[0].endpoint == "https://github.com/labtester"

    def test_parse_falls_back_to_output_text(self) -> None:
        from cyberpowerfull.tools.sherlock import SherlockTool

        tool = SherlockTool()
        findings = tool.parse(tool.validate({"target": "labtester"}), SHERLOCK_CSV)
        assert [finding.title for finding in findings] == ["Username found: GitHub"]


class TestSprint2Gates:
    def test_worker_blocks_gau_without_passive_sources(self, scope: Scope) -> None:
        from cyberpowerfull.tools.gau import GauTool

        worker = WorkerAgent("recon", scope=scope, tools={"gau": GauTool()})
        result = worker.execute(
            DelegationRequest(agent="recon", tool="gau", args={"target": "lab.test"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allow_passive_sources" in (result.error or "")

    def test_worker_blocks_sherlock_without_passive_sources(self, scope: Scope) -> None:
        from cyberpowerfull.tools.sherlock import SherlockTool

        worker = WorkerAgent("recon", scope=scope, tools={"sherlock": SherlockTool()})
        result = worker.execute(
            DelegationRequest(agent="recon", tool="sherlock", args={"target": "labtester"})
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allow_passive_sources" in (result.error or "")

    def test_worker_blocks_dirsearch_without_allowlisted_wordlist(self, scope: Scope) -> None:
        from cyberpowerfull.tools.dirsearch import DirsearchTool

        worker = WorkerAgent("scan", scope=scope, tools={"dirsearch": DirsearchTool()})
        result = worker.execute(
            DelegationRequest(
                agent="scan",
                tool="dirsearch",
                args={"target": "https://lab.test", "wordlist": "/tmp/evil.txt"},
            )
        )
        assert result.status is ToolStatus.BLOCKED
        assert "allowed_wordlists" in (result.error or "")


class TestSprint2Observations:
    def test_sslyze_observations_count_commands(self) -> None:
        from cyberpowerfull.tools.sslyze import SslyzeTool

        tool = SslyzeTool()
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), SSLYZE_JSON)
        assert "11 completed command(s)" in note
        assert "3 accepted cipher suite(s)" in note

    def test_dirsearch_observations_count_statuses(self) -> None:
        from cyberpowerfull.tools.dirsearch import DirsearchTool

        tool = DirsearchTool()
        (note,) = tool.observations(
            tool.validate({"target": "https://lab.test", "wordlist": "/tmp/w.txt"}),
            DIRSEARCH_JSON,
        )
        assert "3 hit(s)" in note
        assert "200=2" in note

    def test_enum4linux_observations_summarise(self) -> None:
        from cyberpowerfull.tools.enum4linux import Enum4linuxTool

        tool = Enum4linuxTool()
        (note,) = tool.observations(tool.validate({"target": "10.0.0.8"}), ENUM4LINUX_JSON)
        assert "sessions_possible=True" in note
        assert "users=2" in note
        assert "shares=2" in note

    def test_gau_observations_count_urls(self) -> None:
        from cyberpowerfull.tools.gau import GauTool

        tool = GauTool()
        (note,) = tool.observations(tool.validate({"target": "lab.test"}), GAU_JSONL)
        assert "3 url(s)" in note

    def test_exiftool_observations_count_files(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.exiftool import ExiftoolTool

        target = tmp_path / "photo.jpg"
        target.write_bytes(b"fake")
        tool = ExiftoolTool()
        (note,) = tool.observations(tool.validate({"target": str(target)}), EXIFTOOL_JSON)
        assert "2 file(s)" in note

    def test_sherlock_observations_count_claimed(self) -> None:
        from cyberpowerfull.tools.sherlock import SherlockTool

        tool = SherlockTool()
        (note,) = tool.observations(tool.validate({"target": "labtester"}), SHERLOCK_CSV)
        assert "1 claimed site(s) out of 2 row(s)" in note
        (note,) = tool.observations(tool.validate({"target": "labtester"}), "[*] console text")
        assert note == "sherlock: results written to the run folder"


class TestSprint2Caps:
    def test_max_findings_caps_each_tool(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.dirsearch import DirsearchTool
        from cyberpowerfull.tools.enum4linux import Enum4linuxTool
        from cyberpowerfull.tools.exiftool import ExiftoolTool
        from cyberpowerfull.tools.gau import GauTool
        from cyberpowerfull.tools.sherlock import SherlockTool
        from cyberpowerfull.tools.sslyze import SslyzeTool

        photo = tmp_path / "photo.jpg"
        photo.write_bytes(b"fake")
        cases = [
            (SslyzeTool(), {"target": "lab.test", "max_findings": 2}, SSLYZE_JSON),
            (
                DirsearchTool(),
                {"target": "https://lab.test", "wordlist": "/tmp/w.txt", "max_findings": 2},
                DIRSEARCH_JSON,
            ),
            (Enum4linuxTool(), {"target": "10.0.0.8", "max_findings": 2}, ENUM4LINUX_JSON),
            (GauTool(), {"target": "lab.test", "max_findings": 2}, GAU_JSONL),
            (ExiftoolTool(), {"target": str(photo), "max_findings": 2}, EXIFTOOL_JSON),
            (SherlockTool(), {"target": "labtester", "max_findings": 1}, SHERLOCK_CSV),
        ]
        for tool, raw_args, output in cases:
            findings = tool.parse(tool.validate(raw_args), output)
            assert len(findings) == raw_args["max_findings"], tool.name
