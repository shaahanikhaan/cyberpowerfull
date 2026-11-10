"""Tool-layer tests: argv construction, parsing, and mocked subprocess execution."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest
from tests.conftest import (
    DALFOX_JSON,
    FFUF_JSON,
    HTTPX_JSONL,
    NIKTO_STDOUT,
    NMAP_XML,
    NUCLEI_JSONL,
    SQLMAP_STDOUT,
    SUBFINDER_STDOUT,
    completed,
)

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Phase, Severity
from cyberpowerfull.tools.base import ToolStatus, normalise_url
from cyberpowerfull.tools.dalfox import DalfoxTool
from cyberpowerfull.tools.ffuf import FfufTool
from cyberpowerfull.tools.httpx_probe import HttpxTool
from cyberpowerfull.tools.nikto import NiktoTool
from cyberpowerfull.tools.nmap import NmapTool
from cyberpowerfull.tools.nuclei import NucleiTool
from cyberpowerfull.tools.registry import catalog, get_tool, installed_tools, tool_names
from cyberpowerfull.tools.sqlmap import SqlmapTool
from cyberpowerfull.tools.subfinder import SubfinderTool
from cyberpowerfull.tools.tcp_probe import TcpProbeTool


def patch_subprocess(stdout: str = "", stderr: str = "", returncode: int = 0, side_effect=None):
    """Patch subprocess.run and shutil.which for a tool invocation."""
    if side_effect is None:
        run_mock = mock.patch(
            "cyberpowerfull.tools.base.subprocess.run",
            return_value=completed(stdout, stderr, returncode),
        )
    else:
        run_mock = mock.patch("cyberpowerfull.tools.base.subprocess.run", side_effect=side_effect)
    which_mock = mock.patch(
        "cyberpowerfull.tools.base.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"
    )
    return run_mock, which_mock


def _write_output_file(argv: list[str], content: str) -> None:
    for flag in ("-o", "--output"):
        if flag in argv:
            Path(argv[argv.index(flag) + 1]).write_text(content, encoding="utf-8")
            return


class TestNmapTool:
    def test_build_argv(self) -> None:
        tool = NmapTool()
        argv = tool.build_argv(tool.validate({"target": "127.0.0.1", "ports": "80,443"}))
        assert argv[:4] == ["nmap", "-oX", "-", "-Pn"]
        assert "-sV" in argv
        assert argv[argv.index("-p") + 1] == "80,443"
        assert argv[-1] == "127.0.0.1"

    def test_top_ports_flag(self) -> None:
        tool = NmapTool()
        argv = tool.build_argv(
            tool.validate({"target": "127.0.0.1", "ports": "top-100", "timing": 4})
        )
        assert argv[argv.index("--top-ports") + 1] == "100"
        assert "-T4" in argv

    def test_rejects_unknown_script(self) -> None:
        with pytest.raises(InvalidToolArguments):
            NmapTool().validate({"target": "127.0.0.1", "scripts": ["http-shellshock"]})

    def test_rejects_bad_ports(self) -> None:
        with pytest.raises(InvalidToolArguments):
            NmapTool().validate({"target": "127.0.0.1", "ports": "1; rm -rf /"})

    def test_parse_findings(self) -> None:
        tool = NmapTool()
        args = tool.validate({"target": "127.0.0.1"})
        findings = tool.parse(args, NMAP_XML)
        titles = [finding.title for finding in findings]
        assert "Open TCP port 22/tcp (ssh)" in titles
        assert "Open TCP port 80/tcp (http)" in titles
        assert not any("443" in title for title in titles), "closed ports must not be findings"
        version = [f for f in findings if "OpenSSH" in f.title]
        assert version and version[0].severity is Severity.LOW
        assert all(f.phase is Phase.SCANNING for f in findings)

    def test_parse_handles_garbage(self) -> None:
        tool = NmapTool()
        assert tool.parse(tool.validate({"target": "127.0.0.1"}), "<not-xml>") == []

    def test_run_with_mocked_subprocess(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout=NMAP_XML)
        with run_mock as run, which_mock:
            result = NmapTool().run({"target": "127.0.0.1", "ports": "22,80"})
        assert result.status is ToolStatus.OK
        assert len(result.findings) == 3
        assert run.call_args.kwargs["shell"] is not True
        assert run.call_args.kwargs["capture_output"] is True
        assert result.duration_ms >= 0

    def test_observations_include_nse(self) -> None:
        tool = NmapTool()
        notes = tool.observations(tool.validate({"target": "127.0.0.1"}), NMAP_XML)
        assert any("http-title" in note for note in notes)


class TestHttpxTool:
    def test_build_argv(self) -> None:
        tool = HttpxTool()
        argv = tool.build_argv(
            tool.validate({"target": "http://127.0.0.1:8080", "ports": [8080, 8443]})
        )
        assert argv[0] == "httpx"
        assert "-json" in argv
        assert argv[argv.index("-ports") + 1] == "8080,8443"

    def test_url_is_normalised(self) -> None:
        args = HttpxTool().validate({"target": "127.0.0.1:8080"})
        assert args.target == "https://127.0.0.1:8080"

    def test_parse_findings(self) -> None:
        tool = HttpxTool()
        findings = tool.parse(tool.validate({"target": "127.0.0.1"}), HTTPX_JSONL)
        titles = " ".join(finding.title for finding in findings)
        assert "Server banner discloses version" in titles
        assert "Technology fingerprint" in titles
        assert "Access-controlled endpoint" in titles

    def test_run_mocked(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout=HTTPX_JSONL)
        with run_mock, which_mock:
            result = HttpxTool().run({"target": "http://127.0.0.1:8080"})
        assert result.status is ToolStatus.OK
        assert len(result.findings) >= 3
        assert result.observations


class TestNucleiTool:
    def test_build_argv_disables_interactsh(self) -> None:
        tool = NucleiTool()
        argv = tool.build_argv(tool.validate({"target": "http://127.0.0.1", "tags": ["cve"]}))
        assert "-no-interactsh" in argv
        assert argv[argv.index("-tags") + 1] == "cve"

    def test_rejects_bad_template_path(self) -> None:
        with pytest.raises(InvalidToolArguments):
            NucleiTool().validate({"target": "http://127.0.0.1", "templates": "../../etc/passwd"})

    def test_rejects_unknown_severity(self) -> None:
        with pytest.raises(InvalidToolArguments):
            NucleiTool().validate({"target": "http://127.0.0.1", "severity": ["apocalyptic"]})

    def test_parse_critical_finding(self) -> None:
        tool = NucleiTool()
        findings = tool.parse(tool.validate({"target": "http://127.0.0.1"}), NUCLEI_JSONL)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity is Severity.CRITICAL
        assert finding.cwe == "CWE-22"
        assert finding.cve == "CVE-2021-41773"
        assert finding.cvss == 7.5
        assert finding.verified is True

    def test_run_mocked(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout=NUCLEI_JSONL)
        with run_mock, which_mock:
            result = NucleiTool().run({"target": "http://127.0.0.1"})
        assert result.status is ToolStatus.OK
        assert result.findings[0].severity is Severity.CRITICAL


class TestFfufTool:
    def test_requires_fuzz_keyword(self, tmp_path: Path) -> None:
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\n", encoding="utf-8")
        with pytest.raises(InvalidToolArguments):
            FfufTool().build_argv(
                FfufTool().validate({"target": "http://127.0.0.1/", "wordlist": str(wordlist)})
            )

    def test_requires_existing_wordlist(self) -> None:
        with pytest.raises(InvalidToolArguments):
            FfufTool().build_argv(
                FfufTool().validate(
                    {"target": "http://127.0.0.1/FUZZ", "wordlist": "/nonexistent/words.txt"}
                )
            )

    def test_parse(self) -> None:
        tool = FfufTool()
        args = tool.validate(
            {"target": "http://127.0.0.1/FUZZ", "wordlist": "/usr/share/wordlists/x.txt"}
        )
        findings = tool.parse(args, FFUF_JSON)
        assert len(findings) == 3
        assert findings[1].severity is Severity.LOW  # 403
        assert findings[0].endpoint == "http://127.0.0.1/admin"

    def test_run_writes_to_output_file(self, tmp_path: Path) -> None:
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\n", encoding="utf-8")

        def fake_run(argv, **kwargs):
            _write_output_file(argv, FFUF_JSON)
            return completed("", "", 1)

        run_mock, which_mock = patch_subprocess(side_effect=fake_run)
        with run_mock, which_mock:
            result = FfufTool().run({"target": "http://127.0.0.1/FUZZ", "wordlist": str(wordlist)})
        assert result.status is ToolStatus.OK  # exit code 1 is "no match" for ffuf
        assert len(result.findings) == 3
        assert any("structured output file" in note for note in result.observations)


class TestSqlmapTool:
    def test_build_argv_is_confirmation_only(self) -> None:
        tool = SqlmapTool()
        argv = tool.build_argv(
            tool.validate({"target": "http://127.0.0.1/item?id=1", "parameter": "id"})
        )
        assert "--batch" in argv
        assert "--level=2" in argv
        assert not any(flag in argv for flag in ("--os-shell", "--dump", "--file-read"))

    def test_rejects_bad_technique(self) -> None:
        with pytest.raises(InvalidToolArguments):
            SqlmapTool().validate({"target": "http://127.0.0.1/?id=1", "technique": "XYZ"})

    def test_rejects_multiline_data(self) -> None:
        with pytest.raises(InvalidToolArguments):
            SqlmapTool().validate({"target": "http://127.0.0.1/", "data": "a=1\nrm -rf /"})

    def test_parse_confirmed_injection(self) -> None:
        tool = SqlmapTool()
        findings = tool.parse(
            tool.validate({"target": "http://127.0.0.1/item?id=1"}), SQLMAP_STDOUT
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity is Severity.HIGH
        assert finding.cwe == "CWE-89"
        assert finding.verified is True
        assert "id" in finding.title

    def test_parse_not_injectable(self) -> None:
        tool = SqlmapTool()
        output = "[INFO] all tested parameters do not appear to be injectable"
        assert tool.parse(tool.validate({"target": "http://127.0.0.1/?id=1"}), output) == []
        assert any(
            "no injectable" in note
            for note in tool.observations(
                tool.validate({"target": "http://127.0.0.1/?id=1"}), output
            )
        )

    def test_run_mocked(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout=SQLMAP_STDOUT)
        with run_mock, which_mock:
            result = SqlmapTool().run({"target": "http://127.0.0.1/item?id=1"})
        assert result.status is ToolStatus.OK
        assert result.findings[0].verified is True


class TestNiktoTool:
    def test_build_argv(self) -> None:
        tool = NiktoTool()
        argv = tool.build_argv(tool.validate({"target": "127.0.0.1", "port": 8443, "ssl": True}))
        assert argv[argv.index("-p") + 1] == "8443"
        assert "-ssl" in argv

    def test_parse_skips_banner_noise(self) -> None:
        tool = NiktoTool()
        findings = tool.parse(tool.validate({"target": "127.0.0.1"}), NIKTO_STDOUT)
        titles = " ".join(finding.title for finding in findings)
        assert "Target IP" not in titles
        assert any("Admin login page" in finding.title for finding in findings)
        assert any(finding.severity.rank >= Severity.LOW.rank for finding in findings)

    def test_run_mocked(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout=NIKTO_STDOUT, returncode=1)
        with run_mock, which_mock:
            result = NiktoTool().run({"target": "127.0.0.1"})
        assert result.status is ToolStatus.OK
        assert result.findings


class TestSubfinderTool:
    def test_requires_domain_not_ip(self) -> None:
        with pytest.raises(InvalidToolArguments):
            SubfinderTool().validate({"target": "127.0.0.1"})

    def test_parse_dedupes_and_filters(self) -> None:
        tool = SubfinderTool()
        findings = tool.parse(tool.validate({"target": "lab.test"}), SUBFINDER_STDOUT)
        hosts = [finding.endpoint for finding in findings]
        assert hosts == ["api.lab.test", "www.lab.test"]

    def test_run_mocked(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout=SUBFINDER_STDOUT)
        with run_mock, which_mock:
            result = SubfinderTool().run({"target": "lab.test"})
        assert result.status is ToolStatus.OK
        assert len(result.findings) == 2


class TestDalfoxTool:
    def test_build_argv_uses_json_output(self) -> None:
        tool = DalfoxTool()
        argv = tool.build_argv(tool.validate({"target": "http://127.0.0.1/search?q=1"}))
        assert "--format" in argv and "json" in argv

    def test_parse_marks_verified(self) -> None:
        tool = DalfoxTool()
        findings = tool.parse(tool.validate({"target": "http://127.0.0.1/search?q=1"}), DALFOX_JSON)
        assert len(findings) == 2
        assert findings[0].verified is True
        assert findings[0].cwe == "CWE-79"
        assert findings[1].verified is False

    def test_run_mocked(self, tmp_path: Path) -> None:
        def fake_run(argv, **kwargs):
            _write_output_file(argv, DALFOX_JSON)
            return completed("", "", 0)

        run_mock, which_mock = patch_subprocess(side_effect=fake_run)
        with run_mock, which_mock:
            result = DalfoxTool().run({"target": "http://127.0.0.1/search?q=1"})
        assert result.status is ToolStatus.OK
        assert len(result.findings) == 2


class TestTcpProbeTool:
    def test_build_argv(self) -> None:
        tool = TcpProbeTool()
        argv = tool.build_argv(tool.validate({"target": "127.0.0.1", "ports": [22, 80]}))
        assert argv[0] == "tcp_probe"
        assert argv[argv.index("--ports") + 1] == "22,80"

    def test_rejects_invalid_port(self) -> None:
        with pytest.raises(InvalidToolArguments):
            TcpProbeTool().validate({"target": "127.0.0.1", "ports": [70000]})

    def test_native_execution(self) -> None:
        class _Conn:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_connect(address, timeout=None):
            if address[1] == 80:
                return _Conn()
            raise OSError("connection refused")

        tool = TcpProbeTool()
        with mock.patch(
            "cyberpowerfull.tools.tcp_probe.socket.create_connection", side_effect=fake_connect
        ):
            result = tool.run({"target": "127.0.0.1", "ports": [22, 80]})
        assert result.status is ToolStatus.OK
        assert [finding.endpoint for finding in result.findings] == ["127.0.0.1:80"]
        assert "closed/filtered" in " ".join(result.observations)

    def test_sensitive_port_severity(self) -> None:
        tool = TcpProbeTool()
        findings = tool.parse(
            tool.validate({"target": "127.0.0.1", "ports": [6379]}),
            json.dumps({"open": [6379], "errors": {}}),
        )
        assert findings[0].severity is Severity.LOW
        assert "redis" in findings[0].title


class TestBaseToolBehaviour:
    def test_dry_run_never_executes(self) -> None:
        with mock.patch("cyberpowerfull.tools.base.subprocess.run") as run:
            result = NmapTool().run({"target": "127.0.0.1"}, dry_run=True)
        run.assert_not_called()
        assert result.status is ToolStatus.SKIPPED
        assert result.argv[0] == "nmap"

    def test_missing_binary(self) -> None:
        with mock.patch("cyberpowerfull.tools.base.shutil.which", return_value=None):
            result = NmapTool().run({"target": "127.0.0.1"})
        assert result.status is ToolStatus.MISSING
        assert "binary not installed" in (result.error or "")

    def test_timeout(self) -> None:
        with (
            mock.patch(
                "cyberpowerfull.tools.base.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=1),
            ),
            mock.patch("cyberpowerfull.tools.base.shutil.which", return_value="/usr/bin/nmap"),
        ):
            result = NmapTool().run({"target": "127.0.0.1"})
        assert result.status is ToolStatus.TIMEOUT

    def test_non_zero_exit_is_error(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout="", returncode=2)
        with run_mock, which_mock:
            result = NmapTool().run({"target": "127.0.0.1"})
        assert result.status is ToolStatus.ERROR
        assert "exit code 2" in (result.error or "")

    def test_os_error(self) -> None:
        with (
            mock.patch("cyberpowerfull.tools.base.subprocess.run", side_effect=OSError("boom")),
            mock.patch("cyberpowerfull.tools.base.shutil.which", return_value="/usr/bin/nmap"),
        ):
            result = NmapTool().run({"target": "127.0.0.1"})
        assert result.status is ToolStatus.ERROR
        assert "failed to start" in (result.error or "")

    def test_invalid_arguments_return_error_result(self) -> None:
        result = NmapTool().run({"target": "", "ports": "abc"})
        assert result.status is ToolStatus.ERROR
        assert "invalid arguments" in (result.error or "")

    def test_non_dict_arguments(self) -> None:
        with pytest.raises(InvalidToolArguments):
            NmapTool().validate(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_env_is_sanitised(self) -> None:
        policy = ToolPolicy()
        clean = policy.sanitized_env(
            {
                "PATH": "/usr/bin",
                "OPENAI_API_KEY": "sk-secret",
                "GH_TOKEN": "ghp_x",
                "HOME": "/root",
            }
        )
        assert clean == {"PATH": "/usr/bin", "HOME": "/root"}

        run_mock, which_mock = patch_subprocess(stdout=NMAP_XML)
        with run_mock as run, which_mock:
            NmapTool().run({"target": "127.0.0.1"})
        assert "OPENAI_API_KEY" not in run.call_args.kwargs["env"]

    def test_parser_crash_is_contained(self) -> None:
        tool = NmapTool()
        with mock.patch.object(NmapTool, "parse", side_effect=RuntimeError("parser bug")):
            run_mock, which_mock = patch_subprocess(stdout=NMAP_XML)
            with run_mock, which_mock:
                result = tool.run({"target": "127.0.0.1"})
        assert result.status is ToolStatus.ERROR
        assert "parser failed" in (result.error or "")

    def test_error_status_wins_over_findings(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout=NUCLEI_JSONL, returncode=3)
        with run_mock, which_mock:
            result = NucleiTool().run({"target": "http://127.0.0.1"})
        assert result.status is ToolStatus.ERROR
        assert result.findings  # evidence kept even when the exit code is non-zero


class TestRegistry:
    def test_expected_tools_registered(self) -> None:
        names = tool_names()
        for expected in (
            "nmap",
            "httpx",
            "nuclei",
            "ffuf",
            "sqlmap",
            "nikto",
            "subfinder",
            "dalfox",
            "tcp_probe",
        ):
            assert expected in names

    def test_get_tool_unknown(self) -> None:
        from cyberpowerfull.errors import ToolNotFound

        with pytest.raises(ToolNotFound):
            get_tool("metasploit")

    def test_catalog_contains_schema(self) -> None:
        entries = {entry["name"]: entry for entry in catalog()}
        assert "input_schema" in entries["nmap"]
        assert entries["tcp_probe"]["installed"] is True

    def test_installed_tools_includes_native(self) -> None:
        assert "tcp_probe" in installed_tools()

    def test_phases_are_declared(self) -> None:
        for entry in catalog():
            assert entry["phase"] in {phase.value for phase in Phase}


def test_normalise_url_rejects_other_schemes() -> None:
    with pytest.raises(ValueError):
        normalise_url("ftp://127.0.0.1")
