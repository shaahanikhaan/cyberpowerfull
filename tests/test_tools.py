"""Tool-layer tests: argv construction, parsing, and mocked subprocess execution."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

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


def patch_subprocess(stdout: str = "", stderr: str = "", returncode: int = 0, side_effect=None):
    """Patch subprocess.run and populate the bounded-output temp files."""

    def execute(argv, **kwargs):
        proc = side_effect(argv, **kwargs) if side_effect else completed(stdout, stderr, returncode)
        kwargs["stdout"].write((proc.stdout or "").encode("utf-8"))
        kwargs["stderr"].write((proc.stderr or "").encode("utf-8"))
        return proc

    run_mock = mock.patch("cyberpowerfull.tools.base.subprocess.run", side_effect=execute)
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
        assert "stdout" in run.call_args.kwargs and "stderr" in run.call_args.kwargs
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

    def test_build_argv_carries_throughput_and_error_budgets(self) -> None:
        tool = NucleiTool()
        argv = tool.build_argv(
            tool.validate({"target": "http://127.0.0.1", "bulk_size": 40, "max_host_error": 10})
        )
        assert argv[argv.index("-bs") + 1] == "40"
        assert argv[argv.index("-mhe") + 1] == "10"
        assert argv[argv.index("-c") + 1] == "10"
        assert NucleiTool.timeout_s == 1800  # full-store runs need a long budget

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
        assert finding.verified is False  # template matches still need human validation

    def test_run_mocked(self) -> None:
        run_mock, which_mock = patch_subprocess(stdout=NUCLEI_JSONL)
        with run_mock, which_mock:
            result = NucleiTool().run({"target": "http://127.0.0.1"})
        assert result.status is ToolStatus.OK
        assert result.findings[0].severity is Severity.CRITICAL

    def test_self_hosted_interactsh_replaces_no_interactsh(self) -> None:
        tool = NucleiTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": "http://127.0.0.1",
                    "interactsh_server": "https://oast.internal:8443/",
                    "interactsh_token": "tok",
                }
            )
        )
        assert argv[argv.index("-interactsh-server") + 1] == "https://oast.internal:8443"
        assert argv[argv.index("-interactsh-token") + 1] == "tok"
        assert "-no-interactsh" not in argv

    def test_public_oast_is_explicit_opt_in(self) -> None:
        tool = NucleiTool()
        argv = tool.build_argv(
            tool.validate({"target": "http://127.0.0.1", "enable_public_oast": True})
        )
        assert "-no-interactsh" not in argv
        assert "-interactsh-server" not in argv

    def test_oast_misconfigurations_are_rejected(self) -> None:
        tool = NucleiTool()
        for bad in (
            {"interactsh_token": "tok"},
            {"interactsh_server": "https://oast.internal", "enable_public_oast": True},
            {"interactsh_server": "ftp://oast.internal"},
            {"interactsh_server": "not-a-url"},
        ):
            with pytest.raises(InvalidToolArguments):
                tool.validate({"target": "http://127.0.0.1", **bad})

    def test_dast_defaults_to_a_target_only_scope_pattern(self) -> None:
        tool = NucleiTool()
        argv = tool.build_argv(
            tool.validate({"target": "https://app.example.test:8443/x", "dast": True})
        )
        assert "-dast" in argv
        assert argv[argv.index("-fuzz-aggression") + 1] == "low"
        assert argv[argv.index("-fuzz-scope") + 1] == (r"^https?://app\.example\.test(:[0-9]+)?/")

    def test_dast_explicit_scope_and_out_of_scope(self) -> None:
        tool = NucleiTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": "http://127.0.0.1",
                    "dast": True,
                    "dast_scope": ["^https?://127.0.0.1/", "^https?://127.0.0.1:8080/"],
                    "dast_out_of_scope": ["logout", "billing"],
                    "fuzz_aggression": "high",
                }
            )
        )
        assert argv.count("-fuzz-scope") == 2
        assert argv.count("-fuzz-out-scope") == 2
        assert argv[argv.index("-fuzz-aggression") + 1] == "high"

    def test_dast_tuning_without_dast_is_rejected(self) -> None:
        tool = NucleiTool()
        for bad in (
            {"dast_scope": ["^https?://127.0.0.1/"]},
            {"dast_out_of_scope": ["logout"]},
            {"fuzz_aggression": "medium"},
        ):
            with pytest.raises(InvalidToolArguments):
                tool.validate({"target": "http://127.0.0.1", **bad})

    def test_observations_name_the_oast_and_dast_state(self) -> None:
        tool = NucleiTool()
        args = tool.validate({"target": "http://127.0.0.1"})
        assert any("oast disabled" in note for note in tool.observations(args, ""))
        args = tool.validate({"target": "http://127.0.0.1", "enable_public_oast": True})
        assert any("WARNING: public OAST" in note for note in tool.observations(args, ""))
        args = tool.validate({"target": "http://127.0.0.1", "dast": True})
        assert any("dast fuzzing on" in note for note in tool.observations(args, ""))


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
        assert findings[1].severity is Severity.INFO  # 403 alone is not a vulnerability
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
        assert result.status is ToolStatus.ERROR  # ffuf exit code 1 signals an error
        assert len(result.findings) == 3  # retain any partial evidence
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
        assert findings[0].severity is Severity.INFO
        assert "redis" in findings[0].title
        assert "not a confirmed service" in findings[0].evidence


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
            get_tool("definitely_not_a_tool")

    def test_metasploit_registered(self) -> None:
        assert get_tool("metasploit").name == "metasploit"

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


DNSX_JSONL = "\n".join(
    [
        json.dumps(
            {
                "host": "example.com",
                "a": ["93.184.216.34"],
                "mx": ["0 mail.example.com"],
                "ns": ["ns1.example.com"],
                "txt": ["v=spf1 -all"],
            }
        ),
        json.dumps({"host": "corp.example.com", "a": ["10.0.0.8"]}),
        "warning: not json",
    ]
)

DNSX_AXFR_JSONL = json.dumps(
    {
        "host": "example.com",
        "a": ["93.184.216.34"],
        "axfr": "ns1.example.com: AXFR: example.com SOA ns1 hostmaster 42 ...",
        "has_internal_ips": True,
        "internal_ips": ["10.0.0.8"],
    }
)

TLSX_JSONL = "\n".join(
    [
        json.dumps(
            {
                "host": "example.com",
                "port": 443,
                "tls_version": "tls13",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "subject_cn": "example.com",
                "subject_an": ["example.com", "www.example.com"],
                "subject_dn": "CN=example.com",
                "issuer_dn": "CN=Example CA",
                "not_after": "2027-03-20T17:46:38Z",
            }
        ),
        json.dumps(
            {
                "host": "legacy.example.com",
                "port": 443,
                "tls_version": "tls11",
                "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                "subject_cn": "other.example.org",
                "subject_an": ["other.example.org"],
                "subject_dn": "CN=legacy",
                "issuer_dn": "CN=legacy",
                "not_after": "2020-01-01T00:00:00Z",
            }
        ),
        "warning: not json",
    ]
)

RUSTSCAN_GREP = "\n".join(
    [
        "The Modern Day Port Scanner.",
        "Open 127.0.0.1:22",
        "Something random on 127.0.0.1 which is not a greppable line",
        "Open 127.0.0.1:79ab",  # invalid port: must not parse
        "127.0.0.1 -> [22,80]",
        "[~] Starting Script(s)",
    ]
)

UNCOVER_JSONL = "\n".join(
    [
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "source": "shodan",
                "ip": "93.184.216.34",
                "port": 80,
                "host": "www.example.com",
                "url": "http://93.184.216.34/index.html",
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-01-02T00:00:00Z",
                "source": "censys",
                "ip": "93.184.216.34",
                "port": 443,
                "host": "www.example.com",
                "url": "https://www.example.com:443/login",
            }
        ),
        json.dumps({"source": "fofa", "ip": "203.0.113.9", "port": 22}),
        "warning: not json",
    ]
)


class TestDnsx:
    def test_argv_resolve_defaults(self) -> None:
        from cyberpowerfull.tools.dnsx import DnsxTool

        tool = DnsxTool()
        argv = tool.build_argv(tool.validate({"target": "example.com"}))
        assert argv == [
            "dnsx",
            "-l",
            "example.com",
            "-j",
            "-silent",
            "-nc",
            "-duc",
            "-threads",
            "100",
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-ns",
            "-txt",
            "-soa",
        ]

    def test_argv_bruteforce_uses_domain_and_wordlist(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.dnsx import DnsxTool

        wordlist = tmp_path / "dns.txt"
        wordlist.write_text("www\nmail\n", encoding="utf-8")
        tool = DnsxTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": "example.com",
                    "resolvers": ["9.9.9.9", "1.1.1.1"],
                    "bruteforce": True,
                    "wordlist": str(wordlist),
                    "threads": 50,
                }
            )
        )
        assert argv[:4] == ["dnsx", "-d", "example.com", "-w"]
        assert "-r" in argv and "9.9.9.9,1.1.1.1" in argv  # comma-joined list
        assert "-nc" in argv  # colour is always off: output must stay parseable
        assert argv[argv.index("-threads") + 1] == "50"

    def test_validate_rejects_garbage_target(self) -> None:
        from cyberpowerfull.tools.dnsx import DnsxTool

        with pytest.raises(InvalidToolArguments):
            DnsxTool().validate({"target": "not a domain!"})

    def test_parse_collects_records_and_skips_non_json(self) -> None:
        from cyberpowerfull.tools.dnsx import DnsxTool

        tool = DnsxTool()
        findings = tool.parse(tool.validate({"target": "example.com"}), DNSX_JSONL)
        assert len(findings) == 2
        assert findings[0].title == "DNS records for example.com"
        assert "A=93.184.216.34" in findings[0].evidence

    def test_parse_flags_axfr_and_internal_ips(self) -> None:
        from cyberpowerfull.tools.dnsx import DnsxTool

        tool = DnsxTool()
        findings = tool.parse(tool.validate({"target": "example.com"}), DNSX_AXFR_JSONL)
        by_title = {finding.title: finding for finding in findings}
        axfr = by_title["DNS zone transfer (AXFR) succeeded for example.com"]
        assert axfr.severity is Severity.MEDIUM
        internal = by_title["DNS exposes internal addresses for example.com"]
        assert internal.severity is Severity.LOW
        assert "10.0.0.8" in internal.evidence

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.dnsx import DnsxTool

        assert DnsxTool().name == "dnsx"
        assert DnsxTool().phase is Phase.RECON


class TestTlsx:
    def test_argv_defaults(self) -> None:
        from cyberpowerfull.tools.tlsx import TlsxTool

        tool = TlsxTool()
        assert tool.build_argv(tool.validate({"target": "example.com"})) == [
            "tlsx",
            "-u",
            "example.com",
            "-p",
            "443",
            "-j",
            "-silent",
            "-nc",
            "-duc",
            "-timeout",
            "5",
        ]

    def test_argv_ports_joined_and_enumeration_flags(self) -> None:
        from cyberpowerfull.tools.tlsx import TlsxTool

        tool = TlsxTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": "example.com",
                    "ports": [443, 8443],
                    "enumerate_versions": True,
                    "enumerate_ciphers": True,
                }
            )
        )
        assert argv[argv.index("-p") + 1] == "443,8443"
        assert "-ve" in argv and "-ce" in argv

    def test_validate_rejects_bad_port(self) -> None:
        from cyberpowerfull.tools.tlsx import TlsxTool

        with pytest.raises(InvalidToolArguments):
            TlsxTool().validate({"target": "example.com", "ports": [70000]})

    def test_parse_scores_each_weakness(self) -> None:
        from cyberpowerfull.tools.tlsx import TlsxTool

        tool = TlsxTool()
        findings = tool.parse(tool.validate({"target": "example.com"}), TLSX_JSONL)
        by_title = {finding.title: finding for finding in findings}
        # The healthy tls13 record yields nothing; the legacy record yields five.
        assert len(findings) == 5
        weak_cipher = by_title["Weak TLS cipher on legacy.example.com:443"]
        assert weak_cipher.severity is Severity.LOW
        expired = by_title["TLS certificate expired for legacy.example.com:443"]
        assert expired.severity is Severity.HIGH
        assert "2020-01-01" in expired.evidence
        mismatch = by_title["TLS certificate hostname mismatch on legacy.example.com:443"]
        assert mismatch.severity is Severity.MEDIUM
        weak_version = by_title["Weak TLS version tls11 on legacy.example.com:443"]
        assert weak_version.severity is Severity.MEDIUM
        assert by_title["Self-signed TLS certificate on legacy.example.com:443"]

    def test_parse_skips_failed_probes(self) -> None:
        from cyberpowerfull.tools.tlsx import TlsxTool

        tool = TlsxTool()
        output = json.dumps({"host": "example.com", "port": 443, "probe_status": False})
        assert tool.parse(tool.validate({"target": "example.com"}), output) == []

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.tlsx import TlsxTool

        assert TlsxTool().name == "tlsx"
        assert TlsxTool().phase is Phase.SCANNING  # same bucket as testssl


class TestRustscan:
    def test_argv_defaults_are_discovery_only(self) -> None:
        from cyberpowerfull.tools.rustscan import RustscanTool

        tool = RustscanTool()
        argv = tool.build_argv(tool.validate({"target": "192.0.2.1", "top_1000": True}))
        assert argv == [
            "rustscan",
            "-a",
            "192.0.2.1",
            "-g",
            "--scripts",
            "none",
            "--no-banner",
            "-b",
            "4500",
            "-t",
            "1500",
            "--tries",
            "1",
            "--scan-order",
            "serial",
            "--top",
        ]

    def test_argv_custom_ports_and_udp(self) -> None:
        from cyberpowerfull.tools.rustscan import RustscanTool

        tool = RustscanTool()
        argv = tool.build_argv(
            tool.validate({"target": "192.0.2.1", "port_range": "1-1024", "udp": True})
        )
        assert argv[argv.index("-r") + 1] == "1-1024"
        assert "--udp" in argv
        assert "--top" not in argv

    def test_validate_rejects_bad_ports(self) -> None:
        from cyberpowerfull.tools.rustscan import RustscanTool

        with pytest.raises(InvalidToolArguments):
            RustscanTool().validate({"target": "192.0.2.1", "port_range": "1-99999"})

    def test_parse_reads_greppable_summary_only(self) -> None:
        from cyberpowerfull.tools.rustscan import RustscanTool

        tool = RustscanTool()
        findings = tool.parse(tool.validate({"target": "192.0.2.1"}), RUSTSCAN_GREP)
        assert {finding.endpoint for finding in findings} == {
            "127.0.0.1:22",
            "127.0.0.1:80",
        }
        assert all(finding.severity is Severity.INFO for finding in findings)

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.rustscan import RustscanTool

        assert RustscanTool().name == "rustscan"
        assert RustscanTool().phase is Phase.SCANNING


class TestUncover:
    def test_argv_defaults_to_shodan(self) -> None:
        from cyberpowerfull.tools.uncover import UncoverTool

        tool = UncoverTool()
        assert tool.build_argv(tool.validate({"target": "example.com"})) == [
            "uncover",
            "-q",
            "example.com",
            "-e",
            "shodan",
            "-l",
            "25",
            "-j",
            "-silent",
            "-nc",
            "-timeout",
            "30",
        ]

    def test_argv_repeats_engine_flag(self) -> None:
        from cyberpowerfull.tools.uncover import UncoverTool

        tool = UncoverTool()
        argv = tool.build_argv(
            tool.validate({"target": "example.com", "engines": ["shodan", "censys"]})
        )
        assert argv.count("-e") == 2
        assert "shodan" in argv and "censys" in argv

    def test_validate_rejects_unknown_engine(self) -> None:
        from cyberpowerfull.tools.uncover import UncoverTool

        with pytest.raises(InvalidToolArguments):
            UncoverTool().validate({"target": "example.com", "engines": ["bing"]})

    def test_parse_keeps_only_in_scope_hosts(self) -> None:
        from cyberpowerfull.tools.uncover import UncoverTool

        tool = UncoverTool()
        args = tool.validate({"target": "example.com", "engines": ["shodan", "censys", "fofa"]})
        findings = tool.parse(args, UNCOVER_JSONL)
        assert len(findings) == 2  # the fofa row for 203.0.113.9 is dropped silently
        assert {finding.endpoint for finding in findings} == {
            "www.example.com:80",
            "www.example.com:443",
        }
        assert all(finding.severity is Severity.INFO for finding in findings)

    def test_observations_count_filtered_rows(self) -> None:
        from cyberpowerfull.tools.uncover import UncoverTool

        tool = UncoverTool()
        args = tool.validate({"target": "example.com", "engines": ["shodan", "censys", "fofa"]})
        (note,) = tool.observations(args, UNCOVER_JSONL)
        assert "2 in-scope" in note and "1 out-of-scope filtered" in note

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.uncover import UncoverTool

        assert UncoverTool().name == "uncover"
        assert UncoverTool().phase is Phase.RECON


NXC_STDOUT = "\n".join(
    [
        "SMB  192.0.2.10  445  DC01  [*] Win2019 (signing:False) (SMBv1:True)",
        "SMB  192.0.2.10  445  DC01  [+] lab.local\\: (Guest)",
        "SYSVOL                               READ",
        "BACKUP                               READ,WRITE",
        "some unrelated log line",
    ]
)


class TestNetexec:
    def test_argv_null_session_defaults(self) -> None:
        from cyberpowerfull.tools.netexec import NetexecTool

        tool = NetexecTool()
        argv = tool.build_argv(tool.validate({"target": "192.0.2.10"}))
        assert argv == ["nxc", "smb", "192.0.2.10", "-u", "", "-p", "", "--shares"]

    def test_argv_guest_with_filter_and_policy(self) -> None:
        from cyberpowerfull.tools.netexec import NetexecTool

        tool = NetexecTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": "192.0.2.10",
                    "guest": True,
                    "enumerate": ["shares", "pass_pol"],
                    "share_filter": "WRITE",
                }
            )
        )
        assert argv == [
            "nxc",
            "smb",
            "192.0.2.10",
            "-u",
            "guest",
            "-p",
            "",
            "--shares",
            "WRITE",
            "--pass-pol",
        ]

    def test_validate_rejects_filter_without_shares(self) -> None:
        from cyberpowerfull.tools.netexec import NetexecTool

        with pytest.raises(InvalidToolArguments):
            NetexecTool().validate(
                {"target": "192.0.2.10", "enumerate": ["users"], "share_filter": "READ"}
            )

    def test_parse_scores_session_signing_and_shares(self) -> None:
        from cyberpowerfull.tools.netexec import NetexecTool

        tool = NetexecTool()
        findings = tool.parse(tool.validate({"target": "192.0.2.10"}), NXC_STDOUT)
        by_title = {finding.title: finding for finding in findings}
        assert by_title["SMB null session accepted on 192.0.2.10"].severity is Severity.MEDIUM
        assert by_title["SMBv1 enabled on 192.0.2.10"].severity is Severity.HIGH
        assert by_title["SMB signing not required on 192.0.2.10"].severity is Severity.MEDIUM
        assert by_title["SMB share BACKUP is writable via null session"].severity is Severity.MEDIUM
        assert by_title["SMB share SYSVOL is readable via null session"].severity is Severity.LOW

    def test_metadata(self) -> None:
        from cyberpowerfull.models import Capability
        from cyberpowerfull.tools.netexec import NetexecTool

        assert NetexecTool().name == "netexec"
        assert NetexecTool().phase is Phase.SCANNING
        assert NetexecTool().required_capability is Capability.CREDENTIAL_TESTING


GITLEAKS_JSON = json.dumps(
    [
        {
            "Description": "Generic API Key",
            "StartLine": 12,
            "EndLine": 12,
            "Secret": "REDACTED",
            "Match": "api_key = REDACTED",
            "File": "app/settings.py",
            "RuleID": "generic-api-key",
            "Tags": ["key", "api"],
        }
    ]
)

TRUFFLEHOG_JSONL = json.dumps(
    {
        "SourceMetadata": {"Data": {"Filesystem": {"file": "app/settings.py", "line": 12}}},
        "SourceType": 15,
        "DetectorType": 17,
        "DetectorName": "Github",
        "Verified": False,
        "Raw": "ghp_LIVESECRET_SHOULD_NEVER_APPEAR",
        "Redacted": "ghp_***",
    }
)

SEMGREP_JSON = json.dumps(
    {
        "results": [
            {
                "check_id": "python.django.security.injection.command.command-injection",
                "path": "app/views.py",
                "start": {"line": 42, "col": 5},
                "end": {"line": 42, "col": 40},
                "extra": {
                    "message": "Possible command injection via os.system",
                    "severity": "ERROR",
                    "metadata": {"cwe": "CWE-78", "owasp": "A03:2021"},
                },
            }
        ],
        "errors": [],
    }
)

TRIVY_JSON = json.dumps(
    {
        "Results": [
            {
                "Target": "app/requirements.txt",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2020-7471",
                        "PkgName": "django",
                        "InstalledVersion": "2.0.9",
                        "FixedVersion": "3.0.3, 2.2.10, 1.11.28",
                        "Severity": "HIGH",
                        "Title": "django: potential SQL injection via StringAgg",
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "github-pat",
                        "Title": "GitHub Personal Access Token",
                        "Severity": "CRITICAL",
                        "StartLine": 3,
                        "EndLine": 3,
                        "Code": "token = ghp_LIVESECRET_SHOULD_NEVER_APPEAR",
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "Specify at least 1 USER command",
                        "Severity": "MEDIUM",
                        "Resolution": "Add 'USER <name>' to the Dockerfile",
                    }
                ],
            }
        ]
    }
)


class TestGitleaks:
    def test_argv_dir_defaults(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.gitleaks import GitleaksTool

        tool = GitleaksTool()
        argv = tool.build_argv(tool.validate({"target": str(tmp_path)}), "/tmp/o.json")
        assert argv == [
            "gitleaks",
            "dir",
            str(tmp_path),
            "--report-format",
            "json",
            "--report-path",
            "/tmp/o.json",
            "--exit-code",
            "0",
            "--redact",
            "--no-banner",
            "--log-level",
            "warn",
        ]

    def test_validate_rejects_missing_path(self) -> None:
        from cyberpowerfull.tools.gitleaks import GitleaksTool

        with pytest.raises(InvalidToolArguments):
            GitleaksTool().validate({"target": "/does/not/exist-xyz"})

    def test_parse_keeps_location_drops_secret(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.gitleaks import GitleaksTool

        tool = GitleaksTool()
        (finding,) = tool.parse(tool.validate({"target": str(tmp_path)}), GITLEAKS_JSON)
        assert finding.severity is Severity.HIGH
        assert finding.endpoint == "app/settings.py:12"
        assert "generic-api-key" in finding.evidence
        assert "REDACTED" not in finding.evidence  # not even the marker leaks shape

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.gitleaks import GitleaksTool

        assert GitleaksTool().scans_local_paths is True
        assert GitleaksTool().phase is Phase.SCANNING


class TestTrufflehog:
    def test_argv_filesystem_defaults(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.trufflehog import TrufflehogTool

        tool = TrufflehogTool()
        argv = tool.build_argv(tool.validate({"target": str(tmp_path)}))
        assert argv == [
            "trufflehog",
            "filesystem",
            str(tmp_path),
            "--json",
            "--no-verification",
            "--no-update",
        ]

    def test_argv_git_mode(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.trufflehog import TrufflehogTool

        tool = TrufflehogTool()
        argv = tool.build_argv(tool.validate({"target": str(tmp_path), "mode": "git"}))
        assert argv[:3] == ["trufflehog", "git", f"file://{tmp_path}"]
        assert "--results=verified,unknown" in argv

    def test_parse_never_reads_raw_secret(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.trufflehog import TrufflehogTool

        tool = TrufflehogTool()
        (finding,) = tool.parse(tool.validate({"target": str(tmp_path)}), TRUFFLEHOG_JSONL)
        assert finding.severity is Severity.HIGH
        assert finding.endpoint == "app/settings.py:12"
        assert "LIVESECRET" not in finding.evidence
        assert "ghp_***" in finding.evidence

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.trufflehog import TrufflehogTool

        assert TrufflehogTool().scans_local_paths is True


class TestSemgrep:
    def test_argv_defaults(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.semgrep import SemgrepTool

        tool = SemgrepTool()
        argv = tool.build_argv(tool.validate({"target": str(tmp_path)}), "/tmp/o.json")
        assert argv == [
            "semgrep",
            "scan",
            "--config",
            "p/default",
            "--json",
            "--output",
            "/tmp/o.json",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            str(tmp_path),
        ]

    def test_validate_refuses_config_auto(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.semgrep import SemgrepTool

        with pytest.raises(InvalidToolArguments):
            SemgrepTool().validate({"target": str(tmp_path), "config": "auto"})

    def test_parse_maps_cwe_and_severity(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.semgrep import SemgrepTool

        tool = SemgrepTool()
        (finding,) = tool.parse(tool.validate({"target": str(tmp_path)}), SEMGREP_JSON)
        assert finding.severity is Severity.HIGH  # ERROR -> HIGH
        assert finding.endpoint == "app/views.py:42"
        assert "CWE-78" in finding.evidence

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.semgrep import SemgrepTool

        assert SemgrepTool().scans_local_paths is True


class TestTrivy:
    def test_argv_defaults(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.trivy import TrivyTool

        tool = TrivyTool()
        argv = tool.build_argv(tool.validate({"target": str(tmp_path)}), "/tmp/o.json")
        assert argv == [
            "trivy",
            "fs",
            "--scanners",
            "vuln,secret",
            "--format",
            "json",
            "--output",
            "/tmp/o.json",
            "--severity",
            "LOW,MEDIUM,HIGH,CRITICAL",
            "--skip-version-check",
            "--disable-telemetry",
            "--exit-code",
            "0",
            "--quiet",
            str(tmp_path),
        ]

    def test_argv_misconfig_and_floor(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.trivy import TrivyTool

        tool = TrivyTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": str(tmp_path),
                    "scanners": ["vuln", "secret", "misconfig"],
                    "severity_floor": "HIGH",
                }
            ),
            "/tmp/o.json",
        )
        assert argv[argv.index("--scanners") + 1] == "vuln,secret,misconfig"
        assert argv[argv.index("--severity") + 1] == "HIGH,CRITICAL"

    def test_parse_all_three_classes(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.trivy import TrivyTool

        tool = TrivyTool()
        findings = tool.parse(tool.validate({"target": str(tmp_path)}), TRIVY_JSON)
        assert len(findings) == 3
        vuln = next(f for f in findings if f.cve == "CVE-2020-7471")
        assert vuln.severity is Severity.HIGH
        assert "3.0.3" in vuln.evidence
        secret = next(f for f in findings if "secret" in f.title.lower())
        assert "LIVESECRET" not in secret.evidence
        misconfig = next(f for f in findings if f.title.startswith("DS002"))
        assert "USER" in misconfig.evidence

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.trivy import TrivyTool

        assert TrivyTool().scans_local_paths is True


ZAP_JSON = json.dumps(
    {
        "@version": "2.17.0",
        "site": [
            {
                "@name": "http://127.0.0.1",
                "alerts": [
                    {
                        "pluginid": "10021",
                        "name": "X-Content-Type-Options Header Missing",
                        "riskcode": "1",
                        "solution": "Ensure the header is set on all responses.",
                        "instances": [
                            {
                                "uri": "http://127.0.0.1/",
                                "method": "GET",
                                "param": "",
                                "evidence": "",
                            }
                        ],
                    },
                    {
                        "pluginid": "40012",
                        "name": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "solution": "Validate and encode all user input.",
                        "instances": [
                            {
                                "uri": "http://127.0.0.1/search?q=1",
                                "method": "GET",
                                "param": "q",
                                "evidence": "<script>alert(1)</script>",
                            }
                        ],
                    },
                ],
            }
        ],
    }
)


class TestZap:
    def test_argv_writes_plan_and_runs_headless(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.zaproxy import ZapTool

        tool = ZapTool()
        out_file = str(tmp_path / "output.json")
        argv = tool.build_argv(tool.validate({"target": "http://127.0.0.1/"}), out_file)
        assert argv[:3] == ["zap.sh", "-cmd", "-autorun"]
        plan = Path(argv[3]).read_text(encoding="utf-8")
        assert "template: traditional-json" in plan
        assert f"reportFile: {Path(out_file).name}" in plan
        assert "type: activeScan" not in plan  # passive default

    def test_render_plan_adds_bounded_active_scan(self) -> None:
        from cyberpowerfull.tools.zaproxy import ZapTool

        tool = ZapTool()
        args = tool.validate({"target": "http://127.0.0.1/", "active": True})
        plan = tool.render_plan(args, "/tmp/cpf-zap/output.json")
        assert "type: activeScan" in plan
        assert "maxDuration: 10" in plan

    def test_parse_maps_risk_to_severity(self) -> None:
        from cyberpowerfull.tools.zaproxy import ZapTool

        tool = ZapTool()
        findings = tool.parse(tool.validate({"target": "http://127.0.0.1/"}), ZAP_JSON)
        assert len(findings) == 2
        by_title = {finding.title: finding for finding in findings}
        low = by_title["ZAP X-Content-Type-Options Header Missing: http://127.0.0.1/"]
        assert low.severity is Severity.LOW
        xss = by_title["ZAP Cross Site Scripting (Reflected): http://127.0.0.1/search?q=1"]
        assert xss.severity is Severity.HIGH
        assert "param=q" in xss.evidence

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.zaproxy import ZapTool

        assert ZapTool().name == "zap"
        assert ZapTool().phase is Phase.SCANNING
        assert ZapTool().binary_alternatives == ("zap", "zaproxy")


class TestNucleiKev:
    def test_kev_only_replaces_tags(self) -> None:
        tool = NucleiTool()
        argv = tool.build_argv(
            tool.validate({"target": "http://127.0.0.1", "kev_only": True, "tags": ["xss"]})
        )
        assert argv[argv.index("-tags") + 1] == "kev"

    def test_tags_untouched_without_kev(self) -> None:
        tool = NucleiTool()
        argv = tool.build_argv(
            tool.validate({"target": "http://127.0.0.1", "tags": ["xss", "sqli"]})
        )
        assert argv[argv.index("-tags") + 1] == "xss,sqli"


KUBEBENCH_JSON = json.dumps(
    {
        "Totals": {"total_pass": 40, "total_fail": 1, "total_warn": 1, "total_info": 5},
        "Controls": [
            {
                "id": "1",
                "text": "Control Plane Security Configuration",
                "tests": [
                    {
                        "section": "1.1",
                        "results": [
                            {
                                "test_number": "1.1.1",
                                "test_desc": "Ensure API server pod file permissions are 600",
                                "status": "FAIL",
                                "actual_value": "644",
                                "remediation": "chmod 600 /etc/kubernetes/kube-apiserver.yaml",
                            },
                            {
                                "test_number": "1.1.2",
                                "test_desc": "Ensure API server pod file ownership is root:root",
                                "status": "PASS",
                            },
                            {
                                "test_number": "1.1.3",
                                "test_desc": "Ensure controller manager uses only strong ciphers",
                                "status": "WARN",
                                "actual_value": "cipher list includes 3DES",
                                "remediation": "restrict --tls-cipher-suites",
                            },
                        ],
                    }
                ],
            }
        ],
    }
)

KUBESCAPE_JSON = json.dumps(
    {
        "summaryDetails": {"score": 72.5, "controls": {"failed": 1, "passed": 40}},
        "controls": {
            "C-0001": {
                "controlID": "C-0001",
                "name": "Naked pods",
                "status": {"status": "failed"},
                "remediation": "Define a PodSecurityPolicy or PSA policy.",
                "failedResources": [{"kind": "Pod", "name": "naked"}],
            },
            "C-0002": {
                "controlID": "C-0002",
                "name": "Host PID/IPC privileges",
                "status": {"status": "passed"},
            },
        },
    }
)

PROWLER_OCSF = json.dumps(
    [
        {
            "message": "Bucket leaky allows public access.",
            "activity_id": 1,
            "finding_info": {
                "title": "S3 bucket public access is not blocked",
                "uid": "prowler-uuid-1",
                "desc": "Check S3 block public access.",
            },
            "remediation": {"desc": "Enable Block Public Access."},
            "severity_id": 4,
            "severity": "High",
            "status_id": 1,
            "status": "New",
            "status_code": "FAIL",
            "status_detail": "Bucket allows public access.",
            "resources": [
                {
                    "name": "leaky",
                    "uid": "arn:aws:s3:::leaky",
                    "type": "Bucket",
                    "region": "us-east-1",
                }
            ],
            "metadata": {
                "event_code": "s3_bucket_public_access",
                "product": {"name": "Prowler"},
            },
        },
        {
            "status_code": "PASS",
            "status_detail": "No security groups allow ingress from everywhere.",
            "finding_info": {
                "title": "Security groups allow ingress from 0.0.0.0/0",
                "uid": "prowler-uuid-2",
            },
            "severity": "Critical",
            "resources": [{"uid": "sg-123", "region": "us-east-1"}],
            "metadata": {
                "event_code": "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
            },
        },
    ]
)


class TestKubebench:
    def test_argv_defaults(self) -> None:
        from cyberpowerfull.tools.kubebench import KubebenchTool

        tool = KubebenchTool()
        argv = tool.build_argv(tool.validate({"target": "node1"}), "/tmp/x/o.json")
        assert argv == ["kube-bench", "--json", "--outputfile", "/tmp/x/o.json"]

    def test_argv_run_targets(self) -> None:
        from cyberpowerfull.tools.kubebench import KubebenchTool

        tool = KubebenchTool()
        argv = tool.build_argv(
            tool.validate({"target": "node1", "targets": ["master", "etcd"]}), "/tmp/x/o.json"
        )
        assert argv[1:4] == ["run", "--targets", "master,etcd"]

    def test_parse_scores_fail_and_warn(self) -> None:
        from cyberpowerfull.tools.kubebench import KubebenchTool

        tool = KubebenchTool()
        findings = tool.parse(tool.validate({"target": "node1"}), KUBEBENCH_JSON)
        assert len(findings) == 2  # PASS stays silent
        by_title = {finding.title: finding for finding in findings}
        fail = by_title["CIS 1.1.1: Ensure API server pod file permissions are 600"]
        assert fail.severity is Severity.MEDIUM
        assert "chmod 600" in fail.evidence
        assert by_title["CIS 1.1.3: Ensure controller manager uses only strong ciphers"]

    def test_observations_carry_totals(self) -> None:
        from cyberpowerfull.tools.kubebench import KubebenchTool

        tool = KubebenchTool()
        (note,) = tool.observations(tool.validate({"target": "node1"}), KUBEBENCH_JSON)
        assert "2 failing" in note and "pass=40" in note  # 1 FAIL + 1 WARN

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.kubebench import KubebenchTool

        assert KubebenchTool().name == "kubebench"
        assert KubebenchTool().phase is Phase.SCANNING


class TestKubescape:
    def test_argv_defaults(self) -> None:
        from cyberpowerfull.tools.kubescape import KubescapeTool

        tool = KubescapeTool()
        argv = tool.build_argv(tool.validate({"target": "node1"}), "/tmp/x/o.json")
        assert argv == ["kubescape", "scan", "--format", "json", "--output", "/tmp/x/o.json"]

    def test_argv_manifests(self, tmp_path: Path) -> None:
        from cyberpowerfull.tools.kubescape import KubescapeTool

        tool = KubescapeTool()
        argv = tool.build_argv(
            tool.validate({"target": "node1", "manifests": str(tmp_path)}), "/tmp/x/o.json"
        )
        assert argv[2] == str(tmp_path)

    def test_parse_failed_controls_only(self) -> None:
        from cyberpowerfull.tools.kubescape import KubescapeTool

        tool = KubescapeTool()
        (finding,) = tool.parse(tool.validate({"target": "node1"}), KUBESCAPE_JSON)
        assert finding.title == "[C-0001] Naked pods"
        assert finding.severity is Severity.MEDIUM
        assert "resources=1" in finding.evidence

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.kubescape import KubescapeTool

        assert KubescapeTool().name == "kubescape"


class TestProwler:
    def test_argv_defaults(self) -> None:
        from cyberpowerfull.tools.prowler import ProwlerTool

        tool = ProwlerTool()
        argv = tool.build_argv(tool.validate({"target": "prod-123"}), "/tmp/x/o.json")
        assert argv == ["prowler", "aws", "-M", "json-ocsf", "-o", "/tmp/x"]

    def test_argv_checks_services_regions(self) -> None:
        from cyberpowerfull.tools.prowler import ProwlerTool

        tool = ProwlerTool()
        argv = tool.build_argv(
            tool.validate(
                {
                    "target": "prod-123",
                    "provider": "aws",
                    "checks": ["s3_bucket_public_access"],
                    "services": ["s3"],
                    "regions": ["us-east-1"],
                }
            ),
            "/tmp/x/o.json",
        )
        assert "-c" in argv and "s3_bucket_public_access" in argv
        assert "-s" in argv and "s3" in argv
        assert "-f" in argv and "us-east-1" in argv

    def test_parse_keeps_fail_drops_pass(self) -> None:
        from cyberpowerfull.tools.prowler import ProwlerTool

        tool = ProwlerTool()
        (finding,) = tool.parse(
            tool.validate({"target": "prod-123", "provider": "aws"}), PROWLER_OCSF
        )
        assert finding.severity is Severity.HIGH
        assert finding.endpoint == "arn:aws:s3:::leaky"
        assert "s3_bucket_public_access" in finding.title

    def test_credential_gate_blocks_without_keys(self, monkeypatch) -> None:
        from cyberpowerfull.tools.prowler import _missing_credential_hint

        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_PROFILE", raising=False)
        hint = _missing_credential_hint("aws")
        assert hint is not None and "AWS_ACCESS_KEY_ID" in hint
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
        assert _missing_credential_hint("aws") is None

    def test_metadata(self) -> None:
        from cyberpowerfull.tools.prowler import ProwlerTool

        assert ProwlerTool().cloud_posture is True
        assert ProwlerTool().phase is Phase.SCANNING
