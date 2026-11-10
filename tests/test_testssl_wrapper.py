"""Targeted tests for the testssl.sh wrapper rewrite.

Flag and severity semantics were verified against the testssl.sh v3.2.5
source; these tests pin the researched behaviour so a regression fails
loudly instead of silently emitting a wrong (or hanging) invocation.
"""

from __future__ import annotations

import json

import pytest

from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Severity
from cyberpowerfull.tools.testssl import TestsslArgs, TestsslTool

TestsslArgs.__test__ = False  # imported model, not a test class

TARGET = "https://127.0.0.1:443"


def _record(
    finding_id: str,
    severity: str,
    finding: str = "TLS_RSA_WITH_RC4_128_SHA offered",
    **extra: object,
) -> dict[str, object]:
    record: dict[str, object] = {
        "id": finding_id,
        "ip": "127.0.0.1",
        "port": "443",
        "severity": severity,
        "finding": finding,
        "cve": "",
        "cwe": "",
    }
    record.update(extra)
    return record


class TestArgv:
    def test_default_check_is_protocols_only(self) -> None:
        argv = TestsslTool().build_argv(TestsslArgs(target=TARGET), out_file="/tmp/t.json")
        assert "-p" in argv
        assert "-S" not in argv and "-U" not in argv and "-h" not in argv
        assert argv[-1] == TARGET

    def test_full_check_emits_no_check_flag(self) -> None:
        argv = TestsslTool().build_argv(
            TestsslArgs(target=TARGET, check="full"), out_file="/tmp/t.json"
        )
        for flag in ("-p", "-S", "-P", "-U", "-h"):
            assert flag not in argv

    def test_starttls_is_always_a_protocol_pair(self) -> None:
        argv = TestsslTool().build_argv(
            TestsslArgs(target=TARGET, starttls="smtp"), out_file="/tmp/t.json"
        )
        assert argv[-2:] == ["smtp", TARGET]
        assert argv[-3] == "-t"
        # bare -t would eat the target as a protocol: it must never happen
        argv = TestsslTool().build_argv(TestsslArgs(target=TARGET), out_file="/tmp/t.json")
        assert "-t" not in argv

    def test_safety_flags_timeouts_and_severity_floor(self) -> None:
        argv = TestsslTool().build_argv(
            TestsslArgs(target=TARGET, severity_floor="MEDIUM"),
            out_file="/tmp/t.json",
        )
        pairs = (
            ("--jsonfile", "/tmp/t.json"),
            ("--color", "0"),
            ("--severity", "MEDIUM"),
            ("--warnings", "batch"),
            ("--connect-timeout", "10"),
            ("--openssl-timeout", "10"),
        )
        assert "--quiet" in argv
        for flag, value in pairs:
            assert argv.index(flag) + 1 < len(argv)
            assert argv[argv.index(flag) + 1] == value
        assert TestsslTool.success_codes == (0,)

    def test_out_file_is_required(self) -> None:
        with pytest.raises(InvalidToolArguments, match="output file"):
            TestsslTool().build_argv(TestsslArgs(target=TARGET))


class TestParse:
    def test_warn_maps_to_medium_and_telemetry_is_skipped(self) -> None:
        output = json.dumps(
            [
                _record("TLS1", "WARN"),
                _record("scanTime", "WARN", "scan done in 12s"),
                _record("scanProblem", "WARN", "none"),
                _record("protocol-negotiated", "OK", "TLS 1.3"),
                _record("some-info", "INFO", "details here"),
                _record("fatal-seen", "FATAL", "oops"),
                _record("untested", "MEDIUM", "not tested: skipped"),
                _record("blank", "HIGH", "   "),
                _record("cipher-a", "HIGH"),
            ]
        )
        findings = TestsslTool().parse(TestsslArgs(target=TARGET), output)
        by_id = {f.evidence.split("id=", 1)[1].split()[0]: f for f in findings}
        assert set(by_id) == {"TLS1", "cipher-a"}
        assert by_id["TLS1"].severity is Severity.MEDIUM
        assert by_id["cipher-a"].severity is Severity.HIGH
