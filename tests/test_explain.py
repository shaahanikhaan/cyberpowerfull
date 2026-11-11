"""Plain-language explanations: rule hits, fallbacks, and report embedding."""

from __future__ import annotations

import pytest

from cyberpowerfull.explain import explain_finding
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.reporting import render_markdown
from tests.test_trace_reporting import sample_finding, sample_trace


def _finding(title: str, tool: str = "nuclei", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        confidence=0.9,
        target="127.0.0.1",
        endpoint="127.0.0.1:443",
        evidence="e",
        tool=tool,
        phase=Phase.VALIDATION,
    )


class TestExplain:
    def test_sql_injection_rule(self) -> None:
        assert "parameterized queries" in explain_finding(sample_finding())

    def test_expired_certificate_rule(self) -> None:
        line = explain_finding(_finding("TLS certificate expired for x:443", tool="tlsx"))
        assert "past its expiry date" in line and "renew" in line

    def test_secret_rule(self) -> None:
        line = explain_finding(_finding("Hardcoded secret (rule) in app.py", tool="gitleaks"))
        assert "revoke the secret" in line

    def test_tool_scoped_rule_ignores_other_tools(self) -> None:
        line = explain_finding(_finding("CIS 1.1.1: something", tool="nmap"))
        assert "CIS Kubernetes Benchmark" not in line  # kubebench rule is tool-scoped

    @pytest.mark.parametrize(
        "severity",
        [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
    )
    def test_fallback_never_empty(self, severity: Severity) -> None:
        line = explain_finding(_finding("Utterly novel title 12345", severity=severity))
        assert line.endswith(".") and len(line) > 20

    def test_report_embeds_explanations(self) -> None:
        report = render_markdown(sample_trace())
        assert "what this means" in report
        assert "parameterized queries" in report
