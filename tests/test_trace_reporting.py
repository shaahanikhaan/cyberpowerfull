"""Trace and report tests: JSON contract, replay, and Markdown rendering."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberpowerfull.errors import CyberpowerfullError
from cyberpowerfull.models import BudgetState, Finding, Phase, Severity
from cyberpowerfull.reporting import render_markdown, severity_breakdown, write_reports
from cyberpowerfull.trace import (
    StepRecord,
    Trace,
    TraceRecorder,
    load_trace,
    save_trace,
    summarize_trace,
)


def sample_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        title="SQL injection in parameter id (GET)",
        severity=severity,
        confidence=0.95,
        target="127.0.0.1",
        endpoint="http://127.0.0.1/item?id=1",
        evidence="sqlmap confirmed injection",
        tool="sqlmap",
        skill="sql_injection",
        cwe="CWE-89",
        verified=True,
    )


def sample_trace() -> Trace:
    recorder = TraceRecorder(
        target="127.0.0.1",
        engagement="test-engagement",
        model="auto-1",
        backend="auto",
        scope_fingerprint="deadbeef" * 8,
        run_id="run-test",
    )
    recorder.add_step(
        StepRecord(
            index=1,
            action="delegate",
            phase=Phase.VALIDATION,
            tool="sqlmap",
            args={"target": "http://127.0.0.1/item?id=1"},
            reason="hypothesis h1",
            node="n1",
            tda={"level": "medium", "difficulty": 0.42},
            result={"status": "ok", "exit_code": 0},
            finding_ids=["f-1"],
        )
    )
    recorder.add_findings([sample_finding()])
    recorder.set_budget(BudgetState(iterations=1, tokens_used=1234))
    return recorder.finish(stop_reason="agent_terminated", tree={"total": 1, "open": 0})


class TestTraceRecorder:
    def test_finish_populates_metadata(self) -> None:
        trace = sample_trace()
        assert trace.stop_reason == "agent_terminated"
        assert trace.finished_at is not None
        assert trace.attack_tree["total"] == 1
        assert trace.agent_version

    def test_duplicate_findings_are_ignored(self) -> None:
        recorder = TraceRecorder(
            target="t", engagement="e", model="m", backend="b", scope_fingerprint="f"
        )
        finding = sample_finding()
        recorder.add_findings([finding, finding])
        recorder.add_findings([finding])
        assert len(recorder.findings) == 1

    def test_save_and_load(self, tmp_path: Path) -> None:
        trace = sample_trace()
        path = save_trace(trace, tmp_path / "nested" / "trace.json")
        loaded = load_trace(path)
        assert loaded.run_id == trace.run_id
        assert loaded.findings[0].title == trace.findings[0].title
        assert json.loads(path.read_text())["schema_version"] == "1.0"

    def test_recorder_save(self, tmp_path: Path) -> None:
        recorder = TraceRecorder(
            target="t", engagement="e", model="m", backend="b", scope_fingerprint="f"
        )
        recorder.finish(stop_reason="done")
        path = recorder.save(tmp_path / "trace.json")
        assert path.exists()

    def test_load_missing(self, tmp_path: Path) -> None:
        with pytest.raises(CyberpowerfullError, match="trace not found"):
            load_trace(tmp_path / "nope.json")

    def test_load_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{", encoding="utf-8")
        with pytest.raises(CyberpowerfullError, match="not valid JSON"):
            load_trace(path)

    def test_summary(self) -> None:
        summary = summarize_trace(sample_trace())
        assert summary["findings"] == 1
        assert summary["tool_calls"] == 1
        assert summary["severity_counts"]["high"] == 1
        assert summary["verified_findings"] == 1

    def test_severity_counts_and_sorting(self) -> None:
        recorder = TraceRecorder(
            target="t", engagement="e", model="m", backend="b", scope_fingerprint="f"
        )
        low = sample_finding(Severity.LOW)
        low.title = "low severity item"
        recorder.add_findings([low, sample_finding(Severity.CRITICAL)])
        trace = recorder.finish(stop_reason="x")
        assert trace.sorted_findings()[0].severity is Severity.CRITICAL
        assert trace.severity_counts()["critical"] == 1


class TestMarkdownReport:
    def test_contains_required_sections(self) -> None:
        markdown = render_markdown(sample_trace())
        for heading in (
            "# Penetration Test Report",
            "## Summary",
            "## Findings",
            "## Attack tree",
            "## Execution trace",
            "## Methodology",
        ):
            assert heading in markdown
        assert "SQL injection in parameter id" in markdown
        assert "CWE-89" in markdown
        assert "agent_terminated" in markdown

    def test_empty_findings(self) -> None:
        recorder = TraceRecorder(
            target="127.0.0.1", engagement="e", model="m", backend="b", scope_fingerprint="f"
        )
        trace = recorder.finish(stop_reason="attack_tree_exhausted")
        markdown = render_markdown(trace)
        assert "No findings were produced" in markdown
        assert "No steps were executed" in markdown

    def test_run_error_section(self) -> None:
        recorder = TraceRecorder(
            target="t", engagement="e", model="m", backend="b", scope_fingerprint="f"
        )
        trace = recorder.finish(stop_reason="inference_failed", error="endpoint unreachable")
        assert "## Run error" in render_markdown(trace)

    def test_write_reports(self, tmp_path: Path) -> None:
        trace = sample_trace()
        paths = write_reports(trace, tmp_path / "out")
        assert paths["report"].exists()
        payload = json.loads(paths["findings"].read_text())
        assert payload["findings"][0]["cwe"] == "CWE-89"
        assert payload["severity_counts"]["high"] == 1

    def test_severity_breakdown(self) -> None:
        assert "high=1" in severity_breakdown(sample_trace())
        empty = TraceRecorder(
            target="t", engagement="e", model="m", backend="b", scope_fingerprint="f"
        ).finish(stop_reason="x")
        assert severity_breakdown(empty) == "none"

    def test_pipe_characters_are_escaped(self) -> None:
        recorder = TraceRecorder(
            target="t", engagement="e", model="m", backend="b", scope_fingerprint="f"
        )
        finding = sample_finding()
        finding.title = "weird | title | with pipes"
        recorder.add_findings([finding])
        markdown = render_markdown(recorder.finish(stop_reason="x"))
        assert "weird \\| title" in markdown


def test_untrusted_scanner_text_cannot_inject_html_or_new_markdown_sections() -> None:
    recorder = TraceRecorder(
        target="t", engagement="e", model="m", backend="b", scope_fingerprint="f"
    )
    finding = sample_finding()
    finding.title = "<img src=x onerror=alert(1)>\n# fake heading"
    finding.evidence = "`<script>alert(1)</script>`\n# fake section"
    recorder.add_findings([finding])
    markdown = render_markdown(recorder.finish(stop_reason="done"))
    assert "<img" not in markdown and "<script>" not in markdown
    assert "\n# fake" not in markdown
    assert "&lt;img" in markdown and "&lt;script&gt;" in markdown
