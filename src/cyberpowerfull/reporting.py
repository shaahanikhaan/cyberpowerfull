"""Report generation from a trace (Markdown + JSON findings)."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from cyberpowerfull.models import Severity
from cyberpowerfull.storage import write_private_text
from cyberpowerfull.trace import Trace, summarize_trace


def _text(value: object) -> str:
    """Escape untrusted scanner/model text before placing it in Markdown."""
    plain = str(value).replace("\r", " ").replace("\n", " ")
    return html.escape(plain, quote=False)


def _markdown_text(value: object) -> str:
    return re.sub(r"([\\`*_{}\[\]()!#|])", r"\\\1", _text(value))


def _inline(value: object) -> str:
    text = _text(value)
    runs = re.findall(r"`+", text)
    delimiter = "`" * (max((len(run) for run in runs), default=0) + 1)
    return f"{delimiter} {text} {delimiter}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        escaped = [_markdown_text(cell) for cell in row]
        lines.append("| " + " | ".join(escaped) + " |")
    return "\n".join(lines)


def render_markdown(trace: Trace) -> str:
    """Render a human-reviewable Markdown report for one run."""
    summary = summarize_trace(trace)
    counts = summary["severity_counts"]
    lines: list[str] = [
        "# Penetration Test Report",
        "",
        f"- engagement: {_inline(trace.engagement)}",
        f"- target: {_inline(trace.target)}",
        f"- run_id: {_inline(trace.run_id)}",
        f"- agent: {_markdown_text(trace.agent)} {_markdown_text(trace.agent_version)} "
        f"(backend: {_markdown_text(trace.backend)}, model: {_markdown_text(trace.model)})",
        f"- started: {_markdown_text(trace.started_at)}",
        f"- finished: {_markdown_text(trace.finished_at or 'incomplete')}",
        f"- stop_reason: {_inline(trace.stop_reason)}",
        f"- scope_fingerprint: {_inline(trace.scope_fingerprint[:16])}",
        "",
        "## Summary",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Steps executed", str(summary["steps"])],
                ["Tool calls", str(summary["tool_calls"])],
                ["Findings", str(summary["findings"])],
                ["Verified findings", str(summary["verified_findings"])],
                *[[f"Severity: {level}", str(counts[level])] for level in counts],
            ],
        ),
        "",
        "## Findings",
        "",
    ]

    findings = trace.sorted_findings()
    if not findings:
        lines.append("No findings were produced in this run.")
    else:
        lines.append(
            _table(
                ["#", "Severity", "Confidence", "Title", "Endpoint", "Tool", "Verified"],
                [
                    [
                        str(index),
                        finding.severity.value,
                        f"{finding.confidence:.2f}",
                        finding.title,
                        finding.endpoint or "-",
                        finding.tool,
                        "yes" if finding.verified else "no",
                    ]
                    for index, finding in enumerate(findings, start=1)
                ],
            )
        )
        lines.append("")
        lines.append("### Finding detail")
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    "",
                    f"#### {index}. [{finding.severity.value.upper()}] "
                    f"{_markdown_text(finding.title)}",
                    "",
                    f"- target: {_inline(finding.target)}",
                    f"- endpoint: {_inline(finding.endpoint or 'n/a')}",
                    f"- tool: {_inline(finding.tool)} skill: {_inline(finding.skill or 'n/a')}",
                    f"- confidence: {finding.confidence:.2f} verified: {finding.verified}",
                    f"- cwe: {_markdown_text(finding.cwe or 'n/a')} "
                    f"cve: {_markdown_text(finding.cve or 'n/a')} "
                    f"cvss: {finding.cvss if finding.cvss is not None else 'n/a'}",
                    f"- evidence: {_inline(finding.evidence or 'none recorded')}",
                    f"- remediation: {_markdown_text(finding.remediation or 'not specified')}",
                ]
            )

    lines.extend(["", "## Attack tree", ""])
    if trace.attack_tree:
        lines.append(
            _table(
                ["State", "Nodes"],
                [[key, str(value)] for key, value in sorted(trace.attack_tree.items())],
            )
        )
    else:
        lines.append("Attack tree state was not recorded.")

    lines.extend(["", "## Execution trace", ""])
    if trace.steps:
        lines.append(
            _table(
                ["Step", "Action", "Tool", "Status", "Difficulty", "Findings", "Reason"],
                [
                    [
                        str(step.index),
                        step.action,
                        step.tool or "-",
                        (step.result or {}).get("status", (step.error and "error") or "-"),
                        str(step.tda.get("level", "-")),
                        str(len(step.finding_ids)),
                        (step.reason or step.error or "")[:80],
                    ]
                    for step in trace.steps
                ],
            )
        )
    else:
        lines.append("No steps were executed.")

    if trace.error:
        lines.extend(["", "## Run error", "", _inline(trace.error)])

    lines.extend(
        [
            "",
            "## Methodology",
            "",
            "The planner is guided to start with recon, then scanning and validation; actual "
            "steps are recorded above. Findings are derived from recorded tool output stored in "
            "append-only memory; hypotheses remain in the "
            "attack tree until confirmed. The recorded backend may be a local model or "
            "a replay stream; review each finding manually.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(trace: Trace, out_dir: str | Path) -> dict[str, Path]:
    """Write Markdown report and machine-readable findings for one run."""
    directory = Path(out_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    report_path = directory / f"report-{trace.run_id}.md"
    findings_path = directory / f"findings-{trace.run_id}.json"
    write_private_text(report_path, render_markdown(trace))
    write_private_text(
        findings_path,
        json.dumps(
            {
                "run_id": trace.run_id,
                "target": trace.target,
                "engagement": trace.engagement,
                "stop_reason": trace.stop_reason,
                "severity_counts": trace.severity_counts(),
                "findings": [
                    finding.model_dump(mode="json") for finding in trace.sorted_findings()
                ],
            },
            indent=2,
            default=str,
        ),
    )
    return {"report": report_path, "findings": findings_path}


def severity_breakdown(trace: Trace) -> str:
    """One-line severity breakdown for the CLI summary."""
    counts = trace.severity_counts()
    parts = [
        f"{level}={counts[level]}" for level in [s.value for s in Severity] if counts.get(level, 0)
    ]
    return ", ".join(parts) if parts else "none"


__all__ = ["render_markdown", "severity_breakdown", "write_reports"]
