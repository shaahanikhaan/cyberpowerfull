"""Report generation from a trace (Markdown + JSON findings)."""

from __future__ import annotations

import json
from pathlib import Path

from cyberpowerfull.models import Severity
from cyberpowerfull.trace import Trace, summarize_trace


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        escaped = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in row]
        lines.append("| " + " | ".join(escaped) + " |")
    return "\n".join(lines)


def render_markdown(trace: Trace) -> str:
    """Render a human-reviewable Markdown report for one run."""
    summary = summarize_trace(trace)
    counts = summary["severity_counts"]
    lines: list[str] = [
        "# Penetration Test Report",
        "",
        f"- engagement: `{trace.engagement}`",
        f"- target: `{trace.target}`",
        f"- run_id: `{trace.run_id}`",
        f"- agent: {trace.agent} {trace.agent_version} "
        f"(backend: {trace.backend}, model: {trace.model})",
        f"- started: {trace.started_at}",
        f"- finished: {trace.finished_at or 'incomplete'}",
        f"- stop_reason: `{trace.stop_reason}`",
        f"- scope_fingerprint: `{trace.scope_fingerprint[:16]}`",
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
                    f"#### {index}. [{finding.severity.value.upper()}] {finding.title}",
                    "",
                    f"- target: `{finding.target}`",
                    f"- endpoint: `{finding.endpoint or 'n/a'}`",
                    f"- tool: `{finding.tool}` skill: `{finding.skill or 'n/a'}`",
                    f"- confidence: {finding.confidence:.2f} verified: {finding.verified}",
                    f"- cwe: {finding.cwe or 'n/a'} cve: {finding.cve or 'n/a'} "
                    f"cvss: {finding.cvss if finding.cvss is not None else 'n/a'}",
                    f"- evidence: `{finding.evidence or 'none recorded'}`",
                    f"- remediation: {finding.remediation or 'not specified'}",
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
                ["Step", "Action", "Tool", "Node", "Status", "Findings", "Reason"],
                [
                    [
                        str(step.index),
                        step.action,
                        step.tool or "-",
                        step.node or "-",
                        (step.result or {}).get("status", (step.error and "error") or "-"),
                        str(len(step.finding_ids)),
                        (step.reason or step.error or "")[:80],
                    ]
                    for step in trace.steps
                ],
            )
        )
    else:
        lines.append("No steps were executed.")

    if trace.stop_reason in {"inference_failed", "policy_violation"} and trace.error:
        lines.extend(["", "## Run error", "", f"`{trace.error}`"])

    if trace.backend.startswith("playbook:"):
        inference_note = (
            "This run executed a deterministic playbook: no model was invoked, every step "
            "was selected by the playbook definition and gated by the same worker policy."
        )
    else:
        inference_note = "All inference ran on a local open-weight model."
    lines.extend(
        [
            "",
            "## Methodology",
            "",
            "Recon precedes scanning, scanning precedes validation. Findings are derived only "
            "from recorded tool output stored in append-only memory; hypotheses remain in the "
            f"attack tree until confirmed. {inference_note}",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(trace: Trace, out_dir: str | Path) -> dict[str, Path]:
    """Write Markdown report and machine-readable findings for one run."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    report_path = directory / f"report-{trace.run_id}.md"
    findings_path = directory / f"findings-{trace.run_id}.json"
    report_path.write_text(render_markdown(trace), encoding="utf-8")
    findings_path.write_text(
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
        encoding="utf-8",
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
