"""Report generation from a trace (Markdown, JSON findings, SARIF, run manifest)."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from cyberpowerfull.models import Finding, Severity
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

    if trace.skipped:
        lines.extend(["", "## Skipped steps", ""])
        lines.extend(f"- `{entry}`" for entry in trace.skipped)

    if trace.error:
        lines.extend(["", "## Run error", "", _inline(trace.error)])

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
            "Recon precedes scanning, scanning precedes validation, and the execution trace "
            "above is the actual sequence. Findings are derived only from recorded tool output "
            "stored in append-only memory; hypotheses remain in the attack tree until "
            f"confirmed. {inference_note}",
            "",
        ]
    )
    return "\n".join(lines)


#: SARIF level for each finding severity (GitHub code scanning reads these).
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rule_id(finding: Finding) -> str:
    """A stable rule id: the CVE, else the CWE, else a slug of the title."""
    if finding.cve:
        return finding.cve
    if finding.cwe:
        return finding.cwe
    slug = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")
    return f"cpf/{slug or 'finding'}"[:128]


def _uri(finding: Finding) -> str:
    """The artefact a result points at: the endpoint when known, else the target."""
    raw = (finding.endpoint or finding.target or "").strip()
    if "://" in raw:
        return raw
    return f"//{raw}" if raw else "unknown"


def render_sarif(trace: Trace) -> dict:
    """Render the run's findings as SARIF 2.1.0 for code-scanning consumers.

    Only recorded findings are exported; a hypothesis in the attack tree never becomes a
    SARIF result, and unverified findings carry ``verified: false`` in their properties so a
    consumer cannot mistake a candidate for a confirmed issue.
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in trace.sorted_findings():
        rule_id = _rule_id(finding)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.title[:200]},
                "fullDescription": {
                    "text": (finding.remediation or finding.evidence or finding.title)[:1000]
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(finding.severity.value, "note")},
                "properties": {
                    "severity": finding.severity.value,
                    "cwe": finding.cwe,
                    "cve": finding.cve,
                    "cvss": finding.cvss,
                    "tool": finding.tool,
                    "skill": finding.skill,
                },
            },
        )
        message = finding.title
        if finding.evidence:
            message = f"{message}\n\nEvidence: {finding.evidence[:1500]}"
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": list(rules).index(rule_id),
                "level": _SARIF_LEVEL.get(finding.severity.value, "note"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(finding)},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence,
                    "verified": finding.verified,
                    "tool": finding.tool,
                    "skill": finding.skill,
                    "endpoint": finding.endpoint,
                    "target": finding.target,
                    "cve": finding.cve,
                    "cwe": finding.cwe,
                },
            }
        )

    statuses = {(step.result or {}).get("status") for step in trace.steps}
    successful = trace.stop_reason not in {"inference_failed", "policy_violation"} and not (
        statuses & {"error", "timeout"}
    )
    run: dict = {
        "tool": {
            "driver": {
                "name": "cyberpowerfull",
                "informationUri": "https://github.com/shaahanikhaan/cyberpowerfull",
                "version": trace.agent_version,
                "rules": list(rules.values()),
            }
        },
        "automationDetails": {"id": trace.run_id},
        "invocations": [
            {
                "executionSuccessful": successful,
                "startTimeUtc": trace.started_at,
                **({"endTimeUtc": trace.finished_at} if trace.finished_at else {}),
                "toolExecutionNotifications": [
                    {
                        "level": "note",
                        "message": {"text": entry},
                    }
                    for entry in trace.skipped[:200]
                ],
            }
        ],
        "results": results,
        "properties": {
            "target": trace.target,
            "engagement": trace.engagement,
            "backend": trace.backend,
            "model": trace.model,
            "stop_reason": trace.stop_reason,
            "severity_counts": trace.severity_counts(),
            "scope_fingerprint": trace.scope_fingerprint,
        },
    }
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }


def render_run_json(trace: Trace) -> dict:
    """A single machine-readable manifest describing the whole run."""
    statuses: dict[str, int] = {}
    tools: list[str] = []
    for step in trace.steps:
        status = (step.result or {}).get("status", "unknown")
        statuses[status] = statuses.get(status, 0) + 1
        if step.tool and step.tool not in tools:
            tools.append(step.tool)
    return {
        "schema": "cyberpowerfull.run/1",
        "run_id": trace.run_id,
        "agent": {"name": trace.agent, "version": trace.agent_version},
        "engagement": trace.engagement,
        "target": trace.target,
        "scope_fingerprint": trace.scope_fingerprint,
        "backend": trace.backend,
        "model": trace.model,
        "started_at": trace.started_at,
        "finished_at": trace.finished_at,
        "stop_reason": trace.stop_reason,
        "error": trace.error,
        "budget": trace.budget.model_dump(mode="json"),
        "tool_status": statuses,
        "tools_used": tools,
        "steps": [
            {
                "index": step.index,
                "action": step.action,
                "tool": step.tool,
                "node": step.node,
                "status": (step.result or {}).get("status"),
                "findings": len(step.finding_ids),
                "reason": step.reason,
                "error": step.error,
            }
            for step in trace.steps
        ],
        "skipped": list(trace.skipped),
        "severity_counts": trace.severity_counts(),
        "findings": len(trace.findings),
        "verified_findings": sum(1 for finding in trace.findings if finding.verified),
    }


def write_reports(trace: Trace, out_dir: str | Path) -> dict[str, Path]:
    """Write Markdown report and machine-readable findings for one run."""
    directory = Path(out_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    report_path = directory / f"report-{trace.run_id}.md"
    findings_path = directory / f"findings-{trace.run_id}.json"
    sarif_path = directory / f"findings-{trace.run_id}.sarif"
    run_path = directory / f"run-{trace.run_id}.json"
    write_private_text(report_path, render_markdown(trace))
    write_private_text(sarif_path, json.dumps(render_sarif(trace), indent=2, default=str))
    write_private_text(run_path, json.dumps(render_run_json(trace), indent=2, default=str))
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
    return {
        "report": report_path,
        "findings": findings_path,
        "sarif": sarif_path,
        "run": run_path,
    }


def severity_breakdown(trace: Trace) -> str:
    """One-line severity breakdown for the CLI summary."""
    counts = trace.severity_counts()
    parts = [
        f"{level}={counts[level]}" for level in [s.value for s in Severity] if counts.get(level, 0)
    ]
    return ", ".join(parts) if parts else "none"


__all__ = [
    "render_markdown",
    "render_run_json",
    "render_sarif",
    "severity_breakdown",
    "write_reports",
]
