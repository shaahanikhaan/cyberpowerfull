"""Shared extraction helpers for tools that emit prose or vendor reports.

Strix, PentAGI and Sn1per do not share one machine-readable schema. Instead of
pretending they do, this module applies a conservative, deterministic extraction
pass over their report text: explicit severity tags and bullet-style finding
lines become findings, everything else stays an observation. A line that cannot
be classified is never promoted to a finding.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from cyberpowerfull.models import Finding, Phase, Severity

_SEVERITY_TOKEN = re.compile(
    r"\b(critical|high|medium|moderate|low|informational|info)\b", re.IGNORECASE
)
_TITLE_CLEAN = re.compile(r"^[\s#>*\-\u2013\u2014\[\]()0-9.:|]+")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE = re.compile(r"CWE-\d{1,4}", re.IGNORECASE)

_NOISE_PREFIXES = (
    "usage",
    "warning",
    "note:",
    "info:",
    "debug",
    "traceback",
    "=====",
    "-----",
    "started",
    "finished",
    "elapsed",
    "tokens",
    "cost",
)

_MIN_TITLE = 8
_MAX_TITLE = 220


def _clean(line: str) -> str:
    text = line.strip().strip("|").strip()
    text = re.sub(r"\*\*|__|`", "", text)
    text = _TITLE_CLEAN.sub("", text).strip()
    return text


def _is_noise(text: str) -> bool:
    lowered = text.lower()
    if len(text) < _MIN_TITLE:
        return True
    return any(lowered.startswith(prefix) for prefix in _NOISE_PREFIXES)


def extract_report_findings(
    text: str,
    *,
    tool: str,
    target: str,
    skill: str | None = None,
    phase: Phase = Phase.VALIDATION,
    max_findings: int = 80,
) -> list[Finding]:
    """Yield findings from severity-tagged lines in an external agent report."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for raw_line in text.splitlines():
        line = _clean(raw_line)
        if _is_noise(line):
            continue
        match = _SEVERITY_TOKEN.search(line)
        if not match:
            continue
        severity = Severity.coerce(match.group(1).lower())
        title = line[:300]
        key = title.lower()
        if key in seen:
            continue
        seen.add(key)
        cve = _CVE.search(title)
        cwe = _CWE.search(title)
        findings.append(
            Finding(
                title=title[:_MAX_TITLE],
                severity=severity,
                confidence=0.75 if severity.rank >= Severity.MEDIUM.rank else 0.55,
                target=target,
                endpoint=None,
                evidence=line[:1000],
                tool=tool,
                skill=skill,
                cve=cve.group(0).upper() if cve else None,
                cwe=cwe.group(0).upper() if cwe else None,
                verified=severity.rank >= Severity.HIGH.rank,
                phase=phase,
            )
        )
        if len(findings) >= max_findings:
            break
    return findings


def merge_findings(*groups: Iterable[Finding]) -> list[Finding]:
    """De-duplicate findings by ``(title, endpoint)`` while preserving order."""
    merged: list[Finding] = []
    seen: set[tuple[str, str | None]] = set()
    for group in groups:
        for finding in group:
            key = (finding.title.lower(), finding.endpoint)
            if key in seen:
                continue
            seen.add(key)
            merged.append(finding)
    return merged


def findings_from_json_records(
    records: Iterable[Any],
    *,
    tool: str,
    target: str,
    skill: str | None = None,
    phase: Phase = Phase.VALIDATION,
) -> list[Finding]:
    """Turn ``{"severity","title","description"}`` records into findings."""
    findings: list[Finding] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        severity = Severity.coerce(str(record.get("severity") or record.get("risk") or "info"))
        title = str(
            record.get("title")
            or record.get("name")
            or record.get("description")
            or "External agent finding"
        )[:220]
        endpoint = record.get("endpoint") or record.get("url") or record.get("location")
        findings.append(
            Finding(
                title=title,
                severity=severity,
                confidence=0.8 if severity.rank >= Severity.HIGH.rank else 0.6,
                target=target,
                endpoint=str(endpoint) if endpoint else None,
                evidence=json.dumps(record, default=str)[:1000],
                tool=tool,
                skill=skill,
                cve=str(record["cve"]) if record.get("cve") else None,
                cwe=str(record["cwe"]) if record.get("cwe") else None,
                verified=severity.rank >= Severity.HIGH.rank,
                phase=phase,
            )
        )
    return findings


__all__ = [
    "extract_report_findings",
    "findings_from_json_records",
    "merge_findings",
]
