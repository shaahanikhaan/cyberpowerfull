"""wafw00f wrapper: web application firewall detection."""

from __future__ import annotations

import json
from typing import Any

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate


class Wafw00fArgs(UrlInput):
    """Validated wafw00f invocation arguments."""

    find_all: bool = True
    max_findings: int = Field(default=10, ge=1, le=30)


class Wafw00fTool(BaseTool):
    name = "wafw00f"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = "wafw00f"
    writes_output_file = True
    success_codes = (0, 1)
    timeout_s = 180
    description = (
        "Fingerprints the WAF in front of a target. Knowing the WAF changes rate "
        "limits and encoding choices for every later probe."
    )
    input_model = Wafw00fArgs

    def build_argv(self, args: Wafw00fArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "wafw00f",
            args.target,
            "-f",
            "json",
            "-o",
            out_file or "-",
            "-a",
        ]
        return argv

    def parse(self, args: Wafw00fArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for record in _load(output):
            if not record.get("detected"):
                continue
            firewall = str(record.get("firewall") or record.get("manufacturer") or "unknown")
            findings.append(
                self.finding(
                    title=f"Web application firewall detected: {firewall}",
                    severity=Severity.INFO,
                    confidence=0.8,
                    target=args.target,
                    endpoint=str(record.get("url") or args.target),
                    evidence=truncate(
                        f"wafw00f detected={firewall} manufacturer={record.get('manufacturer')}"
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: Wafw00fArgs, output: str) -> list[str]:
        records = _load(output)
        names = [
            str(item.get("firewall"))
            for item in records
            if item.get("detected") and item.get("firewall")
        ]
        return [f"wafw00f: detected={', '.join(names) or 'none'} ({len(records)} tested)"]


def _load(output: str) -> list[dict[str, Any]]:
    text = output.strip()
    if not text:
        return []
    candidates = [text]
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            payload = [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
    return []


__all__ = ["Wafw00fArgs", "Wafw00fTool"]
