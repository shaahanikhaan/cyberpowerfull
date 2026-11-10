"""whatweb wrapper: technology fingerprinting with JSON log output."""

from __future__ import annotations

import json

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate


class WhatwebArgs(UrlInput):
    """Validated whatweb invocation arguments."""

    aggression: int = Field(default=1, ge=1, le=4)
    max_findings: int = Field(default=60, ge=1, le=200)


class WhatwebTool(BaseTool):
    name = "whatweb"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "whatweb"
    writes_output_file = True
    success_codes = (0,)
    timeout_s = 300
    description = (
        "Technology and CMS fingerprinting with plugin-level detail. Version "
        "disclosure from a plugin becomes a low-severity finding; the stack itself "
        "is recorded as reconnaissance evidence."
    )
    input_model = WhatwebArgs

    def build_argv(self, args: WhatwebArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "whatweb",
            f"--log-json={out_file or '-'}",
            "--no-errors",
            "--color=never",
            "-a",
            str(args.aggression),
            args.target,
        ]
        return argv

    def parse(self, args: WhatwebArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for target, plugins in _iter_plugins(output):
            stack: list[str] = []
            for name, details in plugins.items():
                if not isinstance(details, dict):
                    continue
                versions = details.get("version") or []
                if isinstance(versions, str):
                    versions = [versions]
                version = ", ".join(str(item) for item in versions[:3])
                stack.append(f"{name}{('/' + version) if version else ''}")
                if version:
                    findings.append(
                        self.finding(
                            title=f"Technology version disclosed: {name} {version}",
                            severity=Severity.LOW,
                            confidence=0.75,
                            target=args.target,
                            endpoint=target or args.target,
                            evidence=truncate(f"whatweb plugin={name} version={version}"),
                            remediation="Suppress version banners where feasible.",
                        )
                    )
            if stack:
                findings.append(
                    self.finding(
                        title=f"Technology fingerprint: {', '.join(stack[:6])}",
                        severity=Severity.INFO,
                        confidence=0.8,
                        target=args.target,
                        endpoint=target or args.target,
                        evidence=truncate(f"whatweb stack={', '.join(stack)}"),
                    )
                )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: WhatwebArgs, output: str) -> list[str]:
        targets = list(_iter_plugins(output))
        return [f"whatweb: fingerprinted {len(targets)} URL(s)"]


def _iter_plugins(output: str) -> list[tuple[str, dict]]:
    """whatweb JSON logs are a JSONL stream of ``[target, {plugins...}]`` pairs."""
    results: list[tuple[str, dict]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, list) or len(payload) < 2:
            continue
        target, body = payload[0], payload[1]
        plugins = body.get("plugins") if isinstance(body, dict) else None
        if isinstance(plugins, dict):
            results.append((str(target), plugins))
    return results


__all__ = ["WhatwebArgs", "WhatwebTool"]
