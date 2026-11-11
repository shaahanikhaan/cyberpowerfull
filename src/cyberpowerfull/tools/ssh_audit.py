"""ssh-audit wrapper: SSH server configuration auditing (JSON output).

Flags verified against jtesta/ssh-audit (``src/ssh_audit/ssh_audit.py`` on
main, 2026-11-11): ``-j`` prints one JSON document to stdout whose shape is
built by ``build_struct`` (``target/banner/kex/key/enc/mac/compression/
fingerprints/cves/recommendations/additional_notes``). Per-algorithm notes
carry ``fail``/``warn``/``info`` levels (``fetch_notes``). Exit codes come
from ``exitcodes.py``: 0 good, 2 warnings, 3 failures, 1 connection error,
so 2 and 3 are successful runs with findings, not failures.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

#: Algorithm categories ssh-audit reports, in JSON key order.
_CATEGORIES = ("kex", "key", "enc", "mac")

#: sshd_config directive that disables an algorithm of each category.
_FIX_DIRECTIVE = {
    "kex": "KexAlgorithms",
    "key": "HostKeyAlgorithms",
    "enc": "Ciphers",
    "mac": "MACs",
}


class SshAuditArgs(HostInput):
    """Validated ssh-audit invocation arguments."""

    port: int = Field(default=22, ge=1, le=65535)
    max_findings: int = Field(default=25, ge=1, le=100)


class SshAuditTool(BaseTool):
    name = "ssh_audit"
    phase = Phase.SCANNING
    skill = "network_services"
    binary = "ssh-audit"
    # 2 = warnings found, 3 = failures found: both are completed audits.
    success_codes = (0, 2, 3)
    description = (
        "SSH server algorithm audit (kex, host key, cipher, MAC). "
        "Reports fail/warn-level algorithms plus banner-matched CVEs."
    )
    input_model = SshAuditArgs

    def build_argv(self, args: SshAuditArgs, out_file: str | None = None) -> list[str]:
        host = args.target
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return ["ssh-audit", "-j", f"{host}:{args.port}"]

    def parse(self, args: SshAuditArgs, output: str, out_file: str | None = None) -> list[Finding]:
        try:
            document = json.loads(output.strip())
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(document, dict):
            return []
        findings: list[Finding] = []
        for category in _CATEGORIES:
            entries = document.get(category)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                self._collect_algorithm(args, category, entry, findings)
                if len(findings) >= args.max_findings:
                    return findings
        cves = document.get("cves")
        if isinstance(cves, list):
            for entry in cves:
                cve_id = _cve_id(entry)
                if not cve_id:
                    continue
                findings.append(
                    self.finding(
                        title=f"SSH software may be affected by {cve_id}",
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        target=args.target,
                        endpoint=f"{args.target}:{args.port}",
                        evidence=truncate(
                            f"ssh-audit cve={cve_id} (banner-matched; " "backports not ruled out)"
                        ),
                        remediation=(
                            "Confirm the SSH software version and patch level, "
                            "then upgrade to a fixed release."
                        ),
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings
        return findings

    def _collect_algorithm(
        self,
        args: SshAuditArgs,
        category: str,
        entry: dict[str, Any],
        findings: list[Finding],
    ) -> None:
        notes = entry.get("notes")
        if not isinstance(notes, dict):
            return
        algorithm = str(entry.get("algorithm") or "unknown")
        directive = _FIX_DIRECTIVE[category]
        for level, severity, confidence in (
            ("fail", Severity.MEDIUM, 0.8),
            ("warn", Severity.LOW, 0.7),
        ):
            messages = notes.get(level)
            if not messages:
                continue
            if isinstance(messages, str):
                messages = [messages]
            text = "; ".join(str(item) for item in messages if item).strip()
            findings.append(
                self.finding(
                    title=truncate(f"Weak SSH {category} algorithm: {algorithm}", 200),
                    severity=severity,
                    confidence=confidence,
                    target=args.target,
                    endpoint=f"{args.target}:{args.port}",
                    evidence=truncate(f"ssh-audit {category} {algorithm}: {text or level}"),
                    remediation=(
                        f"Remove {algorithm} via the {directive} directive "
                        "in sshd_config and restart sshd."
                    ),
                )
            )

    def observations(self, args: SshAuditArgs, output: str) -> list[str]:
        try:
            document = json.loads(output.strip())
        except (json.JSONDecodeError, ValueError):
            return ["ssh-audit: output was not JSON"]
        if not isinstance(document, dict):
            return ["ssh-audit: output was not a JSON object"]
        banner = document.get("banner")
        software = banner.get("software") if isinstance(banner, dict) else None
        recommendations = document.get("recommendations")
        count = len(recommendations) if isinstance(recommendations, list) else 0
        return [
            f"ssh-audit: software={software or 'unknown'} "
            f"recommendations={count} target={document.get('target', args.target)}"
        ]


def _cve_id(entry: Any) -> str:
    if isinstance(entry, str):
        return entry.strip()
    if isinstance(entry, dict):
        for key in ("id", "cve", "name"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


__all__ = ["SshAuditArgs", "SshAuditTool"]
