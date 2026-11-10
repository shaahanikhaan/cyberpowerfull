"""wpscan wrapper: WordPress enumeration and vulnerability matching."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, severity_from_text, truncate

_ENUM_CHOICES = {"vp", "vt", "tt", "cb", "dbe", "u", "ap", "at"}


class WpscanArgs(UrlInput):
    """Validated wpscan invocation arguments."""

    enumerate: list[str] = Field(default_factory=lambda: ["vp", "vt", "u"])
    plugins_detection: Literal["passive", "mixed", "aggressive"] = "passive"
    max_findings: int = Field(default=80, ge=1, le=300)

    @field_validator("enumerate")
    @classmethod
    def _check_enumerate(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            token = str(value).strip().lower()
            if token not in _ENUM_CHOICES:
                raise ValueError(f"unsupported wpscan enumeration token: {value!r}")
            cleaned.append(token)
        return cleaned


class WpscanTool(BaseTool):
    name = "wpscan"
    phase = Phase.SCANNING
    skill = "cms_wordpress"
    binary = "wpscan"
    writes_output_file = True
    success_codes = (0, 5)  # wpscan exits 5 when it finds vulnerabilities
    timeout_s = 900
    description = (
        "WordPress-specific scanner: core version, vulnerable plugins and themes, "
        "and user enumeration. Vulnerability records carry CVE identifiers."
    )
    input_model = WpscanArgs

    def build_argv(self, args: WpscanArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "wpscan",
            "--url",
            args.target,
            "--format",
            "json",
            "--output",
            out_file or "-",
            "--no-banner",
            "--no-update",
            "--random-user-agent",
            "--disable-tls-checks",
            "--plugins-detection",
            args.plugins_detection,
        ]
        if args.enumerate:
            argv.extend(["-e", ",".join(args.enumerate)])
        return argv

    def parse(self, args: WpscanArgs, output: str, out_file: str | None = None) -> list[Finding]:
        try:
            payload = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict):
            return []
        findings: list[Finding] = []

        version = payload.get("version") or {}
        if isinstance(version, dict) and version.get("number"):
            findings.append(
                self.finding(
                    title=f"WordPress core version disclosed: {version.get('number')}",
                    severity=Severity.LOW,
                    confidence=0.85,
                    target=args.target,
                    endpoint=args.target,
                    evidence=truncate(
                        f"wpscan version={version.get('number')} status={version.get('status')}"
                    ),
                    remediation="Remove the generator meta tag and keep core patched.",
                )
            )
            findings.extend(
                self._vulnerabilities(
                    args, version.get("vulnerabilities"), component="WordPress core"
                )
            )

        for kind in ("plugins", "themes"):
            components = payload.get(kind) or {}
            if not isinstance(components, dict):
                continue
            for name, details in components.items():
                if not isinstance(details, dict):
                    continue
                installed = (details.get("version") or {}).get("number")
                findings.extend(
                    self._vulnerabilities(
                        args,
                        details.get("vulnerabilities"),
                        component=f"{kind[:-1]} {name}" + (f" {installed}" if installed else ""),
                    )
                )

        users = payload.get("users")
        if isinstance(users, dict):
            names = ", ".join(sorted(users)[:10])
            if names:
                findings.append(
                    self.finding(
                        title=f"WordPress user enumeration succeeded: {names}",
                        severity=Severity.LOW,
                        confidence=0.8,
                        target=args.target,
                        endpoint=args.target,
                        evidence=truncate(f"wpscan users={names}"),
                        remediation="Disable REST user listing and author archives where possible.",
                    )
                )

        for item in payload.get("interesting_findings") or []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or args.target)
            findings.append(
                self.finding(
                    title=truncate(f"WordPress exposure: {item.get('type') or url}", 200),
                    severity=severity_from_text(str(item.get("type") or "")),
                    confidence=0.6,
                    target=args.target,
                    endpoint=url,
                    evidence=truncate(json.dumps(item, default=str)),
                )
            )
        return findings[: args.max_findings]

    def _vulnerabilities(self, args: WpscanArgs, items: Any, *, component: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(items, list):
            return findings
        for item in items:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "WordPress vulnerability")
            severity = severity_from_text(f"{title} {item.get('cve') or ''}")
            if severity is Severity.INFO:
                severity = Severity.MEDIUM
            cve = item.get("cve")
            findings.append(
                self.finding(
                    title=truncate(f"{component}: {title}", 260),
                    severity=severity,
                    confidence=0.8,
                    target=args.target,
                    endpoint=args.target,
                    evidence=truncate(
                        f"wpscan component={component} fixed_in={item.get('fixed_in')} "
                        f"cve={cve}"
                    ),
                    cve=str(cve) if cve else None,
                    remediation=(
                        f"Update to {item.get('fixed_in')} or remove the component."
                        if item.get("fixed_in")
                        else "Update or remove the vulnerable component."
                    ),
                )
            )
        return findings

    def observations(self, args: WpscanArgs, output: str) -> list[str]:
        count = len(self.parse(args, output))
        return [f"wpscan: {count} item(s) for {args.target}"]


__all__ = ["WpscanArgs", "WpscanTool"]
