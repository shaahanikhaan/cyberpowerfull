"""trivy wrapper: filesystem vulnerability, secret, and misconfig scanning.

Flags verified against aquasecurity/trivy v0.76.2
(docs ``target/filesystem`` + ``configuration/others|reporting``,
2026-11-11): ``trivy fs --scanners vuln,secret[,misconfig] --format json
--output FILE --severity LOW,MEDIUM,HIGH,CRITICAL --skip-version-check
--disable-telemetry --exit-code 0 PATH``.

Notes:

* The first run downloads the vulnerability database (network). Telemetry
  and the version check are always off.
* Secret results keep rule/file/line only. The ``Code`` snippet can carry
  the secret itself, so the parser never copies it into evidence.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, LocalPathInput, truncate

Scanner = Literal["vuln", "secret", "misconfig"]


class TrivyArgs(LocalPathInput):
    """Validated trivy filesystem-scan arguments."""

    scanners: list[Scanner] = Field(default_factory=lambda: ["vuln", "secret"])
    severity_floor: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    max_findings: int = Field(default=100, ge=1, le=1000)

    @field_validator("scanners")
    @classmethod
    def _check_scanners(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one scanner is required")
        return values


class TrivyTool(BaseTool):
    name = "trivy"
    phase = Phase.SCANNING
    skill = "vuln_scanning"
    binary = "trivy"
    scans_local_paths = True
    writes_output_file = True
    timeout_s = 900
    description = (
        "Filesystem audit: dependency vulnerabilities, hardcoded secrets, "
        "and (opt-in) IaC misconfigurations. Secret values never reach the "
        "report."
    )
    input_model = TrivyArgs

    def build_argv(self, args: TrivyArgs, out_file: str | None = None) -> list[str]:
        if not out_file:
            raise ValueError("trivy requires an output file for --output")
        floors = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        severities = ",".join(floors[floors.index(args.severity_floor) :])
        return [
            "trivy",
            "fs",
            "--scanners",
            ",".join(args.scanners),
            "--format",
            "json",
            "--output",
            out_file,
            "--severity",
            severities,
            "--skip-version-check",
            "--disable-telemetry",
            "--exit-code",
            "0",
            "--quiet",
            args.target,
        ]

    def parse(self, args: TrivyArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            document = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []
        results = document.get("Results") if isinstance(document, dict) else None
        if not isinstance(results, list):
            return []
        for result in results:
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target") or args.target)
            for vuln in result.get("Vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vid = str(vuln.get("VulnerabilityID") or "vuln")
                pkg = str(vuln.get("PkgName") or "?")
                installed = str(vuln.get("InstalledVersion") or "?")
                fixed = str(vuln.get("FixedVersion") or "unfixed")
                title = str(vuln.get("Title") or vid).strip()
                severity = Severity.coerce(str(vuln.get("Severity") or "medium"))
                cve = vid if vid.startswith("CVE-") else ""
                findings.append(
                    self.finding(
                        title=truncate(f"{vid} in {pkg} {installed}: {title}", 220),
                        severity=severity,
                        confidence=0.9,
                        target=args.target,
                        endpoint=f"{target}:{pkg}",
                        evidence=truncate(
                            f"trivy {vid} pkg={pkg} installed={installed} fixed={fixed}"
                        ),
                        **({"cve": cve} if cve else {}),
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings[: args.max_findings]
            for secret in result.get("Secrets") or []:
                if not isinstance(secret, dict):
                    continue
                rule = str(secret.get("RuleID") or "secret")
                line_number = secret.get("StartLine") or 0
                try:
                    line_number = int(line_number)
                except (TypeError, ValueError):
                    line_number = 0
                endpoint = f"{target}:{line_number}" if line_number else target
                # secret["Code"] can carry the secret: location proves it.
                findings.append(
                    self.finding(
                        title=f"Hardcoded secret ({rule}) in {target}",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        target=args.target,
                        endpoint=endpoint,
                        evidence=truncate(
                            f"trivy rule={rule} file={target} line={line_number or '-'}"
                        ),
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings[: args.max_findings]
            for misconfig in result.get("Misconfigurations") or []:
                if not isinstance(misconfig, dict):
                    continue
                check_id = str(misconfig.get("ID") or "misconfig")
                title = str(misconfig.get("Title") or check_id).strip()
                severity = Severity.coerce(str(misconfig.get("Severity") or "medium"))
                resolution = str(misconfig.get("Resolution") or "").strip()
                findings.append(
                    self.finding(
                        title=truncate(f"{check_id}: {title}", 220),
                        severity=severity,
                        confidence=0.85,
                        target=args.target,
                        endpoint=target,
                        evidence=truncate(f"trivy {check_id} fix={resolution[:200]}".strip()),
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings[: args.max_findings]
        return findings[: args.max_findings]

    def observations(self, args: TrivyArgs, output: str) -> list[str]:
        return [f"trivy ({','.join(args.scanners)}): {len(self.parse(args, output))} finding(s)"]


__all__ = ["TrivyArgs", "TrivyTool"]
