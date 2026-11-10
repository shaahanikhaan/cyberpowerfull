"""Native CVE correlation tool: observed components -> candidate advisories.

The tool does no network I/O. It reads the local advisory corpus (bundled
snapshot plus whatever NVD/KEV feeds the operator imported), matches the
components the agent supplies, and returns unverified candidate findings with the
matched range, CVSS, KEV flag, and a remediation hint.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from pydantic import Field, field_validator

from cyberpowerfull.errors import CyberpowerfullError
from cyberpowerfull.intel.models import Component
from cyberpowerfull.intel.service import DEFAULT_INTEL_PATH, correlate, load_store
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, ToolInput, ToolStatus, _Exec, truncate


class CveCorrelateArgs(ToolInput):
    """Validated correlation arguments.

    ``components`` is the essential input: product/version pairs observed with
    nmap, httpx, nikto, whatweb, or a banner. Unknown keys are rejected.
    """

    components: list[Component] = Field(min_length=1, max_length=50)
    min_cvss: float = Field(default=0.0, ge=0.0, le=10.0)
    min_severity: str = Field(default="medium")
    intel_store: str | None = Field(default=None, max_length=400)

    @field_validator("min_severity")
    @classmethod
    def _check_severity(cls, value: str) -> str:
        allowed = {severity.value for severity in Severity}
        if value.lower() not in allowed:
            raise ValueError(f"min_severity must be one of {sorted(allowed)}")
        return value.lower()


class CveCorrelateTool(BaseTool):
    name = "cve_correlate"
    phase = Phase.VALIDATION
    skill = "exploit_availability"
    binary: ClassVar[str | None] = None
    timeout_s = 30
    description = (
        "Correlate observed product/version components against the local advisory corpus "
        "(bundled snapshot plus imported NVD/KEV feeds). Returns unverified candidate CVEs "
        "with matched ranges, CVSS, KEV status, and remediation. No network access."
    )
    input_model = CveCorrelateArgs

    def build_argv(self, args: CveCorrelateArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "cve_correlate",
            "--target",
            args.target,
            "--min-cvss",
            str(args.min_cvss),
            "--min-severity",
            args.min_severity,
        ]
        for component in args.components:
            argv.extend(["--component", component.label()])
        if args.intel_store:
            argv.extend(["--intel-store", args.intel_store])
        return argv

    def _execute(self, args: CveCorrelateArgs, argv: list[str], policy: Any) -> _Exec:
        try:
            store = load_store(args.intel_store or DEFAULT_INTEL_PATH)
        except (CyberpowerfullError, OSError) as exc:
            return _Exec(status=ToolStatus.ERROR, error=f"advisory corpus unavailable: {exc}")
        try:
            stats = store.stats()
            findings = correlate(
                args.components,
                store=store,
                target=args.target,
                min_cvss=args.min_cvss,
                min_severity=Severity(args.min_severity),
            )
        finally:
            store.close()
        payload = {
            "target": args.target,
            "components": len(args.components),
            "candidates": len(findings),
            "corpus": stats,
            "findings": [finding.model_dump(mode="json") for finding in findings],
        }
        return _Exec(stdout=json.dumps(payload))

    def parse(
        self, args: CveCorrelateArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        if not output.strip():
            return []
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for item in payload.get("findings", []):
            try:
                findings.append(Finding.model_validate(item))
            except Exception:
                continue
        return findings

    def observations(self, args: CveCorrelateArgs, output: str) -> list[str]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return ["cve_correlate produced unparsable output"]
        corpus = payload.get("corpus") or {}
        years = ",".join(corpus.get("years") or []) or "-"
        lines = [
            f"cve_correlate components={payload.get('components')} "
            f"candidates={payload.get('candidates')} corpus={corpus.get('total')} "
            f"kev={corpus.get('kev')} years={years}"
        ]
        for finding in payload.get("findings", [])[:5]:
            lines.append(
                truncate(
                    f"candidate {finding.get('cve')} [{finding.get('severity')}] "
                    f"conf={finding.get('confidence')} {finding.get('title')}",
                    300,
                )
            )
        return lines


__all__ = ["CveCorrelateArgs", "CveCorrelateTool"]
