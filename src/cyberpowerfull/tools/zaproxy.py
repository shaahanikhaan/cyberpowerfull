"""ZAP wrapper: headless baseline via the Automation Framework.

Flags byte-verified against zaproxy/zaproxy v2.17.0:

* ``-cmd`` in core ``CommandLine.java`` (headless, no GUI/daemon),
* ``-autorun PLAN`` in the automation add-on (``ExtensionAutomation.java``),
* ``traditional-json`` report template in the reports add-on.

The wrapper renders a deterministic AF plan (spider -> passiveScan-wait ->
optional activeScan -> report) into the run temp dir and points the report
job at the tool-output file, so parsing needs no extra plumbing. Plan
rendering is plain string building (no YAML dependency): every interpolated
value is a validated URL, an int, or a fixed token.

Active scanning attacks the target, so ``active=True`` additionally needs
the ``aggressive`` capability (enforced by the orchestrator gate, like the
dnsx wordlist gate). The default is spider + passive rules only.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_RISK = {3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW, 0: Severity.INFO}


class ZapArgs(UrlInput):
    """Validated ZAP baseline arguments."""

    active: bool = False
    spider_minutes: int = Field(default=5, ge=1, le=60)
    active_minutes: int = Field(default=10, ge=1, le=120)
    max_findings: int = Field(default=100, ge=1, le=1000)


class ZapTool(BaseTool):
    name = "zap"
    phase = Phase.SCANNING
    skill = "dast_baseline"
    binary = "zap.sh"
    binary_alternatives = ("zap", "zaproxy")
    writes_output_file = True
    timeout_s = 1800
    description = (
        "Headless ZAP baseline: spider plus passive rules (default), with an "
        "opt-in bounded active scan. Findings map ZAP risk to severity."
    )
    input_model = ZapArgs

    def build_argv(self, args: ZapArgs, out_file: str | None = None) -> list[str]:
        if not out_file:
            raise ValueError("zap requires an output file for its JSON report")
        plan_path = str(Path(out_file).with_name("zap-plan.yaml"))
        Path(plan_path).write_text(self.render_plan(args, out_file), encoding="utf-8")
        return ["zap.sh", "-cmd", "-autorun", plan_path]

    @staticmethod
    def render_plan(args: ZapArgs, out_file: str) -> str:
        """Render the Automation Framework plan (deterministic, no tabs)."""
        report_dir = str(Path(out_file).parent)
        report_file = Path(out_file).name
        jobs = (
            "  - type: spider\n"
            "    parameters:\n"
            f"      url: {args.target}\n"
            f"      maxDuration: {args.spider_minutes}\n"
            "  - type: passiveScan-wait\n"
            "    parameters:\n"
            f"      maxDuration: {args.spider_minutes}\n"
        )
        if args.active:
            jobs += (
                "  - type: activeScan\n"
                "    parameters:\n"
                f"      maxDuration: {args.active_minutes}\n"
            )
        jobs += (
            "  - type: report\n"
            "    parameters:\n"
            "      template: traditional-json\n"
            f"      reportDir: {report_dir}\n"
            f"      reportFile: {report_file}\n"
        )
        return (
            "env:\n"
            "  contexts:\n"
            "    - name: cpf\n"
            "      urls:\n"
            f"        - {args.target}\n"
            "jobs:\n" + jobs
        )

    def parse(self, args: ZapArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            document = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []
        sites = document.get("site") if isinstance(document, dict) else None
        if not isinstance(sites, list):
            return []
        for site in sites:
            if not isinstance(site, dict):
                continue
            for alert in site.get("alerts") or []:
                if not isinstance(alert, dict):
                    continue
                try:
                    risk = int(alert.get("riskcode", 0))
                except (TypeError, ValueError):
                    risk = 0
                name = str(alert.get("name") or alert.get("alert") or "zap alert")
                cweid = str(alert.get("cweid") or "").strip()
                cwe = f"CWE-{cweid}" if cweid.isdigit() else ""
                instances = alert.get("instances") or []
                if not isinstance(instances, list) or not instances:
                    instances = [{}]
                for instance in instances:
                    if not isinstance(instance, dict):
                        continue
                    uri = str(instance.get("uri") or args.target)
                    method = str(instance.get("method") or "GET")
                    param = str(instance.get("param") or "")
                    evidence_text = str(instance.get("evidence") or "")
                    solution = str(alert.get("solution") or "").strip()
                    findings.append(
                        self.finding(
                            title=truncate(f"ZAP {name}: {uri}", 220),
                            severity=_RISK.get(risk, Severity.INFO),
                            confidence=0.7,
                            target=args.target,
                            endpoint=uri,
                            evidence=truncate(
                                f"zap risk={risk} method={method} param={param or '-'} "
                                f"evidence={evidence_text[:160]} fix={solution[:160]}".strip()
                            ),
                            **({"cwe": cwe} if cwe else {}),
                        )
                    )
                    if len(findings) >= args.max_findings:
                        return findings[: args.max_findings]
        return findings[: args.max_findings]

    def observations(self, args: ZapArgs, output: str) -> list[str]:
        mode = "active" if args.active else "passive"
        return [f"zap ({mode}): {len(self.parse(args, output))} alert instance(s)"]


__all__ = ["ZapArgs", "ZapTool"]
