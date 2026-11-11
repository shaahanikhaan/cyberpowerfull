"""kube-bench wrapper: CIS Kubernetes Benchmark checks for a node.

Flags verified against aquasecurity/kube-bench v0.16.0
(``docs/flags-and-commands.md``, 2026-11-11): ``kube-bench [--json]
[--outputfile FILE]`` and ``kube-bench run --targets master,node,etcd,
policies [--json]``.

Runs on the node under test (that is how kube-bench reads the local
config files and processes); ``target`` names that node and must be in
scope like any other host target. FAIL becomes a finding, WARN a
low-severity note; PASS/INFO stay silent.
"""

from __future__ import annotations

import json
from contextlib import suppress
from typing import Literal

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

Target = Literal["master", "node", "etcd", "policies"]


class KubebenchArgs(HostInput):
    """Validated kube-bench arguments."""

    targets: list[Target] = Field(default_factory=list, max_length=4)
    checks: list[str] = Field(default_factory=list, max_length=30)
    max_findings: int = Field(default=100, ge=1, le=1000)


class KubebenchTool(BaseTool):
    name = "kubebench"
    phase = Phase.SCANNING
    skill = "k8s_posture"
    binary = "kube-bench"
    writes_output_file = True
    timeout_s = 600
    description = (
        "CIS Kubernetes Benchmark checks against the node under test. "
        "Run it on the node (or in the privileged pod); failures map to "
        "findings with their remediation text."
    )
    input_model = KubebenchArgs

    def build_argv(self, args: KubebenchArgs, out_file: str | None = None) -> list[str]:
        if not out_file:
            raise ValueError("kube-bench requires an output file for --outputfile")
        argv = ["kube-bench"]
        if args.targets:
            argv.extend(["run", "--targets", ",".join(args.targets)])
        if args.checks:
            argv.extend(["--check", ",".join(args.checks)])
        argv.extend(["--json", "--outputfile", out_file])
        return argv

    def parse(self, args: KubebenchArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            document = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []
        controls = document.get("Controls") if isinstance(document, dict) else None
        if not isinstance(controls, list):
            return []
        for control in controls:
            if not isinstance(control, dict):
                continue
            for test in control.get("tests") or []:
                if not isinstance(test, dict):
                    continue
                for item in test.get("results") or []:
                    if not isinstance(item, dict):
                        continue
                    status = str(item.get("status") or "").upper()
                    if status not in {"FAIL", "WARN"}:
                        continue
                    number = str(item.get("test_number") or "?")
                    desc = str(item.get("test_desc") or "benchmark check").strip()
                    remediation = str(item.get("remediation") or "").strip()
                    actual = str(item.get("actual_value") or "").strip()
                    findings.append(
                        self.finding(
                            title=truncate(f"CIS {number}: {desc}", 220),
                            severity=Severity.MEDIUM if status == "FAIL" else Severity.LOW,
                            confidence=0.85,
                            target=args.target,
                            endpoint=args.target,
                            evidence=truncate(
                                f"kube-bench {status} {number} actual={actual[:160]} "
                                f"fix={remediation[:200]}".strip()
                            ),
                        )
                    )
                    if len(findings) >= args.max_findings:
                        return findings[: args.max_findings]
        return findings[: args.max_findings]

    def observations(self, args: KubebenchArgs, output: str) -> list[str]:
        note = f"kube-bench: {len(self.parse(args, output))} failing check(s)"
        with suppress(json.JSONDecodeError):
            document = json.loads(output) if output.strip() else {}
            totals = document.get("Totals") if isinstance(document, dict) else None
            if isinstance(totals, dict):
                note += (
                    f" (pass={totals.get('total_pass', '?')} "
                    f"fail={totals.get('total_fail', '?')} "
                    f"warn={totals.get('total_warn', '?')})"
                )
        return [note]


__all__ = ["KubebenchArgs", "KubebenchTool"]
