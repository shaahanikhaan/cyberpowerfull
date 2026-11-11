"""kubescape wrapper: Kubernetes posture across frameworks or manifests.

Flags verified against kubescape/kubescape v4.0.20 (README, 2026-11-11):
``kubescape scan [framework nsa|mitre|...] --format json --output FILE``
for a live cluster, ``kubescape scan /path/to/manifests ...`` for files.

Cluster scans read the ambient kubeconfig (``~/.kube/config`` unless
``KUBECONFIG`` says otherwise): without one the run fails fast with a hint
instead of a cryptic client error. Manifest scans are contained by
``scope.allowed_paths`` via the orchestrator gate.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, ToolInput, truncate

Framework = Literal["nsa", "mitre", "devopsbest", "sock2", "all"]


class KubescapeArgs(HostInput):
    """Validated kubescape arguments (cluster or manifest scan)."""

    framework: Framework = "all"
    manifests: str | None = Field(default=None, max_length=500)
    max_findings: int = Field(default=100, ge=1, le=1000)


class KubescapeTool(BaseTool):
    name = "kubescape"
    phase = Phase.SCANNING
    skill = "k8s_posture"
    binary = "kubescape"
    writes_output_file = True
    timeout_s = 900
    description = (
        "Kubernetes posture: live-cluster scan across compliance frameworks, "
        "or an offline manifest-directory scan. Failed controls become "
        "findings with remediation."
    )
    input_model = KubescapeArgs

    def build_argv(self, args: KubescapeArgs, out_file: str | None = None) -> list[str]:
        if not out_file:
            raise ValueError("kubescape requires an output file for --output")
        argv = ["kubescape", "scan"]
        if args.manifests:
            argv.append(args.manifests)
        elif args.framework != "all":
            argv.extend(["framework", args.framework])
        argv.extend(["--format", "json", "--output", out_file])
        return argv

    def _execute(self, args: ToolInput, argv: list[str], policy):  # type: ignore[no-untyped-def]
        from cyberpowerfull.tools.base import ToolResult, ToolStatus

        if not getattr(args, "manifests", None) and not _kubeconfig_exists():
            return ToolResult(
                tool=self.name,
                status=ToolStatus.MISSING,
                error=(
                    "kubescape cluster scan needs a kubeconfig "
                    "(~/.kube/config or $KUBECONFIG); for an offline scan pass "
                    "manifests= inside scope.allowed_paths"
                ),
            )
        return super()._execute(args, argv, policy)

    def parse(self, args: KubescapeArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            document = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []
        controls = document.get("controls") if isinstance(document, dict) else None
        if isinstance(controls, dict):
            items = controls.values()
        elif isinstance(controls, list):
            items = controls
        else:
            return []
        for control in items:
            if not isinstance(control, dict):
                continue
            status = control.get("status") or {}
            state = str(status.get("status") if isinstance(status, dict) else status).lower()
            if state != "failed":
                continue
            control_id = str(control.get("controlID") or control.get("id") or "control")
            name = str(control.get("name") or control_id).strip()
            remediation = str(control.get("remediation") or "").strip()
            resources = control.get("failedResources") or control.get("resources") or []
            count = len(resources) if isinstance(resources, list) else 0
            findings.append(
                self.finding(
                    title=truncate(f"[{control_id}] {name}", 220),
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    target=args.target,
                    endpoint=args.target,
                    evidence=truncate(
                        f"kubescape failed control={control_id} "
                        f"resources={count} fix={remediation[:200]}".strip()
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: KubescapeArgs, output: str) -> list[str]:
        mode = f"manifests {args.manifests}" if args.manifests else f"framework {args.framework}"
        note = f"kubescape ({mode}): {len(self.parse(args, output))} failed control(s)"
        try:
            document = json.loads(output) if output.strip() else {}
            summary = document.get("summaryDetails") if isinstance(document, dict) else None
            if isinstance(summary, dict):
                score = summary.get("score")
                if score is not None:
                    note += f" (score {score})"
        except json.JSONDecodeError:
            pass
        return [note]


def _kubeconfig_exists() -> bool:
    override = os.environ.get("KUBECONFIG", "").strip()
    if override:
        return any(Path(part).expanduser().is_file() for part in override.split(":") if part)
    return (Path.home() / ".kube" / "config").is_file()


__all__ = ["KubescapeArgs", "KubescapeTool"]
