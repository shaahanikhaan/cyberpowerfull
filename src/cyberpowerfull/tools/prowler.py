"""prowler wrapper: read-only cloud posture (OCSF JSON).

Flags verified against prowler-cloud/prowler v5.48.0 (CLI docs + argument
parser, 2026-11-11): ``prowler <aws|azure|gcp|kubernetes> -M json-ocsf -o
DIR [-c CHECK ...] [-s SERVICE ...] [-f REGION ...]``.

Credential gating: each provider needs its ambient credential before the
binary runs (AWS env/profile, Azure service-principal env, GCP application
credentials, kubeconfig). Missing credentials fail fast with a setup hint —
never a stack trace, never a partial scan mistaken for clean.

``target`` is a free-form account label (the credential is the scope, so no
host containment applies). Only FAIL findings become findings; PASS rows
feed the observation counters.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, ToolInput, json_lines, truncate

Provider = Literal["aws", "azure", "gcp", "kubernetes"]

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


class ProwlerArgs(ToolInput):
    """Validated prowler arguments (provider + check selection)."""

    provider: Provider = "aws"
    checks: list[str] = Field(default_factory=list, max_length=50)
    services: list[str] = Field(default_factory=list, max_length=30)
    regions: list[str] = Field(default_factory=list, max_length=30)
    max_findings: int = Field(default=100, ge=1, le=1000)


class ProwlerTool(BaseTool):
    name = "prowler"
    phase = Phase.SCANNING
    skill = "cloud_posture"
    binary = "prowler"
    cloud_posture = True
    writes_output_file = True
    timeout_s = 1800
    description = (
        "Read-only cloud posture audit (AWS/Azure/GCP/Kubernetes) with "
        "credential presence gates. FAIL findings map to severity; PASS "
        "rows stay silent."
    )
    input_model = ProwlerArgs

    def build_argv(self, args: ProwlerArgs, out_file: str | None = None) -> list[str]:
        if not out_file:
            raise ValueError("prowler requires an output directory for -o")
        argv = [self.binary, args.provider, "-M", "json-ocsf", "-o", str(Path(out_file).parent)]
        if args.checks:
            argv.extend(["-c", *args.checks])
        if args.services:
            argv.extend(["-s", *args.services])
        if args.regions:
            argv.extend(["-f", *args.regions])
        return argv

    def _execute(self, args: ToolInput, argv: list[str], policy):  # type: ignore[no-untyped-def]
        from cyberpowerfull.tools.base import ToolResult, ToolStatus

        hint = _missing_credential_hint(getattr(args, "provider", "aws"))
        if hint is not None:
            return ToolResult(tool=self.name, status=ToolStatus.MISSING, error=hint)
        return super()._execute(args, argv, policy)

    def parse(self, args: ProwlerArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for record in _ocsf_records(output, out_file):
            # Real OCSF Detection Finding (py_ocsf_models): verdict lives in
            # status_code, the check id in metadata.event_code, the title in
            # finding_info.title, the asset in resources[0].
            status = str(record.get("status_code") or record.get("status") or "").upper()
            if status != "FAIL":
                continue
            metadata = record.get("metadata") or {}
            info = record.get("finding_info") or {}
            resources = record.get("resources") or []
            first = resources[0] if isinstance(resources, list) and resources else {}
            if not isinstance(first, dict):
                first = {}
            if not isinstance(metadata, dict):
                metadata = {}
            if not isinstance(info, dict):
                info = {}
            check_id = str(metadata.get("event_code") or record.get("check_id") or "prowler")
            title = str(info.get("title") or record.get("check_title") or check_id).strip()
            detail = str(record.get("status_detail") or record.get("message") or "").strip()
            region = str(first.get("region") or record.get("region") or "")
            resource = str(
                first.get("uid")
                or first.get("name")
                or record.get("resource_id")
                or region
                or args.target
            )
            remediation = record.get("remediation") or {}
            fix = str(remediation.get("desc") if isinstance(remediation, dict) else "")[:200]
            severity = _SEVERITY.get(str(record.get("severity") or "").lower(), Severity.MEDIUM)
            findings.append(
                self.finding(
                    title=truncate(f"[{check_id}] {title}", 220),
                    severity=severity,
                    confidence=0.85,
                    target=args.target,
                    endpoint=resource,
                    evidence=truncate(
                        f"prowler {args.provider} {check_id} region={region or '-'} "
                        f"resource={resource} detail={detail[:160]} fix={fix}".strip()
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: ProwlerArgs, output: str) -> list[str]:
        records = _ocsf_records(output, None)
        failed = sum(1 for record in records if str(record.get("status") or "").upper() == "FAIL")
        return [f"prowler ({args.provider}): {failed} FAIL / {len(records)} check(s)"]


def _ocsf_records(output: str, out_file: str | None) -> list[dict]:
    """Load OCSF records from stdout-JSON, a JSON array file, or JSONL."""
    texts: list[str] = []
    if output.strip():
        texts.append(output)
    if out_file:
        # prowler -o takes a directory: the JSON lands next to our marker file.
        parent = Path(out_file).parent
        try:
            candidates = sorted(
                (path for path in parent.glob("*.json") if path.is_file()),
                key=lambda path: path.stat().st_mtime,
            )
        except OSError:
            candidates = []
        for candidate in candidates[-3:]:
            try:
                texts.append(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
    records: list[dict] = []
    for text in texts:
        stripped = text.strip()
        if not stripped:
            continue
        try:
            document = json.loads(stripped)
        except json.JSONDecodeError:
            records.extend(record for record in json_lines(stripped))
            continue
        if isinstance(document, list):
            records.extend(item for item in document if isinstance(item, dict))
        elif isinstance(document, dict):
            inner = document.get("findings", document)
            if isinstance(inner, list):
                records.extend(item for item in inner if isinstance(item, dict))
    return records


def _missing_credential_hint(provider: str) -> str | None:
    """None when the provider's ambient credential exists, else a setup hint."""
    if provider == "aws":
        if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
            return None
        return (
            "prowler aws needs ambient credentials "
            "(AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or AWS_PROFILE)"
        )
    if provider == "azure":
        wanted = ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID")
        if all(os.environ.get(name) for name in wanted):
            return None
        return (
            "prowler azure needs a service principal in the environment "
            "(AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)"
        )
    if provider == "gcp":
        candidate = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if candidate and Path(candidate).expanduser().is_file():
            return None
        return (
            "prowler gcp needs GOOGLE_APPLICATION_CREDENTIALS pointing at a "
            "service-account key file"
        )
    if provider == "kubernetes":
        override = os.environ.get("KUBECONFIG", "").strip()
        if override:
            if any(Path(part).expanduser().is_file() for part in override.split(":") if part):
                return None
        elif (Path.home() / ".kube" / "config").is_file():
            return None
        return "prowler kubernetes needs a kubeconfig (~/.kube/config or $KUBECONFIG)"
    return f"unsupported prowler provider: {provider}"


__all__ = ["ProwlerArgs", "ProwlerTool"]
