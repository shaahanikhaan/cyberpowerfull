"""dnsrecon wrapper: standard DNS enumeration and zone-transfer checks."""

from __future__ import annotations

import json
from typing import Any, Literal

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, truncate

_RECORD_SEVERITY = {
    "zone transfer": Severity.MEDIUM,
    "zonetransfer": Severity.MEDIUM,
    "wildcard": Severity.LOW,
    "spf": Severity.INFO,
}


class DnsreconArgs(DomainInput):
    """Validated dnsrecon invocation arguments."""

    scan_type: Literal["std", "axfr", "brt", "srv", "tld", "zonewalk"] = "std"
    lifetime_s: int = 30


class DnsreconTool(BaseTool):
    name = "dnsrecon"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "dnsrecon"
    writes_output_file = True
    success_codes = (0, 1)
    timeout_s = 600
    description = (
        "DNS record enumeration, SRV discovery and zone-transfer testing. "
        "Structured JSON output is parsed into per-record evidence."
    )
    input_model = DnsreconArgs

    def build_argv(self, args: DnsreconArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "dnsrecon",
            "-d",
            args.target,
            "-t",
            args.scan_type,
            "--lifetime",
            str(args.lifetime_s),
        ]
        if out_file:
            argv.extend(["-j", out_file])
        return argv

    def parse(self, args: DnsreconArgs, output: str, out_file: str | None = None) -> list[Finding]:
        records = _load_records(output)
        findings: list[Finding] = []
        for record in records:
            record_type = str(record.get("type") or record.get("Type") or "").lower()
            name = str(record.get("name") or record.get("Name") or args.target)
            address = str(
                record.get("address")
                or record.get("Address")
                or record.get("target")
                or record.get("exchange")
                or ""
            )
            if record_type in {"soa", "ns"}:
                continue  # structural, not evidence
            severity = _RECORD_SEVERITY.get(record_type, Severity.INFO)
            title = (
                f"Zone transfer succeeded on {name}"
                if record_type in {"zone transfer", "zonetransfer"}
                else f"DNS {record_type.upper() or 'record'} record for {name}"
            )
            findings.append(
                self.finding(
                    title=truncate(title, 200),
                    severity=severity,
                    confidence=0.85 if severity is not Severity.INFO else 0.7,
                    target=args.target,
                    endpoint=name,
                    evidence=truncate(
                        f"dnsrecon type={record_type or 'unknown'} name={name} value={address}"
                    ),
                    remediation=(
                        "Restrict AXFR to authorised secondaries."
                        if severity is Severity.MEDIUM
                        else None
                    ),
                )
            )
        return findings

    def observations(self, args: DnsreconArgs, output: str) -> list[str]:
        records = _load_records(output)
        types = sorted({str(item.get("type") or item.get("Type") or "?") for item in records})
        return [f"dnsrecon: {len(records)} record(s), types={', '.join(types) or 'none'}"]


def _load_records(output: str) -> list[dict[str, Any]]:
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
            payload = payload.get("records") or []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
    return []


__all__ = ["DnsreconArgs", "DnsreconTool"]
