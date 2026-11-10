"""searchsploit wrapper: offline Exploit-DB lookups against the local mirror.

The tool queries the locally installed Exploit-DB (`/usr/share/exploitdb`) via
`searchsploit --json`. It never downloads exploits and never executes them: it
answers "is there public exploit code for this product/version", which is the
evidence needed to raise or lower a finding's priority.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

_QUERY_RE = re.compile(r"^[A-Za-z0-9 ._+\-/]{2,120}$")
_REMOTE = re.compile(r"remote|rce|code execution|overflow", re.IGNORECASE)


class SearchsploitArgs(HostInput):
    """Validated searchsploit invocation arguments.

    ``target`` is the in-scope asset the lookup is evidence for; ``query`` is the
    product, version or CVE text searched in the local Exploit-DB mirror.
    """

    query: str = Field(min_length=2, max_length=120)
    max_findings: int = Field(default=15, ge=1, le=100)

    @field_validator("query")
    @classmethod
    def _check_query(cls, value: str) -> str:
        if not _QUERY_RE.match(value):
            raise ValueError("query must be plain product/version text (no shell characters)")
        return value


class SearchsploitTool(BaseTool):
    name = "searchsploit"
    phase = Phase.VALIDATION
    skill = "exploit_availability"
    binary = "searchsploit"
    success_codes = (0, 1)
    timeout_s = 120
    description = (
        "Searches the locally installed Exploit-DB mirror for public exploit code "
        "matching a product, version or CVE. Local-only: no download, no execution."
    )
    input_model = SearchsploitArgs

    def build_argv(self, args: SearchsploitArgs, out_file: str | None = None) -> list[str]:
        return ["searchsploit", "--json", args.query]

    def parse(
        self, args: SearchsploitArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        payload = _load(output)
        if payload is None:
            return []
        findings: list[Finding] = []
        for record in payload:
            title = str(record.get("Title") or record.get("title") or "Exploit-DB entry")
            edb_id = str(record.get("EDB-ID") or record.get("edb_id") or "?")
            path = str(record.get("Path") or record.get("path") or "")
            exploit_type = str(record.get("Type") or record.get("type") or "")
            severity = Severity.MEDIUM if _REMOTE.search(title) else Severity.LOW
            findings.append(
                self.finding(
                    title=truncate(f"Public exploit available: {title}", 220),
                    severity=severity,
                    confidence=0.6,
                    target=args.target,
                    endpoint=None,
                    evidence=truncate(
                        f"searchsploit query={args.query!r} edb_id={edb_id} "
                        f"type={exploit_type} path={path} date={record.get('Date')}"
                    ),
                    remediation=(
                        "Confirm the exact version is affected and patch; public exploit "
                        "code raises the priority of the matching advisory."
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: SearchsploitArgs, output: str) -> list[str]:
        payload = _load(output) or []
        return [f"searchsploit: {len(payload)} local Exploit-DB record(s) for {args.query!r}"]


def _load(output: str) -> list[dict[str, Any]] | None:
    text = output.strip()
    if not text:
        return None
    start, end = text.find("{"), text.rfind("}")
    candidate = text[start : end + 1] if start != -1 and end > start else text
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    records = payload.get("RESULTS_EXPLOIT") or payload.get("RESULTS_SHELLCODE") or []
    return [item for item in records if isinstance(item, dict)]


__all__ = ["SearchsploitArgs", "SearchsploitTool"]
