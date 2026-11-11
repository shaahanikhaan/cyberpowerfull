"""gitleaks wrapper: secret scanning for directories and git history.

Flags verified against zricethezav/gitleaks v8.30.1 (``gitleaks --help`` in
the README, 2026-11-11): ``gitleaks dir|git SRC --report-format json
--report-path FILE --exit-code 0 --redact --no-banner``.

Secret hygiene: ``--redact`` keeps raw secrets out of the report, and the
parser additionally drops the ``Secret``/``Match`` payloads — findings keep
rule, file, and line only. A finding proves a secret exists at a location;
it never carries the secret itself.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, LocalPathInput, truncate


class GitleaksArgs(LocalPathInput):
    """Validated gitleaks invocation arguments."""

    mode: Literal["dir", "git"] = "dir"
    config: str | None = Field(default=None, max_length=500)
    max_findings: int = Field(default=100, ge=1, le=1000)


class GitleaksTool(BaseTool):
    name = "gitleaks"
    phase = Phase.SCANNING
    skill = "secret_scanning"
    binary = "gitleaks"
    scans_local_paths = True
    writes_output_file = True
    timeout_s = 600
    description = (
        "Secret scanning for a local directory (dir) or full git history "
        "(git). Findings carry rule, file, and line only — never the secret."
    )
    input_model = GitleaksArgs

    def build_argv(self, args: GitleaksArgs, out_file: str | None = None) -> list[str]:
        if not out_file:
            raise ValueError("gitleaks requires an output file for its JSON report")
        argv = [
            "gitleaks",
            args.mode,
            args.target,
            "--report-format",
            "json",
            "--report-path",
            out_file,
            "--exit-code",
            "0",
            "--redact",
            "--no-banner",
            "--log-level",
            "warn",
        ]
        if args.config:
            argv.extend(["--config", args.config])
        return argv

    def parse(self, args: GitleaksArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            records = json.loads(output) if output.strip() else []
        except json.JSONDecodeError:
            return []
        if not isinstance(records, list):
            return []
        for record in records:
            if not isinstance(record, dict):
                continue
            rule = str(record.get("RuleID") or "secret")
            path = str(record.get("File") or args.target)
            line = record.get("StartLine") or 0
            try:
                line_number = int(line)
            except (TypeError, ValueError):
                line_number = 0
            endpoint = f"{path}:{line_number}" if line_number else path
            description = str(record.get("Description") or rule).strip()
            tags = record.get("Tags") or []
            tag_text = ",".join(str(tag) for tag in tags[:6]) if isinstance(tags, list) else ""
            # Secret/Match payloads are deliberately unread: location proves it.
            findings.append(
                self.finding(
                    title=f"Hardcoded secret ({rule}) in {path}",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    target=args.target,
                    endpoint=endpoint,
                    evidence=truncate(
                        f"gitleaks rule={rule} file={path} line={line_number or '-'} "
                        f"desc={description[:160]} tags={tag_text}"
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: GitleaksArgs, output: str) -> list[str]:
        return [f"gitleaks ({args.mode}): {len(self.parse(args, output))} secret(s)"]


__all__ = ["GitleaksArgs", "GitleaksTool"]
