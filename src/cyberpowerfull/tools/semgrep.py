"""semgrep wrapper: static analysis (SAST) over local code.

Flags verified against semgrep/semgrep v1.185.0 (``semgrep scan --help`` in
the CLI reference, 2026-11-11): ``semgrep scan --config CFG --json
--output FILE --metrics=off --disable-version-check PATH``.

Config policy: a local rules file/directory keeps the run fully offline;
a ``p/...`` registry slug downloads rules (network) but never uploads code
— metrics and the version check are always off. ``--config auto`` is
refused: it logs the project URL to the registry.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, LocalPathInput, truncate

_SEVERITY = {"INFO": Severity.LOW, "WARNING": Severity.MEDIUM, "ERROR": Severity.HIGH}


class SemgrepArgs(LocalPathInput):
    """Validated semgrep invocation arguments."""

    config: str = Field(default="p/default", min_length=1, max_length=500)
    exclude: list[str] = Field(default_factory=list, max_length=20)
    max_findings: int = Field(default=100, ge=1, le=1000)

    @field_validator("config")
    @classmethod
    def _check_config(cls, value: str) -> str:
        cleaned = value.strip()
        if cleaned == "auto" or cleaned.startswith("auto"):
            raise ValueError("semgrep --config auto phones home the project URL; refusing")
        if cleaned.startswith(("p/", "r/", "s/")):
            return cleaned  # registry slug: rules download, code stays local
        candidate = Path(cleaned).expanduser()
        if not candidate.exists():
            raise ValueError(f"semgrep config not found: {cleaned}")
        return str(candidate)


class SemgrepTool(BaseTool):
    name = "semgrep"
    phase = Phase.SCANNING
    skill = "sast"
    binary = "semgrep"
    scans_local_paths = True
    writes_output_file = True
    timeout_s = 900
    description = (
        "Static analysis over local code with local rules (offline) or a "
        "registry ruleset (rules download only). Findings map CWE/OWASP IDs."
    )
    input_model = SemgrepArgs

    def build_argv(self, args: SemgrepArgs, out_file: str | None = None) -> list[str]:
        if not out_file:
            raise ValueError("semgrep requires an output file for --output")
        argv = [
            "semgrep",
            "scan",
            "--config",
            args.config,
            "--json",
            "--output",
            out_file,
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
        ]
        for pattern in args.exclude:
            argv.extend(["--exclude", pattern])
        argv.append(args.target)
        return argv

    def parse(self, args: SemgrepArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            document = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []
        results = document.get("results") if isinstance(document, dict) else None
        if not isinstance(results, list):
            return []
        for item in results:
            if not isinstance(item, dict):
                continue
            check_id = str(item.get("check_id") or "semgrep")
            path = str(item.get("path") or args.target)
            start = item.get("start") or {}
            line_number = start.get("line") if isinstance(start, dict) else 0
            try:
                line_number = int(line_number)
            except (TypeError, ValueError):
                line_number = 0
            endpoint = f"{path}:{line_number}" if line_number else path
            extra = item.get("extra") or {}
            message = str(extra.get("message") or check_id).strip()
            severity = _SEVERITY.get(str(extra.get("severity") or "").upper(), Severity.MEDIUM)
            metadata = extra.get("metadata") or {}
            cwe = str(metadata.get("cwe") or "") if isinstance(metadata, dict) else ""
            owasp = str(metadata.get("owasp") or "") if isinstance(metadata, dict) else ""
            refs = " ".join(part for part in (cwe, owasp) if part)
            findings.append(
                self.finding(
                    title=truncate(
                        f"{check_id}: {message.splitlines()[0] if message else check_id}", 220
                    ),
                    severity=severity,
                    confidence=0.75,
                    target=args.target,
                    endpoint=endpoint,
                    evidence=truncate(f"semgrep {check_id} {refs} {message[:200]}".strip()),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: SemgrepArgs, output: str) -> list[str]:
        note = f"semgrep ({args.config}): {len(self.parse(args, output))} finding(s)"
        try:
            document = json.loads(output) if output.strip() else {}
            errors = document.get("errors") if isinstance(document, dict) else None
            if isinstance(errors, list) and errors:
                note += f" ({len(errors)} file(s) failed to parse)"
        except json.JSONDecodeError:
            pass
        return [note]


__all__ = ["SemgrepArgs", "SemgrepTool"]
