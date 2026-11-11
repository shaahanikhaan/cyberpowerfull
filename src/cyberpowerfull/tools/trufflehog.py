"""trufflehog wrapper: verified secret scanning for files and git repos.

Flags verified against trufflesecurity/trufflehog v3.99.8 (README,
2026-11-11): ``trufflehog filesystem PATH... --json`` and ``trufflehog git
file://PATH --results=verified,unknown --json``.

Secret hygiene is load-bearing here:

* ``--no-verification`` is always passed. Verification would send each
  candidate secret to its owning vendor API; a local audit must never
  exfiltrate the secrets it finds.
* The parser reads the ``Redacted`` preview only and never touches ``Raw``.
* ``--no-update`` keeps the run offline and deterministic.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, LocalPathInput, json_lines, truncate


class TrufflehogArgs(LocalPathInput):
    """Validated trufflehog invocation arguments."""

    mode: Literal["filesystem", "git"] = "filesystem"
    since_commit: str | None = Field(default=None, max_length=100)
    branch: str | None = Field(default=None, max_length=200)
    max_findings: int = Field(default=100, ge=1, le=1000)


class TrufflehogTool(BaseTool):
    name = "trufflehog"
    phase = Phase.SCANNING
    skill = "secret_scanning"
    binary = "trufflehog"
    scans_local_paths = True
    timeout_s = 600
    description = (
        "Secret scanning with 800+ detectors for local files (filesystem) or "
        "git history (git). Verification is always off: findings never leave "
        "the box, and parsers only read redacted previews."
    )
    input_model = TrufflehogArgs

    def build_argv(self, args: TrufflehogArgs, out_file: str | None = None) -> list[str]:
        argv = ["trufflehog", args.mode]
        if args.mode == "git":
            argv.append(f"file://{args.target}")
            argv.append("--results=verified,unknown")
            if args.since_commit:
                argv.extend(["--since-commit", args.since_commit])
            if args.branch:
                argv.extend(["--branch", args.branch])
        else:
            argv.append(args.target)
        argv.extend(["--json", "--no-verification", "--no-update"])
        return argv

    def parse(
        self, args: TrufflehogArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        for record in json_lines(output):
            detector = str(record.get("DetectorName") or record.get("DetectorType") or "?")
            metadata = record.get("SourceMetadata") or {}
            data = metadata.get("Data") if isinstance(metadata, dict) else None
            filesystem = (data or {}).get("Filesystem") if isinstance(data, dict) else None
            path = str((filesystem or {}).get("file") or args.target)
            line = (filesystem or {}).get("line") or 0
            try:
                line_number = int(line)
            except (TypeError, ValueError):
                line_number = 0
            endpoint = f"{path}:{line_number}" if line_number else path
            # record["Raw"] is the live secret: never read, never logged.
            preview = str(record.get("Redacted") or "")[:40]
            findings.append(
                self.finding(
                    title=f"Possible secret ({detector}) in {path}",
                    severity=Severity.HIGH,
                    confidence=0.7,  # unverified by design (see module docstring)
                    target=args.target,
                    endpoint=endpoint,
                    evidence=truncate(
                        f"trufflehog detector={detector} file={path} "
                        f"line={line_number or '-'} preview={preview}"
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: TrufflehogArgs, output: str) -> list[str]:
        count = len(self.parse(args, output))
        return [f"trufflehog ({args.mode}, unverified): {count} secret(s)"]


__all__ = ["TrufflehogArgs", "TrufflehogTool"]
