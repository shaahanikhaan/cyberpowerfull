"""exiftool wrapper: file metadata extraction (JSON output).

Flags verified against exiftool/exiftool (``exiftool`` script on main,
2026-11-11): ``-j``/``-json`` selects JSON output, ``-s`` short tag names,
``-r`` recurses directories. The document is one JSON array (envelope at
``$bra/$ket`` ``[``/``]``) of per-file objects, each starting with
``SourceFile`` followed by its tags. Only in-scope local paths are read
(``scope.allowed_paths`` is enforced by the worker for local-path tools).
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, LocalPathInput, truncate

#: Author-attribution tags worth an INFO finding.
_AUTHOR_TAGS = frozenset(
    {"Artist", "Author", "By-line", "Creator", "Credit", "OwnerName", "Writer-Editor"}
)

#: Tool-fingerprint tags worth an INFO finding.
_SOFTWARE_TAGS = frozenset(
    {"CreatorTool", "Encoder", "Generator", "Producer", "Software", "SourceApplication"}
)


class ExiftoolArgs(LocalPathInput):
    """Validated exiftool invocation arguments (local path only)."""

    recursive: bool = False
    max_findings: int = Field(default=50, ge=1, le=500)


class ExiftoolTool(BaseTool):
    name = "exiftool"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = "exiftool"
    description = (
        "File metadata extraction: GPS coordinates, author attribution "
        "and producing-tool fingerprints from local files."
    )
    input_model = ExiftoolArgs

    def build_argv(self, args: ExiftoolArgs, out_file: str | None = None) -> list[str]:
        argv = ["exiftool", "-j", "-s"]
        if args.recursive:
            argv.append("-r")
        argv.append(args.target)
        return argv

    def parse(self, args: ExiftoolArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for entry in _load_entries(output):
            source = str(entry.get("SourceFile") or args.target)
            gps = {key: entry[key] for key in entry if key.startswith("GPS")}
            if any(key in gps for key in ("GPSLatitude", "GPSLongitude", "GPSPosition")):
                findings.append(
                    self.finding(
                        title=f"GPS coordinates embedded in {source}",
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        target=args.target,
                        endpoint=source,
                        evidence=truncate(f"exiftool {_format_tags(gps)}"),
                        remediation="Strip location tags before publishing the file.",
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings
            authors = {key: entry[key] for key in entry if key in _AUTHOR_TAGS}
            if authors:
                findings.append(
                    self.finding(
                        title=f"Author metadata in {source}",
                        severity=Severity.INFO,
                        confidence=0.8,
                        target=args.target,
                        endpoint=source,
                        evidence=truncate(f"exiftool {_format_tags(authors)}"),
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings
            software = {key: entry[key] for key in entry if key in _SOFTWARE_TAGS}
            if software:
                findings.append(
                    self.finding(
                        title=f"Producing tool fingerprinted: {source}",
                        severity=Severity.INFO,
                        confidence=0.75,
                        target=args.target,
                        endpoint=source,
                        evidence=truncate(f"exiftool {_format_tags(software)}"),
                    )
                )
                if len(findings) >= args.max_findings:
                    return findings
        return findings

    def observations(self, args: ExiftoolArgs, output: str) -> list[str]:
        entries = _load_entries(output)
        tags = sum(len(entry) for entry in entries)
        return [f"exiftool: {len(entries)} file(s), {tags} tag(s)"]


def _load_entries(output: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(output.strip())
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(document, list):
        return []
    return [item for item in document if isinstance(item, dict)]


def _format_tags(tags: dict[str, Any]) -> str:
    parts = []
    for key in sorted(tags):
        value = tags[key]
        if isinstance(value, list):
            value = ",".join(str(item) for item in value)
        parts.append(f"{key}={value}")
    return " ".join(parts)


__all__ = ["ExiftoolArgs", "ExiftoolTool"]
