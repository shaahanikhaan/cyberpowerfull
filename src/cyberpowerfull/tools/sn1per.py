"""Sn1per wrapper: drive the Sn1per community/paid scanner and read its loot.

Sn1per writes its results into a workspace directory
(``/usr/share/sniper/loot/<workspace>`` or ``./loot/<workspace>``). This wrapper
launches the real binary, then parses the real loot files it produced. Nothing is
synthesised: if the workspace directory stays empty, no findings are reported.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from cyberpowerfull.models import Capability, Finding, Phase
from cyberpowerfull.tools.base import BaseTool, HostInput, severity_from_text, truncate
from cyberpowerfull.tools.extract import extract_report_findings

_MODES = ("normal", "stealth", "recon", "web", "webscan", "fullportonly", "port")
_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_LOOT_SUFFIXES = (".txt", ".csv", ".json")
_MAX_FILE_BYTES = 512_000
_MAX_FILES = 40


class Sn1perArgs(HostInput):
    """Validated Sn1per invocation arguments."""

    mode: Literal[_MODES] = "normal"  # type: ignore[valid-type]
    workspace: str | None = Field(default=None, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    loot_dir: str | None = Field(default=None, max_length=300)

    @field_validator("workspace")
    @classmethod
    def _check_workspace(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _WORKSPACE_RE.match(value) or value in {".", ".."}:
            raise ValueError("workspace must be a plain directory name")
        return value


class Sn1perTool(BaseTool):
    name = "sn1per"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "sniper"
    binary_alternatives = ("sn1per",)
    external = True
    required_capability = Capability.EXTERNAL_AGENTS
    success_codes = (0,)
    timeout_s = 3600
    description = (
        "Runs the Sn1per automated recon/vulnerability suite against one target and "
        "parses the loot workspace it writes. Requires the 'external_agents' capability."
    )
    input_model = Sn1perArgs

    def build_argv(self, args: Sn1perArgs, out_file: str | None = None) -> list[str]:
        argv = ["sniper", "-t", args.target, "-m", args.mode]
        if args.workspace:
            argv.extend(["-w", args.workspace])
        if args.port:
            argv.extend(["-p", str(args.port)])
        if args.loot_dir:
            argv.extend(["-o", args.loot_dir])
        return argv

    # -- loot discovery ----------------------------------------------------
    def _workspace(self, args: Sn1perArgs) -> str:
        return args.workspace or re.sub(r"[^A-Za-z0-9_.\-]", "_", args.target)

    def loot_roots(self, args: Sn1perArgs) -> list[Path]:
        workspace = self._workspace(args)
        candidates: list[str] = []
        if args.loot_dir:
            candidates.append(args.loot_dir)
        env = os.environ.get("SNIPER_LOOT_DIR")
        if env:
            candidates.append(env)
        candidates.extend(
            [
                "/usr/share/sniper/loot",
                str(Path.home() / "loot"),
                str(Path.cwd() / "loot"),
            ]
        )
        roots: list[Path] = []
        for candidate in candidates:
            path = Path(candidate).expanduser()
            workspace_path = path / workspace
            try:
                if workspace_path.is_dir():
                    roots.append(workspace_path)
                elif path.is_dir() and any(path.glob("*.txt")):
                    roots.append(path)
            except OSError:
                continue
        return roots

    def parse(self, args: Sn1perArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        # 1) live console output
        findings.extend(
            extract_report_findings(
                output, tool=self.name, target=args.target, skill=self.skill, phase=self.phase
            )
        )
        # 2) real loot files written by the suite
        for root in self.loot_roots(args):
            files = sorted(
                path
                for path in root.rglob("*")
                if path.is_file() and path.suffix.lower() in _LOOT_SUFFIXES
            )[:_MAX_FILES]
            for path in files:
                try:
                    if path.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                findings.extend(
                    extract_report_findings(
                        text,
                        tool=self.name,
                        target=args.target,
                        skill=self.skill,
                        phase=self.phase,
                    )
                )
                findings.extend(self._parse_loot_text(text, args, path))
        return findings

    def _parse_loot_text(self, text: str, args: Sn1perArgs, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        lowered_path = str(path).lower()
        if not any(token in lowered_path for token in ("vuln", "finding", "exploit")):
            return findings
        for line in text.splitlines():
            line = line.strip(" \t[]+*-")
            if len(line) < 12 or line.lower().startswith(("http/", "scan", "target")):
                continue
            findings.append(
                self.finding(
                    title=truncate(line, 220),
                    severity=severity_from_text(line),
                    confidence=0.6,
                    target=args.target,
                    endpoint=None,
                    evidence=truncate(f"sn1per loot file {path}: {line}"),
                )
            )
            if len(findings) >= 40:
                break
        return findings

    def observations(self, args: Sn1perArgs, output: str) -> list[str]:
        roots = self.loot_roots(args)
        notes = [f"sn1per mode={args.mode} workspace={self._workspace(args)}"]
        if roots:
            notes.append(f"sn1per loot roots: {', '.join(str(root) for root in roots)}")
        else:
            notes.append("sn1per: no loot workspace found after the run")
        return notes


__all__ = ["Sn1perArgs", "Sn1perTool"]
