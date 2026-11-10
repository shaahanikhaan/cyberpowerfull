"""Strix wrapper: headless run of the open-source Strix agent.

Strix (`pipx install strix-agent`, https://github.com/usestrix/strix) accepts a
target, runs headless with ``-n``, and writes a per-run report under
``strix_runs/<run-name>``. This wrapper:

* launches the real CLI with an explicit budget and turn cap;
* injects the engagement scope into ``--instruction`` so the sub-agent cannot be
  talked outside it;
* parses the console output and the run directory that was actually written.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from cyberpowerfull.models import Capability, Finding, Phase
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate
from cyberpowerfull.tools.extract import extract_report_findings

_RUN_DIR_NAMES = ("strix_runs", "agent_runs", ".strix_runs")
_REPORT_SUFFIXES = (".md", ".json", ".sarif")
_MAX_REPORT_BYTES = 1_500_000
_MAX_REPORTS = 25


class StrixArgs(UrlInput):
    """Validated Strix invocation arguments."""

    scan_mode: Literal["quick", "standard", "deep"] = "quick"
    max_budget_usd: float = Field(default=5.0, gt=0, le=200)
    max_turns: int = Field(default=120, ge=10, le=1000)
    instruction: str | None = Field(default=None, max_length=600)

    @field_validator("instruction")
    @classmethod
    def _single_line(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = " ".join(value.split())
        return cleaned[:600]


class StrixTool(BaseTool):
    name = "strix"
    phase = Phase.VALIDATION
    skill = "external_validation"
    binary = "strix"
    binary_alternatives = ("strix-agent",)
    external = True
    required_capability = Capability.EXTERNAL_AGENTS
    success_codes = (0, 1)  # strix exits non-zero when it finds vulnerabilities
    timeout_s = 3600
    description = (
        "Delegates to the Strix autonomous agent in headless mode with a hard budget "
        "and the engagement scope embedded in the instruction. Requires the "
        "'external_agents' capability, Docker, and STRIX_LLM/LLM_API_KEY on the host."
    )
    input_model = StrixArgs

    def build_argv(self, args: StrixArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "strix",
            "-n",
            "-t",
            args.target,
            "--scan-mode",
            args.scan_mode,
            "--max-budget",
            f"{args.max_budget_usd:g}",
            "--max-turns",
            str(args.max_turns),
        ]
        instruction = args.instruction or ""
        argv.extend(
            [
                "--instruction",
                (
                    "Authorized engagement. Test only this target and assets explicitly "
                    "listed in the scope below. Do not use out-of-band cloud callbacks, "
                    "persistence, lateral movement, or data extraction."
                    + (f" {instruction}" if instruction else "")
                ),
            ]
        )
        return argv

    def run_dirs(self) -> list[Path]:
        roots: list[str] = []
        env = os.environ.get("STRIX_RUNS_DIR")
        if env:
            roots.append(env)
        roots.extend(str(Path.cwd() / name) for name in _RUN_DIR_NAMES)
        dirs: list[Path] = []
        for root in roots:
            path = Path(root).expanduser()
            try:
                if path.is_dir():
                    dirs.append(path)
            except OSError:
                continue
        return dirs

    def parse(self, args: StrixArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings = extract_report_findings(
            output, tool=self.name, target=args.target, skill=self.skill, phase=self.phase
        )
        for root in self.run_dirs():
            candidates: list[Path] = []
            try:
                candidates = sorted(
                    (path for path in root.rglob("*") if path.is_file()),
                    key=lambda path: path.stat().st_mtime,
                    reverse=True,
                )
            except OSError:
                continue
            for path in candidates:
                if path.suffix.lower() not in _REPORT_SUFFIXES:
                    continue
                try:
                    if path.stat().st_size > _MAX_REPORT_BYTES:
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
                if len(findings) >= 80:
                    break
            if len(findings) >= 80:
                break
        return findings

    def observations(self, args: StrixArgs, output: str) -> list[str]:
        notes = [
            f"strix scan_mode={args.scan_mode} budget=${args.max_budget_usd:g} "
            f"turns<={args.max_turns}"
        ]
        dirs = self.run_dirs()
        if dirs:
            notes.append(f"strix run directories: {', '.join(str(path) for path in dirs)}")
        else:
            notes.append("strix: no run directory found (report may be on stdout only)")
        return notes


def default_instruction(scope_block: str) -> str:
    """Build a compact scope statement for ``--instruction``."""
    compact = re.sub(r"\s+", "; ", scope_block.strip())
    return truncate(compact, 500)


__all__ = ["StrixArgs", "StrixTool", "default_instruction"]
