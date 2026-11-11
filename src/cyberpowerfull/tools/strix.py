"""Strix wrapper: headless run of the open-source Strix agent.

Verified against usestrix/strix v1.7.1 (``strix/interface/cli_args.py``,
``strix/interface/{main,environment}.py``, ``strix/report/{writer,state}.py``,
``strix/core/paths.py``, ``strix/config/settings.py``):

* headless runs use ``-n``; findings make strix exit **2** (``--fail-on``
  threshold, default: any finding), errors exit **1**, clean runs exit 0;
* each run writes ``./strix_runs/<run-name>/`` with ``run.json`` (run record),
  ``vulnerabilities.json`` (structured finding records), ``vulnerabilities.csv``,
  ``penetration_test_report.md``, and one ``vulnerabilities/<id>.md`` per finding;
* the model and key come from ``STRIX_LLM`` plus ``LLM_API_KEY`` (or
  ``OPENAI_API_KEY``), and the sandbox defaults to Docker
  (``STRIX_RUNTIME_BACKEND``).

This wrapper launches the real CLI with an explicit budget and turn cap,
injects the engagement scope into ``--instruction``, and parses the newest run
directory's ``vulnerabilities.json`` first — console prose is only a fallback.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.models import Capability, Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, ToolInput, ToolStatus, UrlInput, truncate
from cyberpowerfull.tools.extract import extract_report_findings, merge_findings

_RUN_DIR_NAMES = ("strix_runs", "agent_runs", ".strix_runs")
_REPORT_SUFFIXES = (".md", ".sarif")
_MAX_REPORT_BYTES = 1_500_000
_MAX_STRUCTURED = 80

_CONFIDENCE = {"high": 0.9, "medium": 0.7, "low": 0.5}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d{1,4}", re.IGNORECASE)


class StrixArgs(UrlInput):
    """Validated Strix invocation arguments."""

    scan_mode: Literal["quick", "standard", "deep"] = "quick"
    max_budget_usd: float = Field(default=5.0, gt=0, le=200)
    max_turns: int = Field(default=120, ge=10, le=1000)
    fail_on: Literal["critical", "high", "medium", "low", "info"] | None = None
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
    # Model credentials are useless unless they reach the sandbox subprocess.
    env_passthrough = ("STRIX_LLM", "LLM_API_KEY", "OPENAI_API_KEY")
    external = True
    required_capability = Capability.EXTERNAL_AGENTS
    # Verified: 0 = clean run, 2 = findings at/above --fail-on, 1 = error.
    success_codes = (0, 2)
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
        if args.fail_on:
            argv.extend(["--fail-on", args.fail_on])
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

    def _execute(self, args: ToolInput, argv: list[str], policy: ToolPolicy):
        result = super()._execute(args, argv, policy)
        combined = f"{result.stdout}\n{result.stderr}"
        if "DOCKER NOT INSTALLED" in combined:
            return dataclasses.replace(
                result,
                status=ToolStatus.ERROR,
                error=(
                    "strix needs the docker CLI on PATH (it runs the sandbox in "
                    "Docker); install Docker and re-run"
                ),
            )
        if "MISSING REQUIRED ENVIRONMENT VARIABLES" in combined:
            return dataclasses.replace(
                result,
                status=ToolStatus.ERROR,
                error=(
                    "strix needs STRIX_LLM (model name, e.g. "
                    "'openrouter/z-ai/glm-5.3') and usually LLM_API_KEY in the "
                    "environment; export them and re-run"
                ),
            )
        if result.status is not ToolStatus.OK and (
            "model_connection_failed" in combined or "ModelConnectionError" in combined
        ):
            return dataclasses.replace(
                result,
                error="strix could not reach its model (check STRIX_LLM/LLM_API_KEY)",
            )
        return result

    # -- run discovery -----------------------------------------------------
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

    @staticmethod
    def latest_run_dir(root: Path) -> Path | None:
        """Newest run under a runs root, mirroring strix's own picker.

        A run directory is a child holding ``run.json``; the newest ``run.json``
        mtime wins (it is rewritten on status changes, so a live run sorts to
        the top). Without any ``run.json``, fall back to the newest child dir.
        """
        try:
            children = [child for child in root.iterdir() if child.is_dir()]
        except OSError:
            return None
        with_record = [child for child in children if (child / "run.json").is_file()]
        pool = with_record or children
        if not pool:
            return None

        def _activity(child: Path) -> float:
            try:
                record = child / "run.json"
                stamp = record.stat().st_mtime if record.is_file() else child.stat().st_mtime
            except OSError:
                return 0.0
            return stamp

        return max(pool, key=_activity)

    def read_run_record(self, run_dir: Path) -> dict[str, Any]:
        try:
            payload = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    # -- parsing -----------------------------------------------------------
    def parse(self, args: StrixArgs, output: str, out_file: str | None = None) -> list[Finding]:
        groups: list[list[Finding]] = [
            extract_report_findings(
                output, tool=self.name, target=args.target, skill=self.skill, phase=self.phase
            )
        ]
        for root in self.run_dirs():
            run_dir = self.latest_run_dir(root)
            if run_dir is None:
                continue
            groups.append(self._parse_vulnerabilities_json(args, run_dir))
            groups.append(self._parse_run_markdown(args, run_dir))
        return merge_findings(*groups)

    def _parse_vulnerabilities_json(self, args: StrixArgs, run_dir: Path) -> list[Finding]:
        try:
            payload = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(payload, list):
            return []
        findings: list[Finding] = []
        for record in payload[:_MAX_STRUCTURED]:
            if not isinstance(record, dict):
                continue
            title = str(record.get("title") or "Strix finding").strip()[:220]
            if len(title) < 3:
                continue
            severity = Severity.coerce(str(record.get("severity") or "info"))
            confidence = _CONFIDENCE.get(str(record.get("confidence") or "").lower(), 0.65)
            endpoint = record.get("endpoint") or record.get("target")
            evidence_parts = [
                str(record.get("description") or "").strip(),
                str(record.get("impact") or "").strip(),
                str(record.get("technical_analysis") or "").strip(),
                str(record.get("poc_description") or "").strip(),
                str(record.get("evidence") or "").strip(),
                str(record.get("confidence_rationale") or "").strip(),
            ]
            method = str(record.get("method") or "").strip()
            if method:
                evidence_parts.append(f"method={method}")
            evidence = " ".join(part for part in evidence_parts if part)
            cve_match = _CVE_RE.search(json.dumps(record.get("cve") or ""))
            cwe_match = _CWE_RE.search(json.dumps(record.get("cwe") or ""))
            try:
                cvss = float(record["cvss"]) if record.get("cvss") is not None else None
                if cvss is not None and not 0 <= cvss <= 10:
                    cvss = None
            except (TypeError, ValueError):
                cvss = None
            findings.append(
                self.finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=args.target,
                    endpoint=str(endpoint).strip() if endpoint else None,
                    evidence=truncate(evidence or title, 2000),
                    cwe=cwe_match.group(0).upper() if cwe_match else None,
                    cve=cve_match.group(0).upper() if cve_match else None,
                    cvss=cvss,
                    remediation=truncate(str(record.get("remediation_steps") or "").strip(), 1000)
                    or None,
                    verified=severity.rank >= Severity.HIGH.rank,
                )
            )
        return findings

    def _parse_run_markdown(self, args: StrixArgs, run_dir: Path) -> list[Finding]:
        try:
            candidates = sorted(
                (path for path in run_dir.rglob("*") if path.is_file()),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return []
        findings: list[Finding] = []
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
            if len(findings) >= _MAX_STRUCTURED:
                break
        return findings

    def observations(self, args: StrixArgs, output: str) -> list[str]:
        notes = [
            f"strix scan_mode={args.scan_mode} budget=${args.max_budget_usd:g} "
            f"turns<={args.max_turns}"
        ]
        dirs = self.run_dirs()
        if not dirs:
            notes.append("strix: no run directory found (report may be on stdout only)")
            return notes
        notes.append(f"strix run directories: {', '.join(str(path) for path in dirs)}")
        for root in dirs:
            run_dir = self.latest_run_dir(root)
            if run_dir is None:
                continue
            notes.append(f"strix latest run: {run_dir}")
            record = self.read_run_record(run_dir)
            summary = _summarise_run_record(record)
            if summary:
                notes.append(f"strix run.json: {summary}")
        if "model_connection_failed" in output or "ModelConnectionError" in output:
            notes.append("strix could not reach its model (check STRIX_LLM/LLM_API_KEY)")
        return notes


def _summarise_run_record(record: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("status", "state", "stop_reason", "cost_usd", "total_cost", "turns", "target"):
        value = record.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            parts.append(f"{key}={truncate(str(value).strip(), 60)}")
    return " ".join(parts)


def default_instruction(scope_block: str) -> str:
    """Build a compact scope statement for ``--instruction``."""
    compact = re.sub(r"\s+", "; ", scope_block.strip())
    return truncate(compact, 500)


__all__ = ["StrixArgs", "StrixTool", "default_instruction"]
