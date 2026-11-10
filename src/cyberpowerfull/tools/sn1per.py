"""Sn1per wrapper: drive the Sn1per suite and read the loot it actually wrote.

Behaviour is verified against Sn1per Community Edition v9.2 (``1N3/Sn1per``):
modes dispatch in ``modes/*.sh`` on ``-m``, ``-o`` is a boolean OSINT switch
(not an output directory), ``-re`` enables recon stages, ``-fp`` enables the
full port scan, and loot lands in ``/usr/share/sniper/loot/<target>/`` — or
``/usr/share/sniper/loot/workspace/<workspace>/`` when ``-w`` is given. The
``-b`` brute-force switch is deliberately never passed: credential testing
without the ``credential_testing`` capability would bypass the capability gate.

Loot parsing reads the real files sniper wrote (the console tee in ``output/``,
the vulnerability report, the notification log, and the nmap XML). Nothing is
synthesised: if the loot directory stays empty, no findings are reported.
"""

from __future__ import annotations

import csv
import dataclasses
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.models import Capability, Finding, Phase, Severity
from cyberpowerfull.tools.base import (
    BaseTool,
    HostInput,
    ToolInput,
    ToolStatus,
    host_port,
    severity_from_text,
    truncate,
)
from cyberpowerfull.tools.extract import extract_report_findings, merge_findings

#: Single-target modes verified in modes/*.sh (``if [[ "$MODE" = "<mode>" ]]``).
#: Mass modes (airstrike, nuke, flyover, mass*) need ``-f targets.txt`` and are
#: out of scope for a single-target typed tool.
_MODES = (
    "normal",
    "stealth",
    "discover",
    "port",
    "web",
    "webporthttp",
    "webporthttps",
    "webscan",
    "fullportonly",
    "vulnscan",
)
_PORT_REQUIRED_MODES = frozenset({"webporthttp", "webporthttps"})
_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_LOOT_SUFFIXES = (".txt", ".csv", ".json")
_MAX_FILE_BYTES = 512_000
_MAX_FILES = 40
_ROOT_HINT = "This script must be run as root"


class Sn1perArgs(HostInput):
    """Validated Sn1per invocation arguments."""

    mode: Literal[_MODES] = "normal"  # type: ignore[valid-type]
    workspace: str | None = Field(default=None, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    osint: bool = False
    recon: bool = False
    fullportscan: bool = False
    loot_dir: str | None = Field(default=None, max_length=300)

    @field_validator("workspace")
    @classmethod
    def _check_workspace(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _WORKSPACE_RE.match(value) or value in {".", ".."}:
            raise ValueError("workspace must be a plain directory name")
        return value

    @model_validator(mode="after")
    def _check_port_modes(self) -> Sn1perArgs:
        if self.mode in _PORT_REQUIRED_MODES and self.port is None:
            raise ValueError(
                f"mode {self.mode!r} requires a port (sniper -m {self.mode} -p <port>)"
            )
        return self


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
        "parses the loot it writes. Requires the 'external_agents' capability and a "
        "root shell (sniper refuses to run otherwise). Brute-forcing stays off."
    )
    input_model = Sn1perArgs

    def build_argv(self, args: Sn1perArgs, out_file: str | None = None) -> list[str]:
        argv = ["sniper", "-t", args.target, "-m", args.mode]
        if args.workspace:
            argv.extend(["-w", args.workspace])
        if args.port:
            argv.extend(["-p", str(args.port)])
        if args.osint:
            argv.append("-o")
        if args.recon:
            argv.append("-re")
        if args.fullportscan:
            argv.append("-fp")
        # loot_dir is parse-only: sniper's loot location is fixed by the suite.
        return argv

    def _execute(self, args: ToolInput, argv: list[str], policy: ToolPolicy):
        result = super()._execute(args, argv, policy)
        if result.status is ToolStatus.OK:
            return result
        if _ROOT_HINT in result.stdout or _ROOT_HINT in result.stderr:
            return dataclasses.replace(
                result,
                error=(
                    "sniper refused to run: it must be started as root "
                    "(re-run the engagement with sudo / as root)"
                ),
            )
        return result

    # -- loot discovery ----------------------------------------------------
    def loot_targets(self, args: Sn1perArgs) -> list[str]:
        """Directory names sniper would use for this invocation, in order."""
        names: list[str] = []
        target_dir = re.sub(r"^https?://", "", args.target).rstrip("/")
        if args.workspace:
            names.append(f"workspace/{args.workspace}")
        names.append(target_dir)
        return names

    def loot_roots(self, args: Sn1perArgs) -> list[Path]:
        candidates: list[str] = []
        if args.loot_dir:
            return self._existing_dirs([args.loot_dir])
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
            base = Path(candidate).expanduser()
            for name in self.loot_targets(args):
                roots.extend(self._existing_dirs([str(base / name)]))
            try:
                if base.is_dir() and any(base.glob("*.txt")):
                    roots.append(base)
            except OSError:
                continue
        return roots

    @staticmethod
    def _existing_dirs(candidates: list[str]) -> list[Path]:
        roots: list[Path] = []
        for candidate in candidates:
            path = Path(candidate).expanduser()
            try:
                if path.is_dir():
                    roots.append(path)
            except OSError:
                continue
        return roots

    def loot_files(self, args: Sn1perArgs) -> list[Path]:
        files: list[Path] = []
        for root in self.loot_roots(args):
            try:
                found = sorted(
                    path
                    for path in root.rglob("*")
                    if path.is_file() and path.suffix.lower() in _LOOT_SUFFIXES
                )
            except OSError:
                continue
            files.extend(found)

        # The vulnerability report and the console tee carry the most signal.
        def _priority(path: Path) -> tuple[int, str]:
            name = path.name.lower()
            if "vulnerability-report" in name or "notifications" in name:
                return (0, name)
            if path.parent.name == "output" and name.startswith("sniper-"):
                return (1, name)
            if path.suffix.lower() == ".xml":
                return (2, name)
            return (3, name)

        try:
            xml_files = [
                path
                for root in self.loot_roots(args)
                for path in root.rglob("nmap-*.xml")
                if path.is_file()
            ]
        except OSError:
            xml_files = []
        files.extend(xml_files)
        files.sort(key=_priority)
        return files[:_MAX_FILES]

    # -- parsing -----------------------------------------------------------
    def parse(self, args: Sn1perArgs, output: str, out_file: str | None = None) -> list[Finding]:
        groups: list[list[Finding]] = [
            extract_report_findings(
                output, tool=self.name, target=args.target, skill=self.skill, phase=self.phase
            )
        ]
        for path in self.loot_files(args):
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                if path.suffix.lower() == ".xml":
                    text = path.read_bytes()[:_MAX_FILE_BYTES].decode("utf-8", errors="replace")
                    groups.append(self._parse_nmap_xml(text, args, path))
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Loot-aware lines first: merge_findings keeps the first occurrence, and
            # the loot-file evidence (with its source path) beats the generic one.
            groups.append(self._parse_loot_text(text, args, path))
            groups.append(
                extract_report_findings(
                    text,
                    tool=self.name,
                    target=args.target,
                    skill=self.skill,
                    phase=self.phase,
                )
            )
        return merge_findings(*groups)

    def _parse_nmap_xml(self, text: str, args: Sn1perArgs, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return findings
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            findings.append(
                self.finding(
                    title=f"Open {protocol} port {port_id} ({service_name}, via sn1per nmap)",
                    severity=Severity.INFO,
                    confidence=0.9,
                    target=args.target,
                    endpoint=host_port(args.target, port_id),
                    evidence=truncate(f"sn1per loot file {path}: open {port_id}/{protocol}", 400),
                )
            )
            if len(findings) >= 60:
                break
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

    def host_table_rows(self, args: Sn1perArgs) -> int:
        """Count data rows in the workspace host-table report, if present."""
        rows = 0
        for root in self.loot_roots(args):
            report = root / "reports" / "host-table-report.csv"
            try:
                if not report.is_file():
                    continue
                with report.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                    reader = csv.reader(handle)
                    rows += sum(
                        1 for row in reader if row and not row[0].lower().startswith("host")
                    )
            except OSError:
                continue
        return rows

    def observations(self, args: Sn1perArgs, output: str) -> list[str]:
        roots = self.loot_roots(args)
        notes = [f"sn1per mode={args.mode} loot_names={','.join(self.loot_targets(args))}"]
        if _ROOT_HINT in output:
            notes.append("sn1per refused to run without root; no loot was written")
        if roots:
            notes.append(f"sn1per loot roots: {', '.join(str(root) for root in roots)}")
            notes.append(f"sn1per loot files considered: {len(self.loot_files(args))}")
            table_rows = self.host_table_rows(args)
            if table_rows:
                notes.append(f"sn1per host-table-report.csv rows: {table_rows}")
        else:
            notes.append("sn1per: no loot workspace found after the run")
        return notes


__all__ = ["Sn1perArgs", "Sn1perTool"]
