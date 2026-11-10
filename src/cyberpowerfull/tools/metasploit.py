"""Metasploit wrapper: proof-oriented auxiliary scanning through msfconsole.

There was no Metasploit adapter at all (only inventory detection); this module
drives the real ``msfconsole`` binary non-interactively::

    msfconsole -q -x "use <module>; set RHOSTS <target>; ...; run; exit -y"

The ``-q`` / ``-x`` flags are verified against the upstream option parser
(``Metasploit::Framework::ParsedOptions::Console``), and every module on the
allowlist was verified to exist upstream with the options this wrapper sets.
``RHOSTS`` is always the single validated target, and the module list is a
closed allowlist of ``auxiliary/scanner/*`` modules: version/banner grabs,
anonymous-access checks, and detection-only vulnerability checks whose default
action sends no denial-of-service traffic (BlueKeep's ``Crash`` action is never
selected). Exploit, payload, post, and brute-force-login modules cannot reach
the command line. Console output (``[+]`` / ``[*]`` lines) is parsed per module
into findings; anything msfconsole reports as an error stays an observation.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Literal

from pydantic import Field, model_validator

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.models import Capability, Finding, Phase, Severity
from cyberpowerfull.tools.base import (
    BaseTool,
    HostInput,
    ToolInput,
    ToolStatus,
    host_port,
    truncate,
)

# Short name -> full module path. Every entry was verified against
# rapid7/metasploit-framework (modules/auxiliary/scanner/...).
_MODULES = {
    "tcp_scan": "auxiliary/scanner/portscan/tcp",
    "http_version": "auxiliary/scanner/http/http_version",
    "http_title": "auxiliary/scanner/http/title",
    "robots_txt": "auxiliary/scanner/http/robots_txt",
    "ftp_version": "auxiliary/scanner/ftp/ftp_version",
    "ssh_version": "auxiliary/scanner/ssh/ssh_version",
    "smb_version": "auxiliary/scanner/smb/smb_version",
    "vnc_none_auth": "auxiliary/scanner/vnc/vnc_none_auth",
    "mssql_ping": "auxiliary/scanner/mssql/mssql_ping",
    "bluekeep": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
    "ms17_010": "auxiliary/scanner/smb/smb_ms17_010",
}
_MODULE_NAMES = tuple(_MODULES)

_PORTS_RE = re.compile(r"^[0-9,\- ]{1,64}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9_.\-/]{0,120}$")
_HTTP_MODULES = frozenset({"http_version", "http_title", "robots_txt"})
_RPORT_MODULES = frozenset(_MODULE_NAMES) - {"tcp_scan"}
_MAX_PORT_FINDINGS = 300

_TCP_OPEN_RE = re.compile(r"^\[\+\]\s*(\S+):(\d+)\s+-\s+TCP OPEN\s*$")
_HTTP_VERSION_RE = re.compile(r"^\[\+\]\s*(\S+):(\d+)\s+(.+?)\s*$")
_HTTP_TITLE_RE = re.compile(
    r"^\[\+\]\s*\[(\S+):(\d+)\]\s+\[C:(\d+)\]\s+\[R:(.*?)\]\s+\[S:(.*?)\]\s*(.*)$"
)
_ROBOTS_MARKER = "Contents of Robots.txt:"
_ROBOTS_ENTRY_RE = re.compile(r"^\s*(Disallow|Allow|Sitemap)\s*:\s*(\S+)", re.IGNORECASE)
_FTP_BANNER_RE = re.compile(r"^\[\+\]\s*FTP Banner:\s*(.+?)\s*$")
_SSH_VERSION_RE = re.compile(r"^\[\*\]\s*(\S+)\s+-\s+SSH server version:\s*(.+?)\s*$")
_SSH_FINGERPRINT_RE = re.compile(r"^\[\*\]\s*(\S+)\s+-\s+Key Fingerprint:\s*(.+?)\s*$")
_SMB_DETECTED_RE = re.compile(r"^\[\*\]\s*(?:\S+\s+-\s+)?(SMB Detected .+?)\s*$")
_SMB_OS_RE = re.compile(r"^\[\+\]\s*(?:\S+\s+-\s+)?Host is running (.+?)\s*$")
_SMB_SIGNING_RE = re.compile(r"SMB signing is not required")
_VNC_OPEN_RE = re.compile(r"^\[\+\]\s*(\S+):(\d+)\s+-\s+VNC server (.+)$")
_MSSQL_HEADER_RE = re.compile(r"^\[\*\]\s*SQL Server information for (\S+):\s*$")
_MSSQL_PAIR_RE = re.compile(r"^\[\+\]\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$")
_BLUEKEEP_RE = re.compile(
    r"^\[\+\]\s*(The target (attempted cleanup of the incorrectly-bound"
    r" MS_T120 channel|appears to have been crashed by disconnecting"
    r" from an incorrectly-bound MS_T120 channel)\.?)\s*$"
)
_MS17_010_RE = re.compile(r"^\[\+\]\s*Host is likely VULNERABLE to MS17-010!\s*-\s*(.+?)\s*$")
_MS17_PIPE_RE = re.compile(r"^\[\+\]\s*Named pipe found:\s*(.+?)\s*$")
_GENERIC_GOOD_RE = re.compile(r"^\[\+\]\s*(.+?)\s*$")

_BOOT_FAILURE_MARKERS = (
    "Failed to load module",
    "Invalid module",
    "No such file or directory",
    "cannot load such file",
    "Could not find",
    "Bundler Error",
    "Traceback (most recent call last)",
    "msfconsole: command not found",
)


class MetasploitArgs(HostInput):
    """Validated Metasploit auxiliary-scanner invocation arguments."""

    module: Literal[_MODULE_NAMES] = "tcp_scan"  # type: ignore[valid-type]
    ports: str = Field(default="1-1024", min_length=1, max_length=64)
    rport: int | None = Field(default=None, ge=1, le=65535)
    threads: int = Field(default=4, ge=1, le=16)
    ssl: bool = False
    path: str = Field(default="/", min_length=1, max_length=128)

    @model_validator(mode="after")
    def _check_option_scope(self) -> MetasploitArgs:
        if not _PORTS_RE.match(self.ports) or not any(ch.isdigit() for ch in self.ports):
            raise ValueError("ports must be digits, commas, and dashes (e.g. '80,443' or '1-1024')")
        if not _PATH_RE.match(self.path):
            raise ValueError("path must start with '/' and contain no spaces or quotes")
        if self.module != "tcp_scan" and self.ports != "1-1024":
            raise ValueError("ports only applies to the tcp_scan module")
        if self.module == "tcp_scan" and self.rport is not None:
            raise ValueError("rport does not apply to the tcp_scan module")
        if self.ssl and self.module not in _HTTP_MODULES:
            raise ValueError(
                "ssl only applies to the http_version, http_title, and robots_txt modules"
            )
        if self.path != "/" and self.module not in {"http_title", "robots_txt"}:
            raise ValueError("path only applies to the http_title and robots_txt modules")
        return self


class MetasploitTool(BaseTool):
    name = "metasploit"
    phase = Phase.SCANNING
    skill = "network_services"
    binary = "msfconsole"
    required_capability = Capability.AGGRESSIVE
    success_codes = (0,)
    timeout_s = 900  # framework boot alone can take half a minute on first run
    description = (
        "Runs one allowlisted Metasploit auxiliary scanner (TCP connect scan, service "
        "version grabs, anonymous-access checks, BlueKeep/MS17-010 detection) against a "
        "single host via 'msfconsole -q -x'. Requires the 'aggressive' capability; no "
        "exploit, payload, or brute-force module can run through this tool."
    )
    input_model = MetasploitArgs

    # -- command construction ---------------------------------------------
    def module_path(self, module: str) -> str:
        return _MODULES[module]

    def build_argv(self, args: MetasploitArgs, out_file: str | None = None) -> list[str]:
        commands = [f"use {self.module_path(args.module)}", f"set RHOSTS {args.target}"]
        if args.module == "tcp_scan":
            commands.append(f"set PORTS {args.ports.replace(' ', '')}")
            commands.append(f"set CONCURRENCY {args.threads}")
        else:
            commands.append(f"set THREADS {args.threads}")
        if args.rport is not None:
            commands.append(f"set RPORT {args.rport}")
        if args.ssl:
            commands.append("set SSL true")
        if args.path != "/":
            option = "TARGETURI" if args.module == "http_title" else "PATH"
            commands.append(f"set {option} {args.path}")
        commands.extend(["run", "exit -y"])
        return ["msfconsole", "-q", "-x", "; ".join(commands)]

    def _execute(self, args: ToolInput, argv: list[str], policy: ToolPolicy):
        result = super()._execute(args, argv, policy)
        if result.status is ToolStatus.OK:
            return result
        haystack = f"{result.stdout}\n{result.stderr}"
        if any(marker in haystack for marker in _BOOT_FAILURE_MARKERS):
            detail = next(m for m in _BOOT_FAILURE_MARKERS if m in haystack)
            return dataclasses.replace(
                result,
                error=(
                    f"msfconsole failed to start or load the module ({detail}); on Kali: "
                    "'sudo apt install metasploit-framework' then 'msfdb init' (the database "
                    "is optional for scanners, but the install must be complete)"
                ),
            )
        return result

    # -- output handling ---------------------------------------------------
    def parse(
        self, args: MetasploitArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        lines = output.splitlines()
        handler = _PARSERS.get(args.module, _parse_generic)
        findings = handler(self, args, lines)
        return findings[: _MAX_PORT_FINDINGS + 20]

    def observations(self, args: MetasploitArgs, output: str) -> list[str]:
        goods = sum(1 for line in output.splitlines() if line.startswith("[+]"))
        notes = [f"metasploit module={self.module_path(args.module)} positive_lines={goods}"]
        if "Failed to connect to the database" in output or "db_connect" in output:
            notes.append("metasploit ran without its database (fine for scanners)")
        if goods == 0:
            notes.append("metasploit reported no positive lines for this module/target")
        return notes


def _endpoint(args: MetasploitArgs, host: str, port: str | int) -> str:
    try:
        return host_port(host, int(port))
    except (TypeError, ValueError):
        return host


def _parse_tcp_scan(tool: MetasploitTool, args: MetasploitArgs, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        match = _TCP_OPEN_RE.match(line.strip())
        if not match:
            continue
        host, port = match.group(1), match.group(2)
        findings.append(
            tool.finding(
                title=f"Open TCP port {port} (metasploit connect scan)",
                severity=Severity.INFO,
                confidence=0.95,
                target=args.target,
                endpoint=_endpoint(args, host, port),
                evidence=truncate(f"msf {tool.module_path('tcp_scan')}: {line.strip()}", 400),
            )
        )
        if len(findings) >= _MAX_PORT_FINDINGS:
            break
    return findings


def _parse_http_version(
    tool: MetasploitTool, args: MetasploitArgs, lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        match = _HTTP_VERSION_RE.match(line.strip())
        if not match:
            continue
        host, port, fingerprint = match.groups()
        findings.append(
            tool.finding(
                title=f"HTTP service fingerprint on {port}: {truncate(fingerprint, 120)}",
                severity=Severity.LOW,
                confidence=0.85,
                target=args.target,
                endpoint=_endpoint(args, host, port),
                evidence=truncate(f"msf http_version: {line.strip()}", 600),
                remediation="Suppress server version banners and patch the disclosed version.",
            )
        )
    return findings


def _parse_http_title(
    tool: MetasploitTool, args: MetasploitArgs, lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        match = _HTTP_TITLE_RE.match(line.strip())
        if not match:
            continue
        host, port, code, location, server, title = match.groups()
        title = title.strip() or "(empty title)"
        findings.append(
            tool.finding(
                title=f"Web page title on {port}: {truncate(title, 120)}",
                severity=Severity.LOW,
                confidence=0.8,
                target=args.target,
                endpoint=f"http://{host}:{port}{args.path}",
                evidence=truncate(
                    f"msf http_title: HTTP {code} server={server or '-'} "
                    f"redirect={location or '-'} title={title}",
                    600,
                ),
            )
        )
    return findings


def _parse_robots_txt(
    tool: MetasploitTool, args: MetasploitArgs, lines: list[str]
) -> list[Finding]:
    entries: list[str] = []
    in_body = False
    for raw in lines:
        line = raw.strip()
        if _ROBOTS_MARKER in line:
            in_body = True
            continue
        if in_body:
            if line.startswith("["):
                break
            match = _ROBOTS_ENTRY_RE.match(line)
            if match:
                entries.append(f"{match.group(1).title()}: {match.group(2)}")
    if not entries:
        return []
    robots_path = args.path.rstrip("/") + "/robots.txt"
    return [
        tool.finding(
            title=f"robots.txt discloses {len(entries)} path(s)",
            severity=Severity.LOW,
            confidence=0.9,
            target=args.target,
            endpoint=f"http://{args.target}{robots_path}",
            evidence=truncate("msf robots_txt: " + "; ".join(entries[:12]), 800),
            remediation="Review robots.txt entries; unlinked paths are still fetchable.",
        )
    ]


def _parse_ftp_version(
    tool: MetasploitTool, args: MetasploitArgs, lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        match = _FTP_BANNER_RE.match(line.strip())
        if not match:
            continue
        banner = match.group(1)
        port = args.rport or 21
        findings.append(
            tool.finding(
                title=f"FTP banner disclosure: {truncate(banner, 120)}",
                severity=Severity.LOW,
                confidence=0.85,
                target=args.target,
                endpoint=host_port(args.target, port),
                evidence=truncate(f"msf ftp_version: {line.strip()}", 600),
                remediation="Suppress the FTP version banner and patch the disclosed version.",
            )
        )
    return findings


def _parse_ssh_version(
    tool: MetasploitTool, args: MetasploitArgs, lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    port = args.rport or 22
    for line in lines:
        stripped = line.strip()
        match = _SSH_VERSION_RE.match(stripped)
        if match:
            ident = match.group(2)
            findings.append(
                tool.finding(
                    title=f"SSH server version: {truncate(ident, 120)}",
                    severity=Severity.LOW,
                    confidence=0.9,
                    target=args.target,
                    endpoint=host_port(args.target, port),
                    evidence=truncate(f"msf ssh_version: {stripped}", 600),
                )
            )
            continue
        match = _SSH_FINGERPRINT_RE.match(stripped)
        if match:
            findings.append(
                tool.finding(
                    title=f"SSH host key fingerprint: {truncate(match.group(2), 120)}",
                    severity=Severity.INFO,
                    confidence=0.9,
                    target=args.target,
                    endpoint=host_port(args.target, port),
                    evidence=truncate(f"msf ssh_version: {stripped}", 600),
                )
            )
    return findings


def _parse_smb_version(
    tool: MetasploitTool, args: MetasploitArgs, lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    port = args.rport or 445
    for line in lines:
        stripped = line.strip()
        match = _SMB_DETECTED_RE.match(stripped)
        if match:
            findings.append(
                tool.finding(
                    title=f"SMB service: {truncate(match.group(1), 160)}",
                    severity=Severity.INFO,
                    confidence=0.9,
                    target=args.target,
                    endpoint=host_port(args.target, port),
                    evidence=truncate(f"msf smb_version: {stripped}", 600),
                )
            )
            continue
        match = _SMB_OS_RE.match(stripped)
        if match:
            findings.append(
                tool.finding(
                    title=f"SMB operating system disclosure: {truncate(match.group(1), 140)}",
                    severity=Severity.LOW,
                    confidence=0.85,
                    target=args.target,
                    endpoint=host_port(args.target, port),
                    evidence=truncate(f"msf smb_version: {stripped}", 600),
                )
            )
            continue
        if _SMB_SIGNING_RE.search(stripped):
            findings.append(
                tool.finding(
                    title="SMB signing is not required (relay risk)",
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    target=args.target,
                    endpoint=host_port(args.target, port),
                    evidence=truncate(f"msf smb_version: {stripped}", 600),
                    cwe="CWE-294",
                    remediation=(
                        "Require SMB signing on the server and enable EPA/extended "
                        "protection where supported."
                    ),
                    verified=False,
                )
            )
    return findings


def _parse_vnc_none_auth(
    tool: MetasploitTool, args: MetasploitArgs, lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        match = _VNC_OPEN_RE.match(line.strip())
        if not match:
            continue
        host, port = match.group(1), match.group(2)
        findings.append(
            tool.finding(
                title="VNC server allows unauthenticated access",
                severity=Severity.HIGH,
                confidence=0.9,
                target=args.target,
                endpoint=_endpoint(args, host, port),
                evidence=truncate(f"msf vnc_none_auth: {line.strip()}", 600),
                cwe="CWE-306",
                remediation="Require VNC authentication and restrict access by firewall.",
                verified=False,
            )
        )
    return findings


def _parse_mssql_ping(
    tool: MetasploitTool, args: MetasploitArgs, lines: list[str]
) -> list[Finding]:
    pairs: list[str] = []
    in_body = False
    for raw in lines:
        line = raw.strip()
        if _MSSQL_HEADER_RE.match(line):
            in_body = True
            continue
        if in_body:
            match = _MSSQL_PAIR_RE.match(line)
            if match:
                pairs.append(f"{match.group(1)}={match.group(2)}")
            elif line.startswith("[*]") or line.startswith("[-]"):
                break
    if not pairs:
        return []
    port = args.rport or 1434
    return [
        tool.finding(
            title="MSSQL browser responds with instance details",
            severity=Severity.LOW,
            confidence=0.9,
            target=args.target,
            endpoint=host_port(args.target, port),
            evidence=truncate("msf mssql_ping: " + "; ".join(pairs[:10]), 800),
            remediation="Filter UDP 1434 and hide instance details from untrusted networks.",
        )
    ]


def _parse_bluekeep(tool: MetasploitTool, args: MetasploitArgs, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    port = args.rport or 3389
    for line in lines:
        match = _BLUEKEEP_RE.match(line.strip())
        if not match:
            continue
        findings.append(
            tool.finding(
                title="Host behaves like an unpatched BlueKeep target (CVE-2019-0708)",
                severity=Severity.HIGH,
                confidence=0.75,
                target=args.target,
                endpoint=host_port(args.target, port),
                evidence=truncate(f"msf bluekeep check: {match.group(1)}", 600),
                cve="CVE-2019-0708",
                remediation="Apply the Windows RDP security update and enable NLA.",
                verified=False,
            )
        )
    return findings


def _parse_ms17_010(tool: MetasploitTool, args: MetasploitArgs, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    port = args.rport or 445
    for line in lines:
        stripped = line.strip()
        match = _MS17_010_RE.match(stripped)
        if match:
            findings.append(
                tool.finding(
                    title="Host is likely vulnerable to MS17-010 (EternalBlue)",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    target=args.target,
                    endpoint=host_port(args.target, port),
                    evidence=truncate(f"msf ms17_010 check: {stripped}", 600),
                    cve="CVE-2017-0144",
                    remediation="Apply MS17-010 and disable SMBv1.",
                    verified=False,
                )
            )
            continue
        match = _MS17_PIPE_RE.match(stripped)
        if match:
            findings.append(
                tool.finding(
                    title=f"SMB named pipe reachable: {truncate(match.group(1), 80)}",
                    severity=Severity.INFO,
                    confidence=0.85,
                    target=args.target,
                    endpoint=host_port(args.target, port),
                    evidence=truncate(f"msf ms17_010 check: {stripped}", 400),
                )
            )
    return findings


def _parse_generic(tool: MetasploitTool, args: MetasploitArgs, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for line in lines:
        match = _GENERIC_GOOD_RE.match(line.strip())
        if not match or len(match.group(1)) < 4:
            continue
        findings.append(
            tool.finding(
                title=truncate(f"msf {args.module}: {match.group(1)}", 220),
                severity=Severity.INFO,
                confidence=0.6,
                target=args.target,
                endpoint=None,
                evidence=truncate(f"msf {args.module}: {line.strip()}", 600),
            )
        )
        if len(findings) >= 40:
            break
    return findings


_PARSERS = {
    "tcp_scan": _parse_tcp_scan,
    "http_version": _parse_http_version,
    "http_title": _parse_http_title,
    "robots_txt": _parse_robots_txt,
    "ftp_version": _parse_ftp_version,
    "ssh_version": _parse_ssh_version,
    "smb_version": _parse_smb_version,
    "vnc_none_auth": _parse_vnc_none_auth,
    "mssql_ping": _parse_mssql_ping,
    "bluekeep": _parse_bluekeep,
    "ms17_010": _parse_ms17_010,
}


__all__ = ["MetasploitArgs", "MetasploitTool"]
