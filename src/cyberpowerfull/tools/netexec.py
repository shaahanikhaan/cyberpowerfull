"""NetExec wrapper: read-only SMB null/guest-session enumeration.

Flags verified against Pennyw0rth/NetExec v1.5.1 docs
(``enumerate-null-sessions`` + ``enumerate-shares-and-access``, 2026-11-11):
``nxc smb TARGET -u '' -p '' [--shares [READ,WRITE] | --pass-pol | --users |
--groups]``.

Deliberate limits (proof-only exploitation invariant):

* SMB only, null or guest session only. There is deliberately **no**
  password argument: credential material must never travel in argv, traces,
  or the report. Password-based checks stay with hydra (file-based,
  redacted).
* Enumeration flags only. Command execution (``-x``), dumping (``--sam``),
  spidering, and every ``-M`` module are unreachable: the wrapper has no
  option that emits them.
* Requires the ``credential_testing`` capability: touching the auth surface
  needs an explicit grant even when no credential is sent.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, field_validator

from cyberpowerfull.models import Capability, Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

#: ``SMB  192.0.2.10  445  DC01  [+] ...`` nxc marks successes with [+].
_SUCCESS_RE = re.compile(r"^SMB\s+\S+\s+\d+\s+\S*\s*\[\+\]\s*(.*)$")
_SIGNING_RE = re.compile(r"signing\s*:\s*False", re.IGNORECASE)
_SMB1_RE = re.compile(r"SMBv1\s*:\s*True", re.IGNORECASE)
_SHARE_RE = re.compile(r"^([A-Za-z0-9_.$-]{1,64})\s+(READ(?:,WRITE)?|WRITE)\s*$")
_USER_RE = re.compile(r"^SMB\s+\S+\s+\d+\s+\S*\s*\[\+\]\s*\S*\\(\S+?):\d+\s")

_ENUM_FLAGS = {
    "shares": ("--shares",),
    "pass_pol": ("--pass-pol",),
    "users": ("--users",),
    "groups": ("--groups",),
}


class NetexecArgs(HostInput):
    """Validated NetExec SMB enumeration arguments (null/guest session)."""

    guest: bool = False
    enumerate: list[Literal["shares", "pass_pol", "users", "groups"]] = Field(
        default_factory=lambda: ["shares"]
    )
    share_filter: Literal["READ", "WRITE"] | None = None
    max_findings: int = Field(default=50, ge=1, le=500)

    @field_validator("enumerate")
    @classmethod
    def _check_enumerate(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one enumeration target is required")
        return values

    @field_validator("share_filter")
    @classmethod
    def _check_filter(cls, value: str | None, info) -> str | None:  # type: ignore[no-untyped-def]
        if value is not None and "shares" not in (info.data.get("enumerate") or []):
            raise ValueError("share_filter needs enumerate=['shares', ...]")
        return value


class NetexecTool(BaseTool):
    name = "netexec"
    phase = Phase.SCANNING
    skill = "network_services"
    binary = "nxc"
    required_capability = Capability.CREDENTIAL_TESTING
    timeout_s = 300
    description = (
        "Read-only SMB enumeration over a null or guest session: shares and "
        "their access, password policy, users, groups. No credentials, no "
        "execution, no dumping."
    )
    input_model = NetexecArgs

    def build_argv(self, args: NetexecArgs, out_file: str | None = None) -> list[str]:
        argv = ["nxc", "smb", args.target]
        if args.guest:
            argv.extend(["-u", "guest", "-p", ""])
        else:
            argv.extend(["-u", "", "-p", ""])
        for item in args.enumerate:
            flag = _ENUM_FLAGS[item][0]
            if item == "shares" and args.share_filter:
                argv.extend([flag, args.share_filter])
            else:
                argv.append(flag)
        return argv

    def parse(self, args: NetexecArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        session = "guest" if args.guest else "null"
        seen: set[str] = set()
        for line in output.splitlines():
            stripped = line.strip()
            success = _SUCCESS_RE.match(stripped)
            if success and "session" not in seen:
                # Any [+] line proves the session: nxc cannot enumerate shares,
                # users, or policy without an accepted null/guest logon.
                seen.add("session")
                findings.append(
                    self.finding(
                        title=f"SMB {session} session accepted on {args.target}",
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        target=args.target,
                        endpoint=f"{args.target}:445",
                        evidence=truncate(
                            f"nxc smb {session} session: {success.group(1).strip()}", 300
                        ),
                    )
                )
            if _SMB1_RE.search(stripped) and "smbv1" not in seen:
                seen.add("smbv1")
                findings.append(
                    self.finding(
                        title=f"SMBv1 enabled on {args.target}",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        target=args.target,
                        endpoint=f"{args.target}:445",
                        evidence=truncate(f"nxc: {stripped}", 300),
                    )
                )
            if _SIGNING_RE.search(stripped) and "signing" not in seen:
                seen.add("signing")
                findings.append(
                    self.finding(
                        title=f"SMB signing not required on {args.target}",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        target=args.target,
                        endpoint=f"{args.target}:445",
                        evidence=truncate(f"nxc: {stripped}", 300),
                    )
                )
            share = _SHARE_RE.match(stripped)
            if share and f"share:{share.group(1)}" not in seen:
                seen.add(f"share:{share.group(1)}")
                writable = "WRITE" in share.group(2)
                findings.append(
                    self.finding(
                        title=(
                            f"SMB share {share.group(1)} is "
                            f"{'writable' if writable else 'readable'} "
                            f"via {session} session"
                        ),
                        severity=Severity.MEDIUM if writable else Severity.LOW,
                        confidence=0.85,
                        target=args.target,
                        endpoint=f"{args.target}:445",
                        evidence=truncate(f"nxc --shares: {stripped}", 300),
                    )
                )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: NetexecArgs, output: str) -> list[str]:
        users = {
            match.group(1)
            for line in output.splitlines()
            if (match := _USER_RE.match(line.strip()))
        }
        session = "guest" if args.guest else "null"
        count = len(self.parse(args, output))
        note = f"netexec smb ({session}): {count} finding(s)"
        if users:
            note += f", {len(users)} user(s) enumerated"
        return [note]


__all__ = ["NetexecArgs", "NetexecTool"]
