"""enum4linux-ng wrapper: SMB/AD enumeration with null sessions (JSON output).

Flags verified against CiscoCXSecurity/enum4linux-ng (``enum4linux-ng.py``
on main, 2026-11-11): the host is positional, ``-A`` runs all simple
modules (``-U -G -S -P -O -N -I -L``), ``-C`` enumerates services, ``-d``
adds user/group details, ``-w`` pins the workgroup, ``-t`` sets the
connection timeout (0-600s, default 5s), and ``-oJ STEM`` writes
``STEM.json`` (the extension is ALWAYS appended, so this wrapper passes
the output path minus its ``.json`` suffix). Credentials default to empty
(null session); this wrapper never sends any. The JSON top level carries
``sessions_possible/null_session_possible/user_session_possible/
random_user_session_possible``, ``users`` as ``{rid: {username, ...}}``,
``shares`` as ``{name: {type, comment, access: {mapping, listing}}}``,
``policy.domain_password_information`` (``min_pw_length`` and friends),
``os_info``, ``groups`` and ``errors``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

#: Wrapper module name -> enum4linux-ng CLI flag (README documents -A = all simple).
_MODULE_FLAGS = {
    "users": "-U",
    "groups": "-G",
    "shares": "-S",
    "policy": "-P",
    "os_info": "-O",
    "nmblookup": "-N",
    "printers": "-I",
    "ldap": "-L",
    "services": "-C",
}

_DEFAULT_MODULES = (
    "users",
    "groups",
    "shares",
    "policy",
    "os_info",
    "nmblookup",
    "printers",
    "ldap",
)

_WORKGROUP = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


class Enum4linuxArgs(HostInput):
    """Validated enum4linux-ng invocation arguments (null session only)."""

    modules: list[str] = Field(default_factory=lambda: list(_DEFAULT_MODULES))
    detailed: bool = False
    workgroup: str | None = Field(default=None, max_length=64)
    timeout: int = Field(default=5, ge=1, le=600)
    max_findings: int = Field(default=50, ge=1, le=500)

    @field_validator("modules")
    @classmethod
    def _check_modules(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one module is required")
        lowered = [value.strip().lower() for value in values]
        for value in lowered:
            if value not in _MODULE_FLAGS:
                raise ValueError(f"unsupported module: {value!r}")
        return lowered

    @field_validator("workgroup")
    @classmethod
    def _check_workgroup(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not _WORKGROUP.match(cleaned):
            raise ValueError(f"unsupported workgroup: {value!r}")
        return cleaned


class Enum4linuxTool(BaseTool):
    name = "enum4linux"
    phase = Phase.SCANNING
    skill = "network_services"
    binary = "enum4linux-ng"
    writes_output_file = True
    timeout_s = 600
    description = (
        "SMB enumeration over a null session: sessions, users, groups, "
        "shares, password policy and OS fingerprint. No credentials sent."
    )
    input_model = Enum4linuxArgs

    def build_argv(self, args: Enum4linuxArgs, out_file: str | None = None) -> list[str]:
        argv = ["enum4linux-ng"]
        if out_file:
            # -oJ appends ".json" itself; strip it so the file lands exactly
            # where the runner looks.
            stem = out_file[:-5] if out_file.endswith(".json") else out_file
            argv.extend(["-oJ", stem])
        for module in args.modules:
            argv.append(_MODULE_FLAGS[module])
        if args.detailed:
            argv.append("-d")
        if args.workgroup:
            argv.extend(["-w", args.workgroup])
        argv.extend(["-t", str(args.timeout), args.target])
        return argv

    def parse(
        self, args: Enum4linuxArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        document = _load_document(output)
        if document is None:
            return []
        findings: list[Finding] = []

        def capped() -> bool:
            return len(findings) >= args.max_findings

        if document.get("null_session_possible") is True:
            findings.append(
                self.finding(
                    title="SMB null session allowed",
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    target=args.target,
                    endpoint=args.target,
                    evidence="enum4linux null_session_possible=true",
                    remediation="Require SMB signing and disable null sessions.",
                )
            )
        for key, label in (
            ("user_session_possible", "empty user session"),
            ("random_user_session_possible", "random user session"),
        ):
            if document.get(key) is True:
                findings.append(
                    self.finding(
                        title=f"SMB allows {label} without credentials",
                        severity=Severity.LOW,
                        confidence=0.6,
                        target=args.target,
                        endpoint=args.target,
                        evidence=f"enum4linux {key}=true",
                        remediation="Disable guest/anonymous SMB access.",
                    )
                )
        users = document.get("users")
        if isinstance(users, dict):
            for rid, entry in users.items():
                if not isinstance(entry, dict):
                    continue
                username = str(entry.get("username") or "").strip()
                if not username:
                    continue
                description = str(entry.get("description") or "").strip()
                findings.append(
                    self.finding(
                        title=f"SMB user enumerated: {username}",
                        severity=Severity.INFO,
                        confidence=0.8,
                        target=args.target,
                        endpoint=args.target,
                        evidence=truncate(
                            f"enum4linux rid={rid} username={username}"
                            + (f" description={description}" if description else "")
                        ),
                    )
                )
                if capped():
                    return findings
        groups = document.get("groups")
        if isinstance(groups, dict):
            for name in groups:
                findings.append(
                    self.finding(
                        title=f"SMB group enumerated: {name}",
                        severity=Severity.INFO,
                        confidence=0.75,
                        target=args.target,
                        endpoint=args.target,
                        evidence=truncate(f"enum4linux group={name}"),
                    )
                )
                if capped():
                    return findings
        shares = document.get("shares")
        if isinstance(shares, dict):
            for name, entry in shares.items():
                access = entry.get("access") if isinstance(entry, dict) else None
                mapping = access.get("mapping") if isinstance(access, dict) else None
                listing = access.get("listing") if isinstance(access, dict) else None
                readable = mapping == "ok" and listing == "ok"
                findings.append(
                    self.finding(
                        title=(
                            f"Readable SMB share: {name}"
                            if readable
                            else f"SMB share enumerated: {name}"
                        ),
                        severity=Severity.LOW if readable else Severity.INFO,
                        confidence=0.75,
                        target=args.target,
                        endpoint=args.target,
                        evidence=truncate(
                            f"enum4linux share={name} mapping={mapping} listing={listing}"
                        ),
                        remediation=(
                            "Restrict share permissions to authorised users." if readable else None
                        ),
                    )
                )
                if capped():
                    return findings
        policy = document.get("policy")
        password_info = (
            policy.get("domain_password_information") if isinstance(policy, dict) else None
        )
        if isinstance(password_info, dict):
            min_length = password_info.get("min_pw_length")
            if isinstance(min_length, int) and min_length < 8:
                findings.append(
                    self.finding(
                        title=f"Weak domain password policy: minimum length {min_length}",
                        severity=Severity.LOW,
                        confidence=0.7,
                        target=args.target,
                        endpoint=args.target,
                        evidence=truncate(f"enum4linux min_pw_length={min_length}"),
                        remediation="Enforce a minimum password length of 12+ characters.",
                    )
                )
        os_info = document.get("os_info")
        if isinstance(os_info, dict):
            label = str(os_info.get("os") or "").strip()
            if label:
                findings.append(
                    self.finding(
                        title=truncate(f"OS fingerprint: {label}", 200),
                        severity=Severity.INFO,
                        confidence=0.8,
                        target=args.target,
                        endpoint=args.target,
                        evidence=truncate(f"enum4linux os={label}"),
                    )
                )
        return findings[: args.max_findings]

    def observations(self, args: Enum4linuxArgs, output: str) -> list[str]:
        document = _load_document(output)
        if document is None:
            return ["enum4linux: output was not a JSON document"]
        users = document.get("users")
        shares = document.get("shares")
        errors = document.get("errors")
        return [
            "enum4linux: "
            f"sessions_possible={document.get('sessions_possible', '?')} "
            f"users={len(users) if isinstance(users, dict) else 0} "
            f"shares={len(shares) if isinstance(shares, dict) else 0} "
            f"errors={len(errors) if isinstance(errors, dict) else 0}"
        ]


def _load_document(output: str) -> dict[str, Any] | None:
    try:
        document = json.loads(output.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    return document if isinstance(document, dict) else None


__all__ = ["Enum4linuxArgs", "Enum4linuxTool"]
