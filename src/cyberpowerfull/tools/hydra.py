"""hydra wrapper: bounded online credential testing.

Guardrails are enforced here, not in the prompt:

* the tool requires the ``credential_testing`` capability in ``scope.json``;
* the password list must exist, be plain text, and contain at most
  ``MAX_PASSWORD_CANDIDATES`` lines;
* hydra stops at the first valid credential per login (``-f``) and is capped at
  8 parallel tasks;
* recovered passwords are redacted in evidence - the trace and the Markdown
  report are engagement artefacts that must not become a credential store.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from cyberpowerfull.models import Capability, Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

MAX_PASSWORD_CANDIDATES = 5000
MAX_TASKS = 8

_SERVICES = (
    "ssh",
    "ftp",
    "smtp",
    "pop3",
    "imap",
    "telnet",
    "rdp",
    "mysql",
    "postgres",
    "mssql",
    "vnc",
    "ldap2",
)
_CRED_LINE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[\w-]+)\]\s+host:\s*(?P<host>\S+)\s+"
    r"login:\s*(?P<login>\S+)\s+password:\s*(?P<password>.+)$",
    re.MULTILINE,
)
_WORDLIST_RE = re.compile(r"^[A-Za-z0-9_\-./~ ]{1,400}$")


class HydraArgs(HostInput):
    """Validated hydra invocation arguments."""

    service: Literal[_SERVICES] = "ssh"  # type: ignore[valid-type]
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=64)
    password_list: str = Field(min_length=1, max_length=400)
    tasks: int = Field(default=4, ge=1, le=MAX_TASKS)
    max_password_candidates: int = Field(default=500, ge=1, le=MAX_PASSWORD_CANDIDATES)

    @field_validator("username")
    @classmethod
    def _check_username(cls, value: str) -> str:
        if not re.match(r"^[A-Za-z0-9._@\\-]{1,64}$", value):
            raise ValueError("username must be a plain account name")
        return value

    @field_validator("password_list")
    @classmethod
    def _check_wordlist(cls, value: str) -> str:
        if not _WORDLIST_RE.match(value) or ".." in value:
            raise ValueError("password_list must be a plain filesystem path")
        path = Path(value).expanduser()
        if not path.is_file():
            raise ValueError(f"password list not found: {value}")
        return str(path)


class HydraTool(BaseTool):
    name = "hydra"
    phase = Phase.VALIDATION
    skill = "credential_testing"
    binary = "hydra"
    required_capability = Capability.CREDENTIAL_TESTING
    success_codes = (0, 255)
    timeout_s = 900
    description = (
        "Bounded online credential testing against one service with an explicit "
        "username and a capped password list. Requires the 'credential_testing' "
        "capability; passwords are redacted in evidence."
    )
    input_model = HydraArgs

    def build_argv(self, args: HydraArgs, out_file: str | None = None) -> list[str]:
        from cyberpowerfull.errors import InvalidToolArguments

        wordlist = Path(args.password_list).expanduser()
        try:
            line_count = sum(1 for _ in wordlist.open("r", errors="replace"))
        except OSError as exc:  # pragma: no cover - validation already checked existence
            raise InvalidToolArguments(f"cannot read password list: {exc}") from exc
        if line_count > args.max_password_candidates:
            raise InvalidToolArguments(
                f"password list has {line_count} lines, above the {args.max_password_candidates} "
                "candidate cap; use a smaller list (unbounded guessing is not permitted)"
            )
        argv = [
            "hydra",
            "-t",
            str(min(args.tasks, MAX_TASKS)),
            "-f",
            "-I",
            "-l",
            args.username,
            "-P",
            str(wordlist),
        ]
        if args.port:
            argv.extend(["-s", str(args.port)])
        argv.extend([args.target, args.service])
        return argv

    def parse(self, args: HydraArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for match in _CRED_LINE.finditer(output):
            login = match.group("login")
            password = match.group("password").strip()
            masked = _mask(password)
            findings.append(
                self.finding(
                    title=f"Valid {match.group('service')} credentials for {login}",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    target=args.target,
                    endpoint=f"{match.group('host')}:{match.group('port')}",
                    evidence=truncate(
                        f"hydra service={match.group('service')} login={login} "
                        f"password={masked} (redacted, length {len(password)})"
                    ),
                    verified=True,
                    remediation=(
                        "Enforce MFA, account lockout and strong password policy on this service."
                    ),
                )
            )
        return findings

    def observations(self, args: HydraArgs, output: str) -> list[str]:
        hits = len(self.parse(args, output))
        if hits:
            return [f"hydra: {hits} valid credential pair(s) for {args.service} on {args.target}"]
        return [f"hydra: no valid credential found ({args.service}, bounded list)"]


def _mask(secret: str) -> str:
    if len(secret) <= 2:
        return "*" * len(secret)
    return f"{secret[0]}{'*' * (len(secret) - 2)}{secret[-1]}"


__all__ = ["MAX_PASSWORD_CANDIDATES", "MAX_TASKS", "HydraArgs", "HydraTool"]
