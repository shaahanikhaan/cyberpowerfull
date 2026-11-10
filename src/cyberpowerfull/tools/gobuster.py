"""gobuster wrapper: dir / dns / vhost / fuzz brute forcing.

When the caller omits ``wordlist`` the wrapper resolves a real, uncompressed
wordlist from the host inventory. If the host has none, the call fails with a
precise argument error instead of silently using a fabricated path.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_WORDLIST_RE = re.compile(r"^[A-Za-z0-9_\-./~]{1,400}$")
_STATUS_RE = re.compile(r"\[Status:\s*(?P<status>\d{3})", re.IGNORECASE)
_FOUND_RE = re.compile(r"^Found:\s*(?P<host>\S+)", re.IGNORECASE)
_INTERESTING = re.compile(
    r"(\.git|\.env|admin|api|backup|config|debug|internal|private|swagger|graphql)",
    re.IGNORECASE,
)


class GobusterArgs(UrlInput):
    """Validated gobuster invocation arguments."""

    mode: Literal["dir", "dns", "vhost", "fuzz"] = "dir"
    wordlist: str | None = Field(default=None, max_length=400)
    threads: int = Field(default=20, ge=1, le=50)
    extensions: list[str] = Field(default_factory=list, max_length=8)
    max_findings: int = Field(default=100, ge=1, le=500)

    @field_validator("wordlist")
    @classmethod
    def _check_wordlist(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _WORDLIST_RE.match(value) or ".." in value:
            raise ValueError("wordlist must be a plain filesystem path")
        return value


class GobusterTool(BaseTool):
    name = "gobuster"
    phase = Phase.SCANNING
    skill = "information_disclosure"
    binary = "gobuster"
    writes_output_file = True
    success_codes = (0,)
    timeout_s = 600
    description = (
        "Multi-mode brute forcer: directory and file discovery, DNS subdomain "
        "enumeration, virtual-host discovery, and generic FUZZ replacement."
    )
    input_model = GobusterArgs

    def _resolve_wordlist(self, args: GobusterArgs) -> tuple[str | None, str | None]:
        from cyberpowerfull.inventory import pick_wordlist

        if args.wordlist:
            return args.wordlist, None
        kind = "dns" if args.mode in {"dns", "vhost"} else "discovery"
        picked = pick_wordlist(kind)
        if not picked:
            return None, (
                f"gobuster mode={args.mode} needs a {kind} wordlist but none was found on this "
                "host; pass 'wordlist' explicitly or install seclists/wordlists"
            )
        return picked, None

    def build_argv(self, args: GobusterArgs, out_file: str | None = None) -> list[str]:
        from cyberpowerfull.errors import InvalidToolArguments

        wordlist, error = self._resolve_wordlist(args)
        if error or not wordlist:
            raise InvalidToolArguments(error or "no wordlist resolved")
        argv = [
            "gobuster",
            args.mode,
            "-w",
            wordlist,
            "-t",
            str(args.threads),
            "-q",
            "--no-error",
            "--no-progress",
        ]
        if out_file:
            argv.extend(["-o", out_file])
        if args.mode == "dir":
            argv.extend(["-u", args.target])
            if args.extensions:
                argv.extend(["-x", ",".join(ext.lstrip(".") for ext in args.extensions)])
        elif args.mode == "dns":
            argv.extend(["-d", args.target])
        elif args.mode == "vhost":
            argv.extend(["-u", args.target, "--append-domain"])
        else:
            if "FUZZ" not in args.target:
                raise InvalidToolArguments("gobuster mode=fuzz requires FUZZ in the URL")
            argv.extend(["-u", args.target])
        return argv

    def parse(self, args: GobusterArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            text = line.strip()
            if not text or text.startswith("=") or text.startswith("["):
                continue
            found = _FOUND_RE.match(text)
            status_match = _STATUS_RE.search(text)
            if found:
                host = found.group("host")
                findings.append(
                    self.finding(
                        title=f"Subdomain/vhost discovered: {host}",
                        severity=Severity.INFO,
                        confidence=0.8,
                        target=args.target,
                        endpoint=host,
                        evidence=truncate(f"gobuster mode={args.mode} {text}"),
                    )
                )
                continue
            if not status_match:
                continue
            status = int(status_match.group("status"))
            path = text.split()[0]
            interesting = bool(_INTERESTING.search(path))
            if status in (401, 403):
                severity = Severity.LOW
                title = f"Access-controlled path discovered (HTTP {status}): {path}"
            elif status == 200:
                severity = Severity.LOW if interesting else Severity.INFO
                title = f"Discovered content (HTTP 200): {path}"
            else:
                severity = Severity.INFO
                title = f"Discovered response (HTTP {status}): {path}"
            findings.append(
                self.finding(
                    title=truncate(title, 220),
                    severity=severity,
                    confidence=0.7,
                    target=args.target,
                    endpoint=path,
                    evidence=truncate(f"gobuster mode={args.mode} {text}"),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: GobusterArgs, output: str) -> list[str]:
        count = len(self.parse(args, output))
        return [f"gobuster mode={args.mode}: {count} result(s)"]


__all__ = ["GobusterArgs", "GobusterTool"]
