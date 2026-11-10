"""httpx wrapper: HTTP probing, status/title/tech fingerprinting (JSONL output)."""

from __future__ import annotations

import re

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, json_lines, truncate

_VERSIONED_BANNER = re.compile(r"\d+\.\d+")


class HttpxArgs(UrlInput):
    """Validated httpx invocation arguments."""

    ports: list[int] = Field(default_factory=list, max_length=20)
    tech_detect: bool = True
    follow_redirects: bool = False
    threads: int = Field(default=10, ge=1, le=50)

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, values: list[int]) -> list[int]:
        for value in values:
            if not 1 <= int(value) <= 65535:
                raise ValueError("ports must be within 1-65535")
        return values


class HttpxTool(BaseTool):
    name = "httpx"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = "httpx"
    description = (
        "Fast HTTP probe. Confirms live web endpoints, status codes, page titles and "
        "technology fingerprints before deeper testing."
    )
    input_model = HttpxArgs

    def build_argv(self, args: HttpxArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "httpx",
            "-u",
            args.target,
            "-json",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-sc",
            "-title",
            "-t",
            str(args.threads),
        ]
        if args.tech_detect:
            argv.append("-td")
        if args.follow_redirects:
            argv.append("-follow-host-redirects")
        if args.ports:
            argv.extend(["-ports", ",".join(str(p) for p in args.ports)])
        return argv

    def parse(self, args: HttpxArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for record in json_lines(output):
            url = str(record.get("url") or record.get("input") or args.target)
            status = record.get("status_code")
            webserver = str(record.get("webserver") or "")
            tech = [str(item) for item in (record.get("tech") or [])][:6]
            title = str(record.get("title") or "")
            if webserver and _VERSIONED_BANNER.search(webserver):
                findings.append(
                    self.finding(
                        title=f"Server banner discloses version ({webserver})",
                        severity=Severity.LOW,
                        confidence=0.7,
                        target=args.target,
                        endpoint=url,
                        evidence=truncate(f"status={status} server={webserver}"),
                        remediation="Remove version information from the Server header.",
                    )
                )
            if tech:
                findings.append(
                    self.finding(
                        title=f"Technology fingerprint: {', '.join(tech)}",
                        severity=Severity.INFO,
                        confidence=0.75,
                        target=args.target,
                        endpoint=url,
                        evidence=truncate(f"status={status} tech={', '.join(tech)}"),
                    )
                )
            if status in (401, 403):
                findings.append(
                    self.finding(
                        title=f"Access-controlled endpoint reachable (HTTP {status})",
                        severity=Severity.INFO,
                        confidence=0.6,
                        target=args.target,
                        endpoint=url,
                        evidence=truncate(f"status={status} title={title}"),
                    )
                )
        return findings

    def observations(self, args: HttpxArgs, output: str) -> list[str]:
        notes: list[str] = []
        for record in json_lines(output):
            url = record.get("url") or record.get("input")
            if url:
                notes.append(
                    truncate(
                        f"http {record.get('status_code')} {url} "
                        f"title={record.get('title') or '-'}",
                        200,
                    )
                )
        return notes[:50]


__all__ = ["HttpxArgs", "HttpxTool"]
