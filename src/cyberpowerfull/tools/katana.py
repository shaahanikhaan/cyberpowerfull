"""katana wrapper: crawling and endpoint harvesting (JSONL output)."""

from __future__ import annotations

import re

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, json_lines, truncate

_INTERESTING = re.compile(
    r"(\.git/|\.env|/admin|/api/|/backup|/config|/debug|/graphql|/internal|/private|"
    r"/server-status|/swagger|/actuator|/console|/phpmyadmin|/wp-admin|/\.svn)",
    re.IGNORECASE,
)


class KatanaArgs(UrlInput):
    """Validated katana invocation arguments."""

    depth: int = Field(default=2, ge=1, le=5)
    concurrency: int = Field(default=10, ge=1, le=30)
    rate_limit: int = Field(default=50, ge=5, le=150)
    js_crawl: bool = True
    known_files: bool = True
    max_findings: int = Field(default=120, ge=1, le=500)

    @field_validator("rate_limit")
    @classmethod
    def _cap_rate(cls, value: int) -> int:
        return value


class KatanaTool(BaseTool):
    name = "katana"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = "katana"
    success_codes = (0,)
    timeout_s = 600
    description = (
        "Next-generation crawler. Maps endpoints, query parameters, JavaScript "
        "sources and known files so later probes have concrete URLs to test."
    )
    input_model = KatanaArgs

    def build_argv(self, args: KatanaArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "katana",
            "-u",
            args.target,
            "-jsonl",
            "-silent",
            "-nc",
            "-d",
            str(args.depth),
            "-c",
            str(args.concurrency),
            "-rl",
            str(args.rate_limit),
            "-omit-body",
        ]
        if args.js_crawl:
            argv.append("-jc")
        if args.known_files:
            argv.extend(["-kf", "all"])
        return argv

    def parse(self, args: KatanaArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for record in json_lines(output):
            request = record.get("request") or {}
            response = record.get("response") or {}
            endpoint = str(request.get("endpoint") or record.get("url") or "")
            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)
            method = str(request.get("method") or "GET").upper()
            status = response.get("status_code")
            has_params = "?" in endpoint
            interesting = bool(_INTERESTING.search(endpoint))
            if not interesting and not has_params:
                continue
            severity = Severity.LOW if interesting else Severity.INFO
            findings.append(
                self.finding(
                    title=(
                        f"Sensitive path discovered by crawler: {_path_of(endpoint)}"
                        if interesting
                        else f"Parameterised endpoint discovered by crawler: {_path_of(endpoint)}"
                    ),
                    severity=severity,
                    confidence=0.7,
                    target=args.target,
                    endpoint=endpoint,
                    evidence=truncate(
                        f"katana {method} {endpoint} status={status} source={record.get('source')}"
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: KatanaArgs, output: str) -> list[str]:
        count = sum(1 for _ in json_lines(output))
        return [f"katana: {count} endpoint(s) crawled from {args.target}"]


def _path_of(url: str) -> str:
    path = url.split("://", 1)[-1]
    return truncate(path[:200], 120)


__all__ = ["KatanaArgs", "KatanaTool"]
