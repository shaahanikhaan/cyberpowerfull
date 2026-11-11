"""gospider wrapper: fast web crawling with JSON lines on stdout.

Flags verified against jaeles-project/gospider (README ``Flags`` plus
``core/crawler.go`` on main, 2026-11-11): ``-s`` is the site, ``-d`` depth
(1 by default, 0 means unbounded), ``-c`` concurrency, ``-m`` request
timeout, ``-k`` delay, ``--json`` prints one ``SpiderOutput`` object per
line (``input/source/type/output/status/length``), ``--sitemap`` and
``--subs`` widen the crawl, ``-a`` pulls URLs from third parties
(archive.org, CommonCrawl, VirusTotal, AlienVault). ``-o`` writes a
per-host file inside a folder, so this wrapper parses stdout instead.
Observed ``type`` values: ``url``, ``subdomain``, ``javascript``,
``linkfinder``, ``form``, ``upload-form``, ``robots``, ``sitemap``, ``aws``.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, json_lines, truncate

_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")


class GospiderArgs(UrlInput):
    """Validated gospider invocation arguments."""

    depth: int = Field(default=1, ge=0, le=3)
    concurrent: int = Field(default=5, ge=1, le=20)
    request_timeout: int = Field(default=10, ge=1, le=60)
    delay: int = Field(default=0, ge=0, le=30)
    sitemap: bool = False
    subs: bool = False
    other_source: bool = False
    max_findings: int = Field(default=100, ge=1, le=500)


class GospiderTool(BaseTool):
    name = "gospider"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = "gospider"
    description = (
        "Fast web crawl of pages, scripts, forms and subdomains. "
        "Third-party URL sources are opt-in."
    )
    input_model = GospiderArgs

    def build_argv(self, args: GospiderArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "gospider",
            "-s",
            args.target,
            "-d",
            str(args.depth),
            "-c",
            str(args.concurrent),
            "-m",
            str(args.request_timeout),
            "-k",
            str(args.delay),
            "--json",
        ]
        if args.sitemap:
            argv.append("--sitemap")
        if args.subs:
            argv.append("--subs")
        if args.other_source:
            argv.append("-a")
        return argv

    def parse(self, args: GospiderArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for record in json_lines(output):
            kind = str(record.get("type") or "").strip().lower()
            value = str(record.get("output") or "").strip()
            if not kind or not value:
                continue
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            finding = self._finding_for(args, record, kind, value)
            if finding is not None:
                findings.append(finding)
            if len(findings) >= args.max_findings:
                break
        return findings

    def _finding_for(
        self, args: GospiderArgs, record: dict[str, Any], kind: str, value: str
    ) -> Finding | None:
        source = str(record.get("source") or "")
        status = record.get("status", "")
        length = record.get("length", "")
        context = f"source={source or '?'} status={status or '?'} length={length or '?'}"
        if kind == "subdomain":
            return self.finding(
                title=f"Subdomain discovered: {value}",
                severity=Severity.INFO,
                confidence=0.75,
                target=args.target,
                endpoint=value,
                evidence=truncate(f"gospider type=subdomain output={value} {context}"),
            )
        if kind in {"url", "linkfinder", "javascript", "robots", "sitemap"}:
            label = {"linkfinder": "JS-discovered URL"}.get(kind, kind.upper())
            return self.finding(
                title=truncate(f"Crawled {label}: {value}", 200),
                severity=Severity.INFO,
                confidence=0.7,
                target=args.target,
                endpoint=value,
                evidence=truncate(f"gospider type={kind} output={value} {context}"),
            )
        if kind == "form":
            return self.finding(
                title=truncate(f"HTML form: {value}", 200),
                severity=Severity.INFO,
                confidence=0.65,
                target=args.target,
                endpoint=value,
                evidence=truncate(f"gospider type=form output={value} {context}"),
            )
        if kind == "upload-form":
            return self.finding(
                title=truncate(f"File-upload form: {value}", 200),
                severity=Severity.LOW,
                confidence=0.6,
                target=args.target,
                endpoint=value,
                evidence=truncate(f"gospider type=upload-form output={value} {context}"),
                remediation="Verify upload validation, type checks and storage.",
            )
        if kind == "aws":
            if _AWS_KEY.search(value):
                return self.finding(
                    title="Possible AWS access key in crawled content",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    target=args.target,
                    endpoint=args.target,
                    evidence=truncate(f"gospider type=aws output={value} {context}"),
                    remediation="Rotate the exposed key and audit its usage.",
                )
            return self.finding(
                title=truncate(f"AWS reference: {value}", 200),
                severity=Severity.LOW,
                confidence=0.6,
                target=args.target,
                endpoint=args.target,
                evidence=truncate(f"gospider type=aws output={value} {context}"),
            )
        return self.finding(
            title=truncate(f"Crawled {kind}: {value}", 200),
            severity=Severity.INFO,
            confidence=0.5,
            target=args.target,
            endpoint=args.target,
            evidence=truncate(f"gospider type={kind} output={value} {context}"),
        )

    def observations(self, args: GospiderArgs, output: str) -> list[str]:
        kinds: dict[str, int] = {}
        total = 0
        for record in json_lines(output):
            total += 1
            kind = str(record.get("type") or "unknown")
            kinds[kind] = kinds.get(kind, 0) + 1
        detail = ", ".join(f"{key}={kinds[key]}" for key in sorted(kinds))
        return [f"gospider: {total} record(s) ({detail or 'none'})"]


__all__ = ["GospiderArgs", "GospiderTool"]
