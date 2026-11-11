"""gau wrapper: historical URL discovery from web archives (ndjson on stdout).

Flags verified against lc/gau (``runner/flags/flags.go`` and
``runner/runner.go`` on main, 2026-11-11): the domain is positional,
``--json`` prints one ``{"url": ...}`` object per line, ``--providers``
selects from ``wayback,commoncrawl,otx,urlscan`` (default is all four),
``--subs`` includes subdomains, ``--fp`` collapses parameter variants of
one endpoint, ``--blacklist`` skips extensions, ``--threads``/``--timeout``/
``--retries`` bound the HTTP client (defaults 1/45/0), ``--from``/``--to``
bound wayback coverage as YYYYMM. ``--o`` writes a file, so this wrapper
parses stdout instead. All providers are third-party archives: the worker
requires ``allow_passive_sources`` for this tool.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, json_lines, truncate

_PROVIDERS = ("wayback", "commoncrawl", "otx", "urlscan")
_EXTENSION = re.compile(r"^[a-z0-9]{1,8}$")
_YEAR_MONTH = re.compile(r"^\d{6}$")


class GauArgs(DomainInput):
    """Validated gau invocation arguments."""

    providers: list[str] = Field(default_factory=lambda: list(_PROVIDERS))
    subs: bool = False
    collapse_params: bool = True
    blacklist: list[str] = Field(default_factory=list, max_length=20)
    threads: int = Field(default=1, ge=1, le=10)
    timeout: int = Field(default=45, ge=5, le=300)
    retries: int = Field(default=0, ge=0, le=5)
    fetch_from: str | None = Field(default=None, max_length=6)
    fetch_to: str | None = Field(default=None, max_length=6)
    max_findings: int = Field(default=100, ge=1, le=500)

    @field_validator("providers")
    @classmethod
    def _check_providers(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one provider is required")
        lowered = [value.strip().lower() for value in values]
        for value in lowered:
            if value not in _PROVIDERS:
                raise ValueError(f"unsupported provider: {value!r}")
        return lowered

    @field_validator("blacklist")
    @classmethod
    def _check_blacklist(cls, values: list[str]) -> list[str]:
        lowered = [value.strip().lower().lstrip(".") for value in values]
        for value in lowered:
            if not _EXTENSION.match(value):
                raise ValueError(f"unsupported extension: {value!r}")
        return lowered

    @field_validator("fetch_from", "fetch_to")
    @classmethod
    def _check_year_month(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not _YEAR_MONTH.match(cleaned):
            raise ValueError("fetch window must be YYYYMM")
        return cleaned


class GauTool(BaseTool):
    name = "gau"
    phase = Phase.RECON
    skill = "information_disclosure"
    binary = "gau"
    description = (
        "Historical URL discovery from Wayback, CommonCrawl, OTX and urlscan. "
        "Third-party archives: needs allow_passive_sources."
    )
    input_model = GauArgs

    def build_argv(self, args: GauArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "gau",
            "--json",
            "--providers",
            ",".join(args.providers),
            "--threads",
            str(args.threads),
            "--timeout",
            str(args.timeout),
            "--retries",
            str(args.retries),
        ]
        if args.subs:
            argv.append("--subs")
        if args.collapse_params:
            argv.append("--fp")
        if args.blacklist:
            argv.extend(["--blacklist", ",".join(args.blacklist)])
        if args.fetch_from:
            argv.extend(["--from", args.fetch_from])
        if args.fetch_to:
            argv.extend(["--to", args.fetch_to])
        argv.append(args.target)
        return argv

    def parse(self, args: GauArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen_urls: set[str] = set()
        seen_hosts: set[str] = set()
        for record in json_lines(output):
            url = str(record.get("url") or "").strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                host = (urlsplit(url).hostname or "").lower().rstrip(".")
            except ValueError:
                host = ""
            if host and host != args.target and host.endswith("." + args.target):
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    findings.append(
                        self.finding(
                            title=f"Subdomain discovered: {host}",
                            severity=Severity.INFO,
                            confidence=0.7,
                            target=args.target,
                            endpoint=host,
                            evidence=truncate(f"gau historical url={url}"),
                        )
                    )
                    if len(findings) >= args.max_findings:
                        return findings
                continue
            parameterised = "?" in url and "=" in url.split("?", 1)[1]
            label = "Historical parameterised URL" if parameterised else "Historical URL"
            findings.append(
                self.finding(
                    title=truncate(f"{label}: {url}", 200),
                    severity=Severity.LOW if parameterised else Severity.INFO,
                    confidence=0.6,
                    target=args.target,
                    endpoint=url,
                    evidence=truncate(f"gau url={url}"),
                )
            )
            if len(findings) >= args.max_findings:
                return findings
        return findings

    def observations(self, args: GauArgs, output: str) -> list[str]:
        count = sum(1 for _ in json_lines(output))
        return [f"gau: {count} url(s) from {','.join(args.providers)}"]


__all__ = ["GauArgs", "GauTool"]
