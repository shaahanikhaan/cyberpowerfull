"""uncover wrapper: query internet search engines for exposed hosts (JSONL).

Flags verified against projectdiscovery/uncover (README ``Usage`` on main,
2026-11-11; latest release v1.2.1): ``-q`` query, ``-e`` engines (repeatable),
``-l`` limit (default 100), ``-j`` JSONL, ``-timeout`` seconds. Result keys
come from ``sources/result.go``: ``timestamp/source/ip/port/host/url``.

API keys live in ``$CONFIG/uncover/provider-config.yaml`` or the documented
environment variables (``SHODAN_API_KEY``, ``CENSYS_API_TOKEN`` + ``_ORG_ID``,
``FOFA_EMAIL`` + ``FOFA_KEY``, ``QUAKE_TOKEN``, ``HUNTER_API_KEY``,
``ZOOMEYE_API_KEY``, ...). Key material never appears on argv, in findings,
or in traces: the wrapper only checks *presence* and runs the binary, which
reads its own configuration.

Passive-source discipline: results are scope-filtered (IP targets keep only
their own address; domain targets keep only the domain and its subdomains)
and anything else is counted out loud instead of silently dropped.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

from pydantic import Field, field_validator

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import (
    BaseTool,
    HostInput,
    ToolInput,
    ToolStatus,
    _Exec,
    json_lines,
    truncate,
)

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,24}$")
#: Explicit engine queries: DSL characters only, no shell metacharacters (argv
#: is never shelled, but tight input keeps traces auditable).
_QUERY_RE = re.compile(r"^[A-Za-z0-9_.:\"' \t()/=<>!#+-]{1,200}$")

#: Engines from ``uncover -h`` (``-e``). ``shodan-idb`` (InternetDB) needs no key.
_ENGINES = frozenset(
    {
        "shodan",
        "shodan-idb",
        "fofa",
        "censys",
        "quake",
        "hunter",
        "zoomeye",
        "netlas",
        "publicwww",
        "criminalip",
        "hunterhow",
        "google",
        "odin",
        "binaryedge",
        "onyphe",
        "driftnet",
        "greynoise",
        "daydaymap",
        "nerdydata",
    }
)

#: Documented environment variables per engine (README "Provider Configuration").
_ENGINE_ENV: dict[str, tuple[str, ...]] = {
    "shodan": ("SHODAN_API_KEY",),
    "censys": ("CENSYS_API_TOKEN", "CENSYS_ORGANIZATION_ID"),
    "fofa": ("FOFA_EMAIL", "FOFA_KEY"),
    "quake": ("QUAKE_TOKEN",),
    "hunter": ("HUNTER_API_KEY",),
    "zoomeye": ("ZOOMEYE_API_KEY",),
}


class UncoverArgs(HostInput):
    """Validated uncover invocation arguments."""

    query: str | None = Field(default=None, max_length=200)
    engines: list[str] = Field(default_factory=lambda: ["shodan"])
    limit: int = Field(default=25, ge=1, le=100)
    timeout: int = Field(default=30, ge=5, le=300)
    max_findings: int = Field(default=50, ge=1, le=500)

    @field_validator("target")
    @classmethod
    def _check_host(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "://" in cleaned or "/" in cleaned:
            raise ValueError("uncover requires a bare host or IP, not a URL")
        try:
            ipaddress.ip_address(cleaned)
        except ValueError:
            if not _HOSTNAME.match(cleaned):
                raise ValueError("uncover requires a valid DNS name or IP address") from None
        return cleaned

    @field_validator("query")
    @classmethod
    def _check_query(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not _QUERY_RE.match(cleaned):
            raise ValueError("query uses characters outside the engine-DSL allowlist")
        return cleaned

    @field_validator("engines")
    @classmethod
    def _check_engines(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one engine is required")
        lowered = [value.lower() for value in values]
        for value in lowered:
            if value not in _ENGINES:
                raise ValueError(f"unsupported engine: {value!r}")
        return lowered


class UncoverTool(BaseTool):
    name = "uncover"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "uncover"
    timeout_s = 300
    description = (
        "Queries internet search engines (Shodan, Censys, Fofa, ...) for hosts and "
        "services observed on the target. Needs API keys plus scope "
        "allow_passive_sources; results are scope-filtered."
    )
    input_model = UncoverArgs

    def build_argv(self, args: UncoverArgs, out_file: str | None = None) -> list[str]:
        argv = ["uncover", "-q", args.query or args.target]
        for engine in args.engines:
            argv.extend(["-e", engine])
        argv.extend(["-l", str(args.limit), "-j", "-silent", "-nc", "-timeout", str(args.timeout)])
        return argv

    def _execute(self, args: ToolInput, argv: list[str], policy: ToolPolicy) -> _Exec:
        missing = self._missing_credentials(args)
        if missing:
            return _Exec(
                status=ToolStatus.MISSING,
                error=(
                    f"uncover needs API keys for {', '.join(missing)}: "
                    f"{self._credential_hint(missing)} (keys are never logged)"
                ),
            )
        return super()._execute(args, argv, policy)

    def _missing_credentials(self, args: ToolInput) -> list[str]:
        """Engines with neither env keys nor a provider config file."""
        engines = getattr(args, "engines", ["shodan"])
        if _provider_file_exists():
            return []
        missing: list[str] = []
        for engine in engines:
            if engine == "shodan-idb":
                continue  # InternetDB is keyless
            wanted = _ENGINE_ENV.get(engine, ())
            if wanted and all(os.environ.get(name) for name in wanted):
                continue
            if not wanted:
                # Undocumented env mapping: only the config file can provide it,
                # and there is none.
                missing.append(engine)
            elif not all(os.environ.get(name) for name in wanted):
                missing.append(engine)
        return missing

    @staticmethod
    def _credential_hint(engines: list[str]) -> str:
        parts: list[str] = []
        for engine in engines:
            wanted = _ENGINE_ENV.get(engine)
            if wanted:
                parts.append(f"{engine} needs {'+'.join(wanted)}")
            else:
                parts.append(f"{engine} needs {engine} credentials in provider-config.yaml")
        return "; ".join(parts)

    def parse(self, args: UncoverArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        target_is_ip = _is_ip(args.target)
        for record in json_lines(output):
            ip = str(record.get("ip") or "").strip()
            host = str(record.get("host") or "").strip().lower()
            port = record.get("port")
            source = str(record.get("source") or "uncover")
            if target_is_ip:
                if ip != args.target:
                    continue
                endpoint_host = ip
            else:
                if host != args.target and not host.endswith("." + args.target):
                    continue
                endpoint_host = host or ip
            try:
                port_number = int(port)
            except (TypeError, ValueError):
                port_number = 0
            endpoint = (
                f"{endpoint_host}:{port_number}" if port_number else (endpoint_host or args.target)
            )
            findings.append(
                self.finding(
                    title=f"Exposed service observed via {source}: {endpoint}",
                    severity=Severity.INFO,
                    confidence=0.7,
                    target=args.target,
                    endpoint=endpoint,
                    evidence=truncate(
                        f"source={source} ip={ip or '-'} port={port_number or '-'} "
                        f"host={host or '-'}"
                    ),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: UncoverArgs, output: str) -> list[str]:
        total = sum(1 for _ in json_lines(output))
        kept = len(self.parse(args, output))
        filtered = total - kept
        note = f"uncover: {kept} in-scope result(s) via {','.join(args.engines)}"
        if filtered:
            note += f" ({filtered} out-of-scope filtered)"
        return [note]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _provider_file_exists() -> bool:
    """Only existence is checked: key material is never read by this tool."""
    candidates = [
        Path.home() / ".config" / "uncover" / "provider-config.yaml",
        (
            Path(os.environ.get("XDG_CONFIG_HOME", "")) / "uncover" / "provider-config.yaml"
            if os.environ.get("XDG_CONFIG_HOME")
            else None
        ),
    ]
    return any(path is not None and path.is_file() for path in candidates)


__all__ = ["UncoverArgs", "UncoverTool"]
