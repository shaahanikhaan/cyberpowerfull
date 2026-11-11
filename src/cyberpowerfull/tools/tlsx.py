"""tlsx wrapper: fast TLS data collection (JSONL output).

Flags verified against projectdiscovery/tlsx (README ``Usage`` plus the
``JSON Output`` sample on main, 2026-11-11; latest release v1.4.0): ``-u``
hosts, ``-p`` ports (default 443), ``-j`` JSONL, ``-ve``/``-ce`` version/cipher
enumeration, ``-timeout`` seconds, ``-retry``, ``-c`` concurrency.

The probe flags (``-san``/``-cn``/``-tls-version``/``-cipher``/...) only shape
text display — the README states all information is always in the JSON — so
the wrapper ships only behavior-changing flags. Parsed keys are exactly the
documented JSON sample: ``host/ip/port/probe_status/tls_version/cipher/
not_before/not_after/subject_dn/subject_cn/subject_org/subject_an/
issuer_dn/issuer_cn/issuer_org/fingerprint_hash``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, json_lines, truncate

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,24}$")

#: TLS versions with no business being negotiated. Anything else is reported
#: as observed, never guessed about.
_WEAK_VERSIONS = frozenset({"ssl30", "tls10", "tls11", "sslv3", "tls1.0", "tls1.1"})

#: Cipher-name fragments that always mean a broken primitive.
_WEAK_CIPHER_TOKENS = ("rc4", "des", "3des", "md5", "null", "anon", "export")


class TlsxArgs(HostInput):
    """Validated tlsx invocation arguments."""

    ports: list[int] = Field(default_factory=lambda: [443], max_length=10)
    enumerate_versions: bool = False
    enumerate_ciphers: bool = False
    timeout: int = Field(default=5, ge=1, le=60)
    retries: int | None = Field(default=None, ge=0, le=10)
    concurrency: int | None = Field(default=None, ge=1, le=1000)
    max_findings: int = Field(default=50, ge=1, le=500)

    @field_validator("target")
    @classmethod
    def _check_host(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "://" in cleaned or "/" in cleaned or ":" in cleaned:
            raise ValueError("tlsx requires a bare host or IP, not a URL")
        if not _HOSTNAME.match(cleaned):
            import ipaddress

            try:
                ipaddress.ip_address(cleaned)
            except ValueError:
                raise ValueError("tlsx requires a valid DNS name or IP address") from None
        return cleaned

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, values: list[int]) -> list[int]:
        if not values:
            raise ValueError("at least one port is required")
        for value in values:
            if not 1 <= value <= 65535:
                raise ValueError(f"invalid port: {value}")
        return sorted(set(values))


class TlsxTool(BaseTool):
    name = "tlsx"
    phase = Phase.SCANNING
    skill = "tls_hardening"
    binary = "tlsx"
    description = (
        "Fast TLS certificate grabber: expiry, hostname match, self-signed status, "
        "negotiated version/cipher, and optional version/cipher enumeration."
    )
    input_model = TlsxArgs

    def build_argv(self, args: TlsxArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "tlsx",
            "-u",
            args.target,
            "-p",
            ",".join(str(port) for port in args.ports),
            "-j",
            "-silent",
            "-nc",
            "-duc",
            "-timeout",
            str(args.timeout),
        ]
        if args.enumerate_versions:
            argv.append("-ve")
        if args.enumerate_ciphers:
            argv.append("-ce")
        if args.retries is not None:
            argv.extend(["-retry", str(args.retries)])
        if args.concurrency is not None:
            argv.extend(["-c", str(args.concurrency)])
        return argv

    def parse(self, args: TlsxArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        now = datetime.now(timezone.utc)
        for record in json_lines(output):
            if record.get("probe_status") is False:
                continue
            host = str(record.get("host") or args.target)
            port = str(record.get("port") or (args.ports[0] if args.ports else 443))
            endpoint = f"{host}:{port}"
            tls_version = str(record.get("tls_version") or "")
            cipher = str(record.get("cipher") or "")
            common_name = str(record.get("subject_cn") or "")
            sans = [str(item) for item in (record.get("subject_an") or []) if str(item)]
            subject_dn = str(record.get("subject_dn") or "")
            issuer_dn = str(record.get("issuer_dn") or "")
            names = " ".join([common_name, *sans]).lower()
            expires = _parse_time(record.get("not_after"))
            if expires is not None and expires < now:
                findings.append(
                    self.finding(
                        title=f"TLS certificate expired for {endpoint}",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        target=args.target,
                        endpoint=endpoint,
                        evidence=truncate(f"not_after={record.get('not_after')} cipher={cipher}"),
                    )
                )
            elif expires is not None and (expires - now).days < 30:
                findings.append(
                    self.finding(
                        title=f"TLS certificate expires soon for {endpoint}",
                        severity=Severity.LOW,
                        confidence=0.9,
                        target=args.target,
                        endpoint=endpoint,
                        evidence=truncate(f"not_after={record.get('not_after')}"),
                    )
                )
            if subject_dn and issuer_dn and subject_dn == issuer_dn:
                findings.append(
                    self.finding(
                        title=f"Self-signed TLS certificate on {endpoint}",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        target=args.target,
                        endpoint=endpoint,
                        evidence=truncate(f"subject_dn={subject_dn} tls={tls_version}"),
                    )
                )
            if common_name or sans:
                wanted = args.target.lower()
                if wanted not in names.split():
                    findings.append(
                        self.finding(
                            title=f"TLS certificate hostname mismatch on {endpoint}",
                            severity=Severity.MEDIUM,
                            confidence=0.85,
                            target=args.target,
                            endpoint=endpoint,
                            evidence=truncate(f"cn={common_name} san={','.join(sans[:8])}"),
                        )
                    )
            if tls_version.lower() in _WEAK_VERSIONS:
                findings.append(
                    self.finding(
                        title=f"Weak TLS version {tls_version} on {endpoint}",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        target=args.target,
                        endpoint=endpoint,
                        evidence=truncate(f"tls_version={tls_version} cipher={cipher}"),
                    )
                )
            lowered_cipher = cipher.lower()
            if any(token in lowered_cipher for token in _WEAK_CIPHER_TOKENS):
                findings.append(
                    self.finding(
                        title=f"Weak TLS cipher on {endpoint}",
                        severity=Severity.LOW,
                        confidence=0.8,
                        target=args.target,
                        endpoint=endpoint,
                        evidence=truncate(f"cipher={cipher} tls_version={tls_version}"),
                    )
                )
            if len(findings) >= args.max_findings:
                break
        return findings[: args.max_findings]

    def observations(self, args: TlsxArgs, output: str) -> list[str]:
        count = sum(1 for _ in json_lines(output))
        return [f"tlsx: {count} TLS record(s) across {len(args.ports)} port(s)"]


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


__all__ = ["TlsxArgs", "TlsxTool"]
