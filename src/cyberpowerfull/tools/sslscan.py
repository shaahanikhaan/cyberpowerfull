"""sslscan wrapper: fast TLS protocol/cipher enumeration (XML output).

Flags verified against rbsec/sslscan (``sslscan.c`` on main, 2026-11-11):
``--xml=<file>`` writes a ``<document><ssltest>`` tree; ``-`` means stdout
but interleaves human-readable lines, so this wrapper always uses a real
output file. ``<protocol>`` carries ``type/version/enabled``; ``<cipher>``
carries ``status`` (``accepted``/``preferred``), ``sslversion``, ``bits``,
``cipher``, ``id`` and ``strength`` (``null``/``anonymous``/``weak``/
``medium``/``strong``/``acceptable``). ``<heartbleed>`` carries
``sslversion``/``vulnerable``; ``<compression>`` carries ``supported``.
Exit code is 0 on a completed scan, 1 when the target cannot be reached.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,24}$")

#: Legacy protocol versions worth a finding: (title label, severity, confidence).
_WEAK_PROTOCOLS = {
    ("ssl", "2"): ("SSLv2", Severity.HIGH, 0.9),
    ("ssl", "3"): ("SSLv3", Severity.HIGH, 0.85),
    ("tls", "1.0"): ("TLSv1.0", Severity.MEDIUM, 0.85),
    ("tls", "1.1"): ("TLSv1.1", Severity.MEDIUM, 0.85),
}

#: Accepted-cipher strength ratings worth a finding: (severity, confidence).
_WEAK_STRENGTHS = {
    "null": (Severity.CRITICAL, 0.9),
    "anonymous": (Severity.HIGH, 0.85),
    "weak": (Severity.MEDIUM, 0.8),
    "medium": (Severity.LOW, 0.7),
}


class SslscanArgs(HostInput):
    """Validated sslscan invocation arguments."""

    port: int = Field(default=443, ge=1, le=65535)
    sni: str | None = Field(default=None, max_length=253)
    show_certificate: bool = False
    max_findings: int = Field(default=40, ge=1, le=200)

    @field_validator("sni")
    @classmethod
    def _check_sni(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().lower().rstrip(".")
        if not _HOSTNAME.match(cleaned):
            raise ValueError("sni must be a valid DNS name")
        return cleaned


class SslscanTool(BaseTool):
    name = "sslscan"
    phase = Phase.SCANNING
    skill = "tls_hardening"
    binary = "sslscan"
    writes_output_file = True
    description = (
        "Fast TLS protocol and cipher enumeration. "
        "Reports legacy protocols, weak ciphers, Heartbleed and compression."
    )
    input_model = SslscanArgs

    def build_argv(self, args: SslscanArgs, out_file: str | None = None) -> list[str]:
        argv = ["sslscan", "--no-colour"]
        if out_file:
            argv.append(f"--xml={out_file}")
        if args.show_certificate:
            argv.append("--show-certificate")
        if args.sni:
            argv.append(f"--sni-name={args.sni}")
        argv.append(f"{args.target}:{args.port}")
        return argv

    def parse(self, args: SslscanArgs, output: str, out_file: str | None = None) -> list[Finding]:
        try:
            root = ET.fromstring(output.strip())
        except ET.ParseError:
            return []
        findings: list[Finding] = []

        def capped() -> bool:
            return len(findings) >= args.max_findings

        for protocol in root.iter("protocol"):
            if protocol.get("enabled") != "1":
                continue
            key = (
                str(protocol.get("type") or "").lower(),
                str(protocol.get("version") or ""),
            )
            matched = _WEAK_PROTOCOLS.get(key)
            if matched is None:
                continue
            label, severity, confidence = matched
            findings.append(
                self.finding(
                    title=f"Legacy protocol enabled: {label}",
                    severity=severity,
                    confidence=confidence,
                    target=args.target,
                    endpoint=f"{args.target}:{args.port}",
                    evidence=truncate(f"sslscan protocol type={key[0]} version={key[1]}"),
                    remediation=("Disable protocol versions below TLS 1.2 on the service."),
                )
            )
            if capped():
                return findings
        for cipher in root.iter("cipher"):
            if cipher.get("status") not in {"accepted", "preferred"}:
                continue
            strength = str(cipher.get("strength") or "").lower()
            matched_strength = _WEAK_STRENGTHS.get(strength)
            if matched_strength is None:
                continue
            severity, confidence = matched_strength
            name = str(cipher.get("cipher") or "unknown")
            findings.append(
                self.finding(
                    title=truncate(f"Weak TLS cipher accepted: {name}", 200),
                    severity=severity,
                    confidence=confidence,
                    target=args.target,
                    endpoint=f"{args.target}:{args.port}",
                    evidence=truncate(
                        "sslscan cipher="
                        f"{name} strength={strength} bits={cipher.get('bits')} "
                        f"version={cipher.get('sslversion')} id={cipher.get('id')}"
                    ),
                    remediation=(
                        "Remove null, anonymous and weak ciphers from the " "service cipher list."
                    ),
                )
            )
            if capped():
                return findings
        for heartbleed in root.iter("heartbleed"):
            if heartbleed.get("vulnerable") != "1":
                continue
            findings.append(
                self.finding(
                    title="Heartbleed vulnerability detected (CVE-2014-0160)",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    target=args.target,
                    endpoint=f"{args.target}:{args.port}",
                    evidence=truncate(
                        "sslscan heartbleed sslversion="
                        f"{heartbleed.get('sslversion')} vulnerable=1"
                    ),
                    remediation=(
                        "Upgrade OpenSSL to a fixed release, revoke and "
                        "reissue exposed certificates."
                    ),
                )
            )
        for compression in root.iter("compression"):
            if compression.get("supported") != "1":
                continue
            findings.append(
                self.finding(
                    title="TLS compression enabled (CRIME)",
                    severity=Severity.LOW,
                    confidence=0.7,
                    target=args.target,
                    endpoint=f"{args.target}:{args.port}",
                    evidence="sslscan compression supported=1",
                    remediation="Disable TLS compression on the service.",
                )
            )
            if capped():
                return findings
        return findings

    def observations(self, args: SslscanArgs, output: str) -> list[str]:
        try:
            root = ET.fromstring(output.strip())
        except ET.ParseError:
            return ["sslscan: output was not XML"]
        counts: dict[str, int] = {}
        for element in root.iter():
            tag = element.tag if isinstance(element.tag, str) else "?"
            counts[tag] = counts.get(tag, 0) + 1
        interesting = {key: counts[key] for key in ("protocol", "cipher") if key in counts}
        detail = ", ".join(f"{key}={value}" for key, value in sorted(interesting.items()))
        return [f"sslscan: {detail or 'no protocol/cipher elements'}"]


__all__ = ["SslscanArgs", "SslscanTool"]
