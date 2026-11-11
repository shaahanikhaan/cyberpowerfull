"""sslyze wrapper: deep TLS scanning with explicit scan commands (JSON output).

Flags verified against nabla-c0d3/sslyze (``sslyze/plugins/*/implementation.py``
``_cli_option`` values on main, 2026-11-11): cipher suites use SHORT flags
(``--sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3``) while the JSON
document keys the same commands LONG (``ssl_2_0_cipher_suites``, ...);
vulnerability probes are ``--compression --heartbleed --openssl_ccs
--robot --fallback --reneg``. ``--json_out FILE`` writes
``SslyzeOutputAsJson`` (``server_scan_results[].scan_result.<command>`` with
``status`` in ``ERROR/COMPLETED/NOT_SCHEDULED``); the target is a
``host:port`` string and ``--sni`` overrides the SNI hostname. Exit code is
0 on success, 1 on errors.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, HostInput, truncate

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,24}$")

#: CLI flags for the fixed high-signal scan subset (short option names).
_SCAN_FLAGS = (
    "--sslv2",
    "--sslv3",
    "--tlsv1",
    "--tlsv1_1",
    "--tlsv1_2",
    "--tlsv1_3",
    "--compression",
    "--heartbleed",
    "--openssl_ccs",
    "--robot",
    "--fallback",
    "--reneg",
)

#: JSON cipher-suite keys that always deserve a finding: (label, severity, confidence).
_LEGACY_VERSIONS = {
    "ssl_2_0_cipher_suites": ("SSLv2", Severity.HIGH, 0.9),
    "ssl_3_0_cipher_suites": ("SSLv3", Severity.HIGH, 0.85),
    "tls_1_0_cipher_suites": ("TLSv1.0", Severity.MEDIUM, 0.85),
    "tls_1_1_cipher_suites": ("TLSv1.1", Severity.MEDIUM, 0.85),
}

_CIPHER_SUITE_KEYS = (
    "ssl_2_0_cipher_suites",
    "ssl_3_0_cipher_suites",
    "tls_1_0_cipher_suites",
    "tls_1_1_cipher_suites",
    "tls_1_2_cipher_suites",
    "tls_1_3_cipher_suites",
)


class SslyzeArgs(HostInput):
    """Validated sslyze invocation arguments."""

    port: int = Field(default=443, ge=1, le=65535)
    sni: str | None = Field(default=None, max_length=253)
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


class SslyzeTool(BaseTool):
    name = "sslyze"
    phase = Phase.SCANNING
    skill = "tls_hardening"
    binary = "sslyze"
    writes_output_file = True
    description = (
        "Deep TLS scan: legacy protocols, weak ciphers, compression, "
        "Heartbleed, CCS injection, ROBOT, fallback SCSV and renegotiation."
    )
    input_model = SslyzeArgs

    def build_argv(self, args: SslyzeArgs, out_file: str | None = None) -> list[str]:
        argv = ["sslyze", *_SCAN_FLAGS]
        if out_file:
            argv.extend(["--json_out", out_file])
        if args.sni:
            argv.extend(["--sni", args.sni])
        argv.append(f"{args.target}:{args.port}")
        return argv

    def parse(self, args: SslyzeArgs, output: str, out_file: str | None = None) -> list[Finding]:
        commands = _completed_commands(output)
        if commands is None:
            return []
        findings: list[Finding] = []
        endpoint = f"{args.target}:{args.port}"

        def capped() -> bool:
            return len(findings) >= args.max_findings

        seen_ciphers: set[str] = set()
        for key in _CIPHER_SUITE_KEYS:
            result = commands.get(key)
            if result is None:
                continue
            if result.get("is_tls_version_supported") is True and key in _LEGACY_VERSIONS:
                label, severity, confidence = _LEGACY_VERSIONS[key]
                findings.append(
                    self.finding(
                        title=f"Legacy protocol enabled: {label}",
                        severity=severity,
                        confidence=confidence,
                        target=args.target,
                        endpoint=endpoint,
                        evidence=truncate(f"sslyze {key} is_tls_version_supported=true"),
                        remediation="Disable protocol versions below TLS 1.2.",
                    )
                )
                if capped():
                    return findings
            accepted = result.get("accepted_cipher_suites")
            if isinstance(accepted, list):
                for entry in accepted:
                    if not isinstance(entry, dict):
                        continue
                    suite = entry.get("cipher_suite")
                    if not isinstance(suite, dict):
                        continue
                    name = str(suite.get("openssl_name") or suite.get("name") or "")
                    if not name or name in seen_ciphers:
                        continue
                    seen_ciphers.add(name)
                    if suite.get("is_anonymous") is True:
                        findings.append(
                            self.finding(
                                title=truncate(f"Anonymous TLS cipher accepted: {name}", 200),
                                severity=Severity.HIGH,
                                confidence=0.85,
                                target=args.target,
                                endpoint=endpoint,
                                evidence=truncate(f"sslyze cipher={name} anonymous=true"),
                                remediation="Disable anonymous cipher suites.",
                            )
                        )
                    else:
                        key_size = suite.get("key_size")
                        if isinstance(key_size, int) and key_size < 128:
                            findings.append(
                                self.finding(
                                    title=truncate(f"Short-key TLS cipher accepted: {name}", 200),
                                    severity=Severity.MEDIUM,
                                    confidence=0.75,
                                    target=args.target,
                                    endpoint=endpoint,
                                    evidence=truncate(f"sslyze cipher={name} key_size={key_size}"),
                                    remediation="Disable ciphers below 128-bit keys.",
                                )
                            )
                    if capped():
                        return findings
        compression = commands.get("tls_compression")
        if compression is not None and compression.get("compression_name"):
            findings.append(
                self.finding(
                    title="TLS compression enabled (CRIME)",
                    severity=Severity.LOW,
                    confidence=0.7,
                    target=args.target,
                    endpoint=endpoint,
                    evidence=truncate(
                        f"sslyze compression_name={compression.get('compression_name')}"
                    ),
                    remediation="Disable TLS compression on the service.",
                )
            )
        heartbleed = commands.get("heartbleed")
        if heartbleed is not None and heartbleed.get("is_vulnerable_to_heartbleed") is True:
            findings.append(
                self.finding(
                    title="Heartbleed vulnerability detected (CVE-2014-0160)",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    target=args.target,
                    endpoint=endpoint,
                    evidence="sslyze is_vulnerable_to_heartbleed=true",
                    remediation="Upgrade OpenSSL, revoke and reissue exposed certificates.",
                )
            )
        ccs = commands.get("openssl_ccs_injection")
        if ccs is not None and ccs.get("is_vulnerable_to_ccs_injection") is True:
            findings.append(
                self.finding(
                    title="OpenSSL CCS injection vulnerability (CVE-2014-0224)",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    target=args.target,
                    endpoint=endpoint,
                    evidence="sslyze is_vulnerable_to_ccs_injection=true",
                    remediation="Upgrade OpenSSL to a fixed release.",
                )
            )
        robot = commands.get("robot")
        if robot is not None:
            robot_result = str(robot.get("robot_result") or "")
            if robot_result == "VULNERABLE_STRONG_ORACLE":
                findings.append(
                    self.finding(
                        title="ROBOT oracle: real RSA decryption attack feasible",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        target=args.target,
                        endpoint=endpoint,
                        evidence="sslyze robot_result=VULNERABLE_STRONG_ORACLE",
                        remediation="Disable RSA key exchange cipher suites.",
                    )
                )
            elif robot_result == "VULNERABLE_WEAK_ORACLE":
                findings.append(
                    self.finding(
                        title="ROBOT oracle (weak): attack theoretically possible",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        target=args.target,
                        endpoint=endpoint,
                        evidence="sslyze robot_result=VULNERABLE_WEAK_ORACLE",
                        remediation="Disable RSA key exchange cipher suites.",
                    )
                )
        fallback = commands.get("tls_fallback_scsv")
        if fallback is not None and fallback.get("supports_fallback_scsv") is False:
            findings.append(
                self.finding(
                    title="TLS_FALLBACK_SCSV not supported (downgrade risk)",
                    severity=Severity.LOW,
                    confidence=0.7,
                    target=args.target,
                    endpoint=endpoint,
                    evidence="sslyze supports_fallback_scsv=false",
                    remediation="Enable TLS_FALLBACK_SCSV on the service.",
                )
            )
        reneg = commands.get("session_renegotiation")
        if reneg is not None:
            if reneg.get("supports_secure_renegotiation") is False:
                findings.append(
                    self.finding(
                        title="Insecure TLS renegotiation (CVE-2009-3555)",
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        target=args.target,
                        endpoint=endpoint,
                        evidence="sslyze supports_secure_renegotiation=false",
                        remediation="Enable secure renegotiation (RFC 5746).",
                    )
                )
            if reneg.get("is_vulnerable_to_client_renegotiation_dos") is True:
                findings.append(
                    self.finding(
                        title="TLS client renegotiation DoS possible",
                        severity=Severity.LOW,
                        confidence=0.7,
                        target=args.target,
                        endpoint=endpoint,
                        evidence="sslyze is_vulnerable_to_client_renegotiation_dos=true",
                        remediation="Rate-limit or disable client renegotiation.",
                    )
                )
        return findings[: args.max_findings]

    def observations(self, args: SslyzeArgs, output: str) -> list[str]:
        commands = _completed_commands(output)
        if commands is None:
            return ["sslyze: output was not a scan result document"]
        accepted = 0
        for key in _CIPHER_SUITE_KEYS:
            result = commands.get(key)
            suites = result.get("accepted_cipher_suites") if result else None
            if isinstance(suites, list):
                accepted += len(suites)
        return [
            f"sslyze: {len(commands)} completed command(s), " f"{accepted} accepted cipher suite(s)"
        ]


def _completed_commands(output: str) -> dict[str, dict[str, Any]] | None:
    """Return COMPLETED scan-command results keyed by command, if parseable."""
    try:
        document = json.loads(output.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    results = document.get("server_scan_results")
    if not isinstance(results, list) or not results:
        return None
    first = results[0]
    if not isinstance(first, dict):
        return None
    scan_result = first.get("scan_result")
    if not isinstance(scan_result, dict):
        return None
    commands: dict[str, dict[str, Any]] = {}
    for key, attempt in scan_result.items():
        if not isinstance(attempt, dict):
            continue
        if attempt.get("status") != "COMPLETED":
            continue
        result = attempt.get("result")
        if isinstance(result, dict):
            commands[str(key)] = result
    return commands


__all__ = ["SslyzeArgs", "SslyzeTool"]
