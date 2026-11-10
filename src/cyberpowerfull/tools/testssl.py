"""testssl.sh wrapper: TLS/SSL configuration assessment (JSON output).

Flag and output semantics verified against the testssl.sh v3.2.5 source
(``testssl/testssl.sh`` tag ``v3.2.5``):

* single checks are ``-p`` (protocols), ``-S`` (server defaults), ``-U``
  (vulnerabilities), ``-h`` (headers); no check flag runs everything except
  ``-E``/``-g``. ``-t`` is *not* a check -- it is ``--starttls <protocol>``
  and consumes the next argument, so it must never be emitted bare.
* ``--severity LOW|MEDIUM|HIGH|CRITICAL`` filters the JSON findings.
* ``--warnings batch|off``, ``--quiet``, ``--color 0..3`` as documented.
* ``--jsonfile`` writes a file (or a directory+generated name); ``-`` is a
  literal filename, never stdout -- so an output file is always required.
* flat JSON records carry ``id``, ``ip`` (``NODE/NODEIP``), ``port``,
  ``severity``, ``cve``, ``cwe``, ``finding`` (plus ``hint`` with hints on).
* severities are ``OK INFO LOW MEDIUM HIGH CRITICAL WARN FATAL``; ``FATAL``
  and the ``scanTime``/``scanProblem`` ids are testssl's own telemetry, not
  target facts, and are skipped.
* exit ``0`` means the scan completed; ``1`` is a usage error and
  ``242-254`` are tool failures -- only ``0`` counts as success.
* upstream sets no connect/openssl timeouts, so bounded ones are passed to
  stop a filtered port from hanging the run.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import Field

from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_SKIP_SEVERITIES = {"ok", "info", "debug", "fatal"}
_SKIP_IDS = {"scantime", "scanproblem"}

_CheckName = Literal["protocols", "server_defaults", "vulnerabilities", "headers", "full"]

_CHECK_FLAGS: dict[str, str | None] = {
    "protocols": "-p",
    "server_defaults": "-S",
    "vulnerabilities": "-U",
    "headers": "-h",
    "full": None,
}

_StarttlsProtocol = Literal[
    "ftp",
    "smtp",
    "lmtp",
    "pop3",
    "imap",
    "sieve",
    "xmpp",
    "xmpp-server",
    "telnet",
    "ldap",
    "irc",
    "nntp",
    "postgres",
    "mysql",
]


class TestsslArgs(UrlInput):
    """Validated testssl.sh invocation arguments."""

    check: _CheckName = "protocols"
    severity_floor: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    starttls: _StarttlsProtocol | None = None
    connect_timeout: int = Field(default=10, ge=2, le=120)
    openssl_timeout: int = Field(default=10, ge=2, le=120)
    max_findings: int = Field(default=60, ge=1, le=200)


class TestsslTool(BaseTool):
    name = "testssl"
    phase = Phase.SCANNING
    skill = "tls_hardening"
    binary = "testssl.sh"
    binary_alternatives = ("testssl",)
    writes_output_file = True
    success_codes = (0,)
    timeout_s = 900
    description = (
        "TLS configuration assessment: protocol versions, cipher suites, "
        "certificate validity and known TLS vulnerabilities, parsed from JSON."
    )
    input_model = TestsslArgs

    def build_argv(self, args: TestsslArgs, out_file: str | None = None) -> list[str]:
        if not out_file:
            raise InvalidToolArguments(
                "testssl requires an output file: --jsonfile writes a file, "
                "never stdout, so there is no safe default"
            )
        argv = [
            "testssl.sh",
            "--jsonfile",
            out_file,
            "--quiet",
            "--color",
            "0",
            "--severity",
            args.severity_floor,
            "--warnings",
            "batch",
            "--connect-timeout",
            str(args.connect_timeout),
            "--openssl-timeout",
            str(args.openssl_timeout),
        ]
        flag = _CHECK_FLAGS[args.check]
        if flag is not None:
            argv.append(flag)
        if args.starttls is not None:
            argv.extend(["-t", args.starttls])
        argv.append(args.target)
        return argv

    def parse(self, args: TestsslArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for record in _load(output):
            severity_raw = str(record.get("severity") or "").strip()
            finding_id = str(record.get("id") or "TLS").strip()
            if severity_raw.lower() in _SKIP_SEVERITIES:
                continue
            if finding_id.lower() in _SKIP_IDS:
                continue
            detail = str(record.get("finding") or "").strip()
            if not detail or detail.lower().startswith("not tested"):
                continue
            if severity_raw.upper() == "WARN":
                severity = Severity.MEDIUM
            else:
                severity = Severity.coerce(severity_raw)
            findings.append(
                self.finding(
                    title=truncate(f"TLS issue {finding_id}: {detail}", 220),
                    severity=severity,
                    confidence=0.85,
                    target=args.target,
                    endpoint=args.target,
                    evidence=truncate(
                        f"testssl id={finding_id} severity={severity_raw} "
                        f"finding={detail} ip={record.get('ip')} port={record.get('port')} "
                        f"cve={record.get('cve')} cwe={record.get('cwe')}"
                    ),
                    cve=str(record["cve"]) if record.get("cve") else None,
                    cwe=str(record["cwe"]) if record.get("cwe") else None,
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: TestsslArgs, output: str) -> list[str]:
        records = _load(output)
        return [f"testssl: {len(records)} check(s) parsed for {args.target}"]


def _load(output: str) -> list[dict[str, Any]]:
    text = output.strip()
    if not text:
        return []
    candidates = [text]
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            payload = payload.get("scanResult") or [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
    return []


__all__ = ["TestsslArgs", "TestsslTool"]
