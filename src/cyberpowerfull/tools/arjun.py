"""arjun wrapper: hidden HTTP parameter discovery."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, UrlInput, truncate

_PRIVILEGED = (
    "admin",
    "debug",
    "role",
    "is_admin",
    "internal",
    "token",
    "secret",
    "test",
    "dev",
    "redirect",
    "url",
    "file",
    "cmd",
)


class ArjunArgs(UrlInput):
    """Validated arjun invocation arguments."""

    method: Literal["GET", "POST", "JSON"] = "GET"
    threads: int = Field(default=8, ge=1, le=20)
    wordlist: str | None = Field(default=None, max_length=400)


class ArjunTool(BaseTool):
    name = "arjun"
    phase = Phase.SCANNING
    skill = "api_security"
    binary = "arjun"
    writes_output_file = True
    success_codes = (0,)
    timeout_s = 600
    description = (
        "Discovers hidden query/body parameters that are accepted but undocumented. "
        "Privileged-sounding parameters become low-severity findings for follow-up."
    )
    input_model = ArjunArgs

    def build_argv(self, args: ArjunArgs, out_file: str | None = None) -> list[str]:
        argv = [
            "arjun",
            "-u",
            args.target,
            "-m",
            args.method,
            "-t",
            str(args.threads),
            "-oJ",
            out_file or "-",
            "-q",
        ]
        if args.wordlist:
            argv.extend(["-w", args.wordlist])
        return argv

    def parse(self, args: ArjunArgs, output: str, out_file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for url, params in _iter_results(output):
            for name in params:
                lowered = str(name).lower()
                privileged = any(token in lowered for token in _PRIVILEGED)
                findings.append(
                    self.finding(
                        title=f"Hidden parameter accepted: {name}",
                        severity=Severity.LOW if privileged else Severity.INFO,
                        confidence=0.65,
                        target=args.target,
                        endpoint=url or args.target,
                        evidence=truncate(f"arjun method={args.method} url={url} parameter={name}"),
                    )
                )
        return findings

    def observations(self, args: ArjunArgs, output: str) -> list[str]:
        results = list(_iter_results(output))
        total = sum(len(params) for _url, params in results)
        return [f"arjun: {total} parameter(s) across {len(results)} URL(s)"]


def _iter_results(output: str) -> list[tuple[str, list[str]]]:
    text = output.strip()
    if not text:
        return []
    candidates = [text]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            payload: Any = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        results: list[tuple[str, list[str]]] = []
        for url, value in payload.items():
            if isinstance(value, list):
                params = [str(item) for item in value]
            elif isinstance(value, dict):
                raw = value.get("params") or value.get("parameters") or []
                params = [str(item) for item in raw] if isinstance(raw, list) else []
            else:
                continue
            if params:
                results.append((str(url), params))
        return results
    return []


__all__ = ["ArjunArgs", "ArjunTool"]
