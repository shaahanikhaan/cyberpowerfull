"""Native payload generator tool: the agent's own proof-vector factory."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from pydantic import Field, field_validator

from cyberpowerfull.models import Finding, Phase
from cyberpowerfull.payloads import DEFAULT_MARKER, catalog, generate, resolve_skill, skills
from cyberpowerfull.tools.base import (
    BaseTool,
    ToolStatus,
    UrlInput,
    _Exec,
    truncate,
)


class PayloadArgs(UrlInput):
    """Validated payload-generation arguments."""

    skill: str | None = Field(default=None, max_length=40)
    param: str = Field(default="q", min_length=1, max_length=40)
    marker: str = Field(default=DEFAULT_MARKER, min_length=4, max_length=32)
    ids: list[str] = Field(default_factory=list, max_length=20)
    max_payloads: int = Field(default=5, ge=1, le=25)

    @field_validator("skill")
    @classmethod
    def _known_skill(cls, value: str | None) -> str | None:
        if value is None:
            return None
        canonical = resolve_skill(value)
        if canonical not in skills():
            raise ValueError(f"unknown payload skill {value!r}; known: {', '.join(skills())}")
        return canonical

    @field_validator("marker")
    @classmethod
    def _alnum_marker(cls, value: str) -> str:
        if not value.isalnum():
            raise ValueError("marker must be alphanumeric so it survives encoding contexts")
        return value


class PayloadTool(BaseTool):
    name = "payload"
    phase = Phase.VALIDATION
    skill = "api_security"
    binary: ClassVar[str | None] = None
    timeout_s = 30
    description = (
        "Generate proof-only test vectors for one vulnerability class "
        "(sql_injection/sqli, xss, ssrf, ssti, path_traversal, open_redirect, "
        "command_injection/cmdi, xxe, jwt, idor, mass_assignment, cache_poisoning, "
        "crlf_injection, api_enumeration). Returns ready-to-send requests with the "
        "expected signal; deliver exactly one with http_probe."
    )
    input_model = PayloadArgs

    def build_argv(self, args: PayloadArgs, out_file: str | None = None) -> list[str]:
        argv = ["payload", "--target", args.target, "--param", args.param, "--marker", args.marker]
        if args.skill:
            argv.extend(["--skill", args.skill])
        if args.ids:
            argv.extend(["--ids", ",".join(args.ids)])
        return argv

    def _execute(self, args: PayloadArgs, argv: list[str], policy: Any) -> _Exec:
        try:
            rendered = generate(
                args.skill,
                target=args.target,
                param=args.param,
                marker=args.marker,
                ids=args.ids or None,
                max_payloads=args.max_payloads,
            )
        except Exception as exc:
            return _Exec(status=ToolStatus.ERROR, error=str(exc))
        payload = {
            "skill": args.skill or "all",
            "marker": args.marker,
            "count": len(rendered),
            "payloads": [item.model_dump() for item in rendered],
            "catalogue_size": len(catalog()),
        }
        return _Exec(stdout=json.dumps(payload))

    def parse(self, args: PayloadArgs, output: str, out_file: str | None = None) -> list[Finding]:
        """Generation is not evidence: the payload tool never yields findings."""
        return []

    def observations(self, args: PayloadArgs, output: str) -> list[str]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return ["payload generator produced unparsable output"]
        lines: list[str] = []
        for item in payload.get("payloads", [])[:8]:
            line = (
                f"[{item['skill']}/{item['id']}] {item['method']} {item['url']}"
                f" | expect: {item['expected_signal']}"
            )
            if item.get("body"):
                line += f" | body: {item['body']}"
            if item.get("headers"):
                line += f" | headers: {item['headers']}"
            lines.append(truncate(line, 420))
        return lines or [f"payload: no vectors generated for {args.skill!r}"]


__all__ = ["PayloadArgs", "PayloadTool"]
