"""Typed tool layer primitives.

Every capability is a :class:`BaseTool` subclass with a Pydantic argument model,
an argv builder that never touches a shell, and a deterministic output parser
that turns tool output into :class:`~cyberpowerfull.models.Finding` objects.

The reasoning model chooses *which* tool to call and with *which* arguments; it
never builds a command line, never sees a shell, and never writes a finding.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.errors import InvalidToolArguments
from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.scope import normalize_host


class ToolStatus(str, Enum):
    """Outcome of a tool invocation, recorded in memory and traces."""

    OK = "ok"
    ERROR = "error"
    MISSING = "missing"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class ToolResult(BaseModel):
    """Structured result of one tool invocation."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    status: ToolStatus
    argv: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is ToolStatus.OK


class ToolInput(BaseModel):
    """Base argument model. Unknown keys are rejected (no free-form injection)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(min_length=1, max_length=512)


class HostInput(ToolInput):
    """Argument model for tools that take a bare host or IP address."""

    @field_validator("target")
    @classmethod
    def _normalise_host(cls, value: str) -> str:
        try:
            return normalize_host(value)
        except Exception as exc:  # ScopeError -> validation error
            raise ValueError(str(exc)) from exc


class UrlInput(ToolInput):
    """Argument model for tools that take an absolute http(s) URL."""

    @field_validator("target")
    @classmethod
    def _normalise_url(cls, value: str) -> str:
        return normalise_url(value)


def normalise_url(value: str, default_scheme: str = "https") -> str:
    """Return a validated HTTP(S) URL, rejecting ambiguous or unsafe authorities."""
    candidate = value.strip()
    if "://" not in candidate:
        # Bare IPv6 literals need brackets inside a URL.
        if candidate.count(":") > 1 and not candidate.startswith("["):
            try:
                host = normalize_host(candidate)
            except Exception as exc:
                raise ValueError(str(exc)) from exc
            candidate = f"{default_scheme}://[{host}]"
        else:
            candidate = f"{default_scheme}://{candidate}"
    try:
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"invalid HTTP(S) URL: {value!r}")
        normalize_host(candidate)
    except Exception as exc:
        raise ValueError(f"invalid HTTP(S) URL: {value!r}: {exc}") from exc
    return candidate


def host_port(host: str, port: int | str) -> str:
    """Render an unambiguous host:port, including brackets for IPv6."""
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"


@dataclass(frozen=True)
class _Exec:
    """Internal execution envelope produced by :meth:`BaseTool._execute`."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    status: ToolStatus = ToolStatus.OK
    error: str | None = None
    truncated: bool = False


def truncate(text: str, limit: int = 800) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def json_lines(text: str) -> Iterator[dict[str, Any]]:
    """Yield JSON objects from JSONL tool output, ignoring malformed lines."""
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload


class BaseTool(ABC):
    """Abstract typed tool wrapper."""

    name: ClassVar[str]
    phase: ClassVar[Phase]
    skill: ClassVar[str]
    description: ClassVar[str]
    input_model: ClassVar[type[ToolInput]]
    binary: ClassVar[str | None] = None
    timeout_s: ClassVar[int] = 300
    success_codes: ClassVar[tuple[int, ...]] = (0,)
    writes_output_file: ClassVar[bool] = False
    destructive: ClassVar[bool] = False

    # -- argument handling -------------------------------------------------
    def validate(self, raw_args: dict[str, Any]) -> ToolInput:
        """Validate raw model-supplied arguments against the Pydantic schema."""
        if not isinstance(raw_args, dict):
            raise InvalidToolArguments(f"{self.name}: arguments must be a JSON object")
        try:
            return self.input_model.model_validate(raw_args)
        except ValidationError as exc:
            raise InvalidToolArguments(f"{self.name}: invalid arguments: {exc}") from exc

    def schema(self) -> dict[str, Any]:
        return self.input_model.model_json_schema()

    # -- command construction ---------------------------------------------
    @abstractmethod
    def build_argv(self, args: ToolInput, out_file: str | None = None) -> list[str]:
        """Return the exact argv list. Never called with a shell."""

    # -- output handling ---------------------------------------------------
    def parse(self, args: ToolInput, output: str, out_file: str | None = None) -> list[Finding]:
        """Turn raw tool output into findings. Default: no findings."""
        return []

    def observations(self, args: ToolInput, output: str) -> list[str]:
        """Non-finding notes recorded in memory (raw evidence pointers)."""
        return []

    def finding(self, **kwargs: Any) -> Finding:
        kwargs.setdefault("tool", self.name)
        kwargs.setdefault("skill", self.skill)
        kwargs.setdefault("phase", self.phase)
        return Finding(**kwargs)

    # -- execution ---------------------------------------------------------
    def exit_succeeded(self, exit_code: int, stdout: str, stderr: str) -> bool:
        """Interpret a tool exit code; wrappers may inspect ambiguous output."""
        return exit_code in self.success_codes

    def _execute(self, args: ToolInput, argv: list[str], policy: ToolPolicy) -> _Exec:
        if self.binary is None:  # pragma: no cover - native tools override this
            return _Exec(status=ToolStatus.ERROR, error="native tool did not implement _execute")
        if shutil.which(self.binary) is None:
            return _Exec(
                status=ToolStatus.MISSING,
                error=f"binary not installed: {self.binary}",
            )
        try:
            # Spool process output to disk, not unbounded RAM, and read only a
            # limited excerpt after completion. The temporary files are private.
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                proc = subprocess.run(
                    argv,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=min(self.timeout_s, policy.timeout_s),
                    env=policy.sanitized_env(),
                    check=False,
                    shell=False,
                )
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout_bytes = stdout_file.read(policy.max_output_bytes + 1)
                stderr_bytes = stderr_file.read(policy.max_output_bytes + 1)
                truncated_output = (
                    len(stdout_bytes) > policy.max_output_bytes
                    or len(stderr_bytes) > policy.max_output_bytes
                )
                stdout = stdout_bytes[: policy.max_output_bytes].decode("utf-8", errors="replace")
                stderr = stderr_bytes[: policy.max_output_bytes].decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return _Exec(
                status=ToolStatus.TIMEOUT,
                error=f"{self.name} exceeded {min(self.timeout_s, policy.timeout_s):g}s",
            )
        except FileNotFoundError:
            return _Exec(status=ToolStatus.MISSING, error=f"binary not installed: {self.binary}")
        except OSError as exc:
            return _Exec(status=ToolStatus.ERROR, error=f"{self.name} failed to start: {exc}")

        status = (
            ToolStatus.OK
            if self.exit_succeeded(proc.returncode, stdout, stderr)
            else ToolStatus.ERROR
        )
        error = None
        if status is ToolStatus.ERROR:
            error = (
                f"{self.name} reported an error or incomplete output despite exit code 0"
                if proc.returncode == 0
                else f"{self.name} exit code {proc.returncode}"
            )
        if truncated_output:
            status = ToolStatus.ERROR
            error = (
                f"{self.name} output exceeded {policy.max_output_bytes} bytes; "
                "results are incomplete"
            )
        return _Exec(
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode,
            status=status,
            error=error,
            truncated=truncated_output,
        )

    def apply_policy(self, args: ToolInput, argv: list[str], policy: ToolPolicy) -> list[str]:
        """Apply per-tool rate hints; external scanners are not a network sandbox."""
        if policy.max_rps is None:
            return argv
        rate = policy.max_rps
        if not math.isfinite(rate) or rate <= 0:
            raise InvalidToolArguments("scope max_rps must be finite and positive")
        # These tools only accept an integer per-second limit. Refuse instead of
        # silently rounding a sub-one request/second limit upward.
        integer_rate_tools = {"httpx", "nuclei", "ffuf", "subfinder"}
        if self.name in integer_rate_tools and rate < 1:
            raise InvalidToolArguments(f"{self.name} cannot enforce max_rps below 1 request/second")
        if self.name == "nmap":
            argv.extend(["--max-rate", f"{rate:g}"])
        elif self.name == "nuclei":
            position = argv.index("-rl") + 1
            argv[position] = str(min(int(argv[position]), math.floor(rate)))
        elif self.name in {"httpx", "subfinder"}:
            argv.extend(["-rl", str(math.floor(rate))])
        elif self.name == "ffuf":
            argv.extend(["-rate", str(math.floor(rate))])
        elif self.name in {"sqlmap", "nikto", "dalfox"}:
            # Round up to whole milliseconds so formatting never makes the
            # requested delay shorter than the scope's minimum interval.
            milliseconds = 1000 / rate
            if not math.isfinite(milliseconds):
                raise InvalidToolArguments("scope max_rps is too small to represent a delay")
            delay_ms = math.ceil(milliseconds)
            delay_s = f"{delay_ms // 1000}.{delay_ms % 1000:03d}"
            if self.name == "sqlmap":
                argv.extend([f"--delay={delay_s}", "--threads=1"])
            elif self.name == "nikto":
                argv.extend(["-Pause", delay_s])
            else:
                # One worker avoids multiplying the inter-request delay.
                position = argv.index("--worker") + 1
                argv[position] = "1"
                argv.extend(["--delay", str(delay_ms)])
        return argv

    def run(
        self,
        raw_args: dict[str, Any],
        *,
        dry_run: bool = False,
        policy: ToolPolicy | None = None,
    ) -> ToolResult:
        """Validate, execute, and parse a single invocation."""
        policy = policy or ToolPolicy()
        started = time.perf_counter()
        try:
            args = self.validate(raw_args)
        except InvalidToolArguments as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, error=str(exc))

        tmpdir: tempfile.TemporaryDirectory[str] | None = None
        out_file: str | None = None
        if self.writes_output_file:
            tmpdir = tempfile.TemporaryDirectory(prefix=f"cpf-{self.name}-")
            out_file = str(Path(tmpdir.name) / "output.json")
        try:
            try:
                argv = self.apply_policy(args, self.build_argv(args, out_file), policy)
            except InvalidToolArguments as exc:
                return ToolResult(tool=self.name, status=ToolStatus.ERROR, error=str(exc))
            if dry_run:
                return ToolResult(
                    tool=self.name,
                    status=ToolStatus.SKIPPED,
                    argv=argv,
                    observations=["dry-run: argv constructed, nothing executed"],
                )
            exec_result = self._execute(args, argv, policy)
            output = exec_result.stdout
            observations: list[str] = []
            findings: list[Finding] = []
            file_truncated = False
            if out_file:
                path = Path(out_file)
                if path.exists():
                    with path.open("rb") as output_file:
                        file_bytes = output_file.read(policy.max_output_bytes + 1)
                        file_truncated = len(file_bytes) > policy.max_output_bytes
                        file_output = file_bytes[: policy.max_output_bytes].decode(
                            "utf-8", errors="replace"
                        )
                    if file_output.strip():
                        output = file_output
                        observations.append("parsed structured output file")
            try:
                findings = self.parse(args, output, out_file)
                observations.extend(self.observations(args, output))
            except Exception as exc:
                return ToolResult(
                    tool=self.name,
                    status=ToolStatus.ERROR,
                    argv=argv,
                    exit_code=exec_result.exit_code,
                    stdout=truncate(output, 4000),
                    stderr=truncate(exec_result.stderr, 4000),
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    error=f"output parser failed: {exc}",
                )
            inconclusive_dalfox = (
                self.name == "dalfox" and exec_result.exit_code == 1 and not findings
            )
            return ToolResult(
                tool=self.name,
                status=(
                    ToolStatus.ERROR
                    if file_truncated or inconclusive_dalfox
                    else exec_result.status
                ),
                argv=argv,
                exit_code=exec_result.exit_code,
                stdout=truncate(output, 4000),
                stderr=truncate(exec_result.stderr, 4000),
                duration_ms=int((time.perf_counter() - started) * 1000),
                findings=findings,
                observations=observations,
                error=(
                    f"{self.name} output file exceeded {policy.max_output_bytes} bytes; "
                    "results are incomplete"
                    if file_truncated
                    else (
                        "dalfox returned exit code 1 without parseable findings"
                        if inconclusive_dalfox
                        else exec_result.error
                    )
                ),
            )
        finally:
            if tmpdir is not None:
                tmpdir.cleanup()

    # -- catalogue ---------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        """Machine-readable description injected into the system prompt."""
        return {
            "name": self.name,
            "phase": self.phase.value,
            "skill": self.skill,
            "binary": self.binary or "native",
            "installed": True if self.binary is None else shutil.which(self.binary) is not None,
            "destructive": self.destructive,
            "description": self.description,
            "input_schema": self.schema(),
        }


_SEVERITY_BY_KEYWORD: tuple[tuple[str, Severity], ...] = (
    ("remote code execution", Severity.CRITICAL),
    ("sql injection", Severity.HIGH),
    ("command injection", Severity.HIGH),
    ("authentication bypass", Severity.HIGH),
    ("deserialization", Severity.HIGH),
    ("ssrf", Severity.HIGH),
    ("xxe", Severity.HIGH),
    ("xss", Severity.MEDIUM),
    ("csrf", Severity.MEDIUM),
    ("directory traversal", Severity.HIGH),
    ("path traversal", Severity.HIGH),
    ("file upload", Severity.MEDIUM),
    ("open redirect", Severity.LOW),
    ("information disclosure", Severity.LOW),
    ("outdated", Severity.LOW),
    ("admin", Severity.LOW),
    ("default", Severity.LOW),
)

_CWE_PATTERN = re.compile(r"CWE-(\d{1,4})", re.IGNORECASE)
_CVE_PATTERN = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)


def severity_from_text(text: str) -> Severity:
    """Deterministic keyword-to-severity mapping used by text parsers."""
    lowered = text.lower()
    best = Severity.INFO
    for keyword, severity in _SEVERITY_BY_KEYWORD:
        if keyword in lowered and severity.rank > best.rank:
            best = severity
    return best


def extract_identifiers(text: str) -> tuple[str | None, str | None]:
    """Return the first CWE and CVE identifiers found in free text."""
    cwe_match = _CWE_PATTERN.search(text)
    cve_match = _CVE_PATTERN.search(text)
    cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else None
    cve = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}" if cve_match else None
    return cwe, cve


__all__ = [
    "BaseTool",
    "HostInput",
    "ToolInput",
    "ToolResult",
    "ToolStatus",
    "UrlInput",
    "extract_identifiers",
    "host_port",
    "json_lines",
    "normalise_url",
    "severity_from_text",
    "truncate",
]
