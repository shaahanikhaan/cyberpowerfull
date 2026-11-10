"""Decision backends for the reasoning loop.

Three backends are supported:

* ``auto``           - the built-in deterministic agent (default; no server)
* ``llamacpp:model`` - llama.cpp ``llama-server`` OpenAI-compatible API
* ``replay:path.json`` - deterministic replay of a recorded decision stream

Model traffic, when used at all, talks to loopback only. Cloud endpoints are
rejected before a single byte is sent: this agent has no API-key path, and
none will be added.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass, field
from http.client import HTTPException
from pathlib import Path
from typing import Any, ClassVar, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from pydantic import ValidationError

from cyberpowerfull import DEFAULT_ENDPOINT
from cyberpowerfull.config import ModelConfig
from cyberpowerfull.errors import LLMError
from cyberpowerfull.models import Decision

DEFAULT_ENDPOINTS: dict[str, str] = {
    "llamacpp": "http://127.0.0.1:8080",
}

_JSON_FENCE = re.compile(r"```(?:json)?\s*(?P<body>.*?)```", re.DOTALL)


def is_loopback_host(host: str) -> bool:
    """True for ``localhost`` and any address in the 127.0.0.0/8 / ::1 range."""
    if host.lower() in {"localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_local_endpoint(endpoint: str) -> str:
    """Reject any inference endpoint that is not loopback."""
    try:
        parsed = urlparse(endpoint)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        if (
            parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or port == 0
            or any(ord(ch) <= 32 or ord(ch) == 127 for ch in endpoint)
        ):
            raise ValueError("invalid endpoint authority")
    except ValueError as exc:
        raise LLMError(f"invalid inference endpoint: {endpoint!r}") from exc
    if not is_loopback_host(host):
        raise LLMError(
            f"refusing non-local inference endpoint {host!r}: this agent runs local models only "
            "(127.0.0.1 / localhost / ::1)"
        )
    return endpoint.rstrip("/")


def parse_decision(text: str, *, step: int = 0) -> Decision:
    """Parse one decision object out of model output, strictly."""
    if not text or not text.strip():
        raise LLMError("model returned an empty response")
    candidate = text.strip()
    fence = _JSON_FENCE.search(candidate)
    if fence:
        candidate = fence.group("body").strip()
    start = candidate.find("{")
    if start == -1:
        raise LLMError(f"model output contains no JSON object: {text[:200]!r}")
    try:
        payload, _ = json.JSONDecoder().raw_decode(candidate[start:])
    except json.JSONDecodeError as exc:
        raise LLMError(f"model output is not valid JSON: {exc}: {text[:200]!r}") from exc
    if not isinstance(payload, dict):
        raise LLMError("model output must be a JSON object")
    payload["step"] = step
    try:
        return Decision.model_validate(payload)
    except ValidationError as exc:
        raise LLMError(f"model decision failed schema validation: {exc}") from exc


class LLMClient(Protocol):
    """Minimal interface every decision backend implements."""

    backend: str
    model: str

    def decide(self, system_prompt: str, step_prompt: str, *, step: int = 0) -> Decision:
        """Return exactly one validated :class:`Decision`."""

    def health(self) -> dict[str, Any]:
        """Return backend reachability information for ``--check``."""


class _NoRedirect(HTTPRedirectHandler):
    """Never allow a local model server to redirect prompt data elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "inference redirects are disabled", headers, fp)


def _local_open(request: Request | str, *, timeout: float):
    """Open without proxies or redirects; pin localhost to a loopback address."""
    if isinstance(request, str):
        request = Request(request)
    parts = urlsplit(request.full_url)
    assert_local_endpoint(urlunsplit((parts.scheme, parts.netloc, "", "", "")))
    if parts.hostname and parts.hostname.lower() == "localhost":
        netloc = "127.0.0.1" + (f":{parts.port}" if parts.port else "")
        request = Request(
            urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)),
            data=request.data,
            headers={**dict(request.header_items()), "Host": parts.netloc},
            method=request.get_method(),
        )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    return opener.open(request, timeout=timeout)


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with _local_open(request, timeout=timeout) as response:
            body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise LLMError("inference response exceeds 2 MB")
            raw = body.decode("utf-8", errors="replace")
    except HTTPError as exc:  # pragma: no cover - depends on server behaviour
        raise LLMError(f"inference HTTP error {exc.code} from {url}") from exc
    except URLError as exc:
        raise LLMError(
            f"inference endpoint unreachable: {url} ({exc.reason}). Start the local model "
            "server first (for example: llama-server -m model.gguf), or drop --llm to "
            "use the built-in auto agent"
        ) from exc
    except TimeoutError as exc:
        raise LLMError(f"inference request to {url} timed out") from exc
    except (OSError, HTTPException) as exc:
        raise LLMError(f"inference connection to {url} failed: {exc}") from exc
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"inference endpoint returned non-JSON body: {raw[:200]!r}") from exc
    if not isinstance(result, dict):
        raise LLMError("inference endpoint returned a JSON value that is not an object")
    return result


def _get_json(url: str, timeout: int) -> dict[str, Any]:
    try:
        with _local_open(url, timeout=timeout) as response:
            body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise LLMError("inference response exceeds 2 MB")
            raw = body.decode("utf-8", errors="replace")
    except (OSError, HTTPException) as exc:
        raise LLMError(f"inference endpoint unreachable: {url} ({exc})") from exc
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"inference endpoint returned non-JSON body: {raw[:200]!r}") from exc
    if not isinstance(result, dict):
        raise LLMError("inference endpoint returned a JSON value that is not an object")
    return result


def _request_timeout(timeout: float, deadline: float | None) -> float:
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LLMError("run time budget exhausted before inference request")
    return min(timeout, remaining)


@dataclass
class LlamaCppClient:
    """llama.cpp ``llama-server`` OpenAI-compatible backend."""

    model: str = "local-model"
    endpoint: str = DEFAULT_ENDPOINTS["llamacpp"]
    temperature: float = 0.1
    context_window: int = 32768
    timeout: int = 180
    max_retries: int = 2
    deadline: float | None = field(default=None, repr=False)
    backend: ClassVar[str] = "llamacpp"

    def __post_init__(self) -> None:
        self.endpoint = assert_local_endpoint(self.endpoint)

    def set_deadline(self, deadline: float) -> None:
        self.deadline = deadline

    def decide(self, system_prompt: str, step_prompt: str, *, step: int = 0) -> Decision:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": step_prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": 512,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        last_error: Exception | None = None
        for _ in range(max(1, self.max_retries)):
            try:
                data = _post_json(
                    f"{self.endpoint}/v1/chat/completions",
                    payload,
                    _request_timeout(self.timeout, self.deadline),
                )
                choices = data.get("choices")
                if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                    raise LLMError("llama.cpp returned no choices")
                message = choices[0].get("message")
                if not isinstance(message, dict):
                    raise LLMError("llama.cpp response has no message object")
                return parse_decision(str(message.get("content") or ""), step=step)
            except LLMError as exc:
                last_error = exc
        raise LLMError(str(last_error) if last_error else "llama.cpp inference failed")

    def health(self) -> dict[str, Any]:
        try:
            data = _get_json(f"{self.endpoint}/v1/models", min(self.timeout, 10))
        except LLMError as exc:
            return {
                "ok": False,
                "backend": self.backend,
                "endpoint": self.endpoint,
                "error": str(exc),
            }
        models = data.get("data")
        if not isinstance(models, list):
            return {"ok": False, "backend": self.backend, "error": "invalid llama.cpp model list"}
        return {
            "ok": bool(models),
            "backend": self.backend,
            "endpoint": self.endpoint,
            "models": [str(item.get("id", "")) for item in models if isinstance(item, dict)][:20],
        }


@dataclass
class ReplayClient:
    """Deterministic replay of a recorded decision stream.

    This is not a reasoning engine: it feeds previously recorded decisions back
    to the orchestrator so a run can be reproduced exactly (tests, CI, audits).
    """

    path: str | Path
    model: str = "replay"
    backend: ClassVar[str] = "replay"
    _decisions: list[Decision] = field(default_factory=list, repr=False)
    _index: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.path, str) and self.path.startswith("replay:"):
            self.path = self.path.split(":", 1)[1]
        file_path = Path(self.path)
        if not file_path.exists():
            raise LLMError(f"replay stream not found: {file_path}")
        try:
            raw = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise LLMError(f"replay stream is not valid JSON: {file_path}: {exc}") from exc
        except (OSError, UnicodeError) as exc:
            raise LLMError(f"replay stream could not be read: {file_path}: {exc}") from exc
        items = raw.get("decisions") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            raise LLMError("replay stream must be a list or {'decisions': [...]}")
        for item in items:
            if not isinstance(item, dict):
                raise LLMError("replay decisions must be JSON objects")
            try:
                self._decisions.append(Decision.model_validate(item))
            except ValidationError as exc:
                raise LLMError(f"replay decision failed schema validation: {exc}") from exc

    @property
    def remaining(self) -> int:
        return max(len(self._decisions) - self._index, 0)

    def decide(self, system_prompt: str, step_prompt: str, *, step: int = 0) -> Decision:
        if self._index >= len(self._decisions):
            return Decision(
                step=step,
                tool="terminate",
                reason="replay stream exhausted",
                done=True,
            )
        decision = self._decisions[self._index].model_copy(update={"step": step})
        self._index += 1
        return decision

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "backend": self.backend,
            "model": self.model,
            "decisions": len(self._decisions),
            "remaining": self.remaining,
        }


def build_client(spec: str | None = None, config: ModelConfig | None = None) -> LLMClient:
    """Build a decision backend from an ``auto`` / ``backend[:model]`` spec."""
    try:
        cfg = config or ModelConfig.from_env()
    except (TypeError, ValueError) as exc:
        raise LLMError(f"invalid local inference configuration: {exc}") from exc
    if cfg.request_timeout <= 0 or cfg.context_window <= 0 or cfg.max_retries <= 0:
        raise LLMError("inference timeout, context window and retry count must be positive")
    spec = (spec or f"{cfg.backend}:{cfg.model}").strip()
    if spec.startswith("replay:"):
        return ReplayClient(path=spec.split(":", 1)[1])
    backend, _, model = spec.partition(":")
    backend = (backend or cfg.backend).lower()
    aliases = {"llama.cpp", "llama_cpp", "llama-server"}
    if backend in aliases:
        backend = "llamacpp"
    configured_backend = "llamacpp" if cfg.backend.lower() in aliases else cfg.backend.lower()
    if "://" in model:
        # ``llamacpp:http://host:8080`` is a common slip: the endpoint is a config
        # value (CYBERPOWERFULL_LLM_ENDPOINT / ModelConfig), not part of the model id.
        # Silently using the URL as a model name would look like it worked.
        raise LLMError(
            f"{model!r} is an endpoint, not a model id: pass a model name after the colon "
            f"and set the endpoint with CYBERPOWERFULL_LLM_ENDPOINT "
            f"(loopback only, currently {cfg.endpoint!r})"
        )
    if backend == "auto":
        # The agent itself needs no endpoint, but a remote endpoint in the
        # environment is still a misconfiguration worth failing fast on.
        assert_local_endpoint(cfg.endpoint)
        from cyberpowerfull.brain.agent import AutoAgent

        return AutoAgent()
    if backend == "ollama":
        raise LLMError(
            "the Ollama backend was removed in 5.0: drop --llm to use the built-in "
            "auto agent (no server needed), or point --llm at a local llama-server "
            "with 'llamacpp[:model]'"
        )
    model = model or cfg.model
    configured_default = DEFAULT_ENDPOINTS.get(configured_backend, DEFAULT_ENDPOINT)
    explicit_env_endpoint = config is None and "CYBERPOWERFULL_LLM_ENDPOINT" in os.environ
    if backend == configured_backend or explicit_env_endpoint or cfg.endpoint != configured_default:
        endpoint = cfg.endpoint
    else:
        endpoint = DEFAULT_ENDPOINTS.get(backend, cfg.endpoint)
    if backend == "llamacpp":
        return LlamaCppClient(
            model=model,
            endpoint=endpoint,
            temperature=cfg.temperature,
            context_window=cfg.context_window,
            timeout=cfg.request_timeout,
            max_retries=cfg.max_retries,
        )
    raise LLMError(
        f"unsupported decision backend {backend!r}; use auto, llamacpp, or replay:<path>"
    )


__all__ = [
    "DEFAULT_ENDPOINTS",
    "LLMClient",
    "LlamaCppClient",
    "ReplayClient",
    "assert_local_endpoint",
    "build_client",
    "is_loopback_host",
    "parse_decision",
]
