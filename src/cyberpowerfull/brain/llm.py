"""Local-only inference transport.

Three backends are supported and every one of them talks to loopback only:

* ``ollama:qwen3:4b``  - Ollama HTTP API (default)
* ``llamacpp:model``   - llama.cpp ``llama-server`` OpenAI-compatible API
* ``replay:path.json`` - deterministic replay of a recorded decision stream

Cloud endpoints are rejected before a single byte is sent: this agent has no
API-key path, and none will be added.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from pydantic import ValidationError

from cyberpowerfull import DEFAULT_ENDPOINT, DEFAULT_MODEL
from cyberpowerfull.config import ModelConfig
from cyberpowerfull.errors import LLMError
from cyberpowerfull.models import Decision

DEFAULT_ENDPOINTS: dict[str, str] = {
    "ollama": DEFAULT_ENDPOINT,
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
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise LLMError(f"invalid inference endpoint: {endpoint!r}")
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
    """Minimal interface every local backend implements."""

    backend: str
    model: str

    def decide(self, system_prompt: str, step_prompt: str, *, step: int = 0) -> Decision:
        """Return exactly one validated :class:`Decision`."""

    def health(self) -> dict[str, Any]:
        """Return backend reachability information for ``--check``."""


def _post_json(url: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:  # pragma: no cover - depends on server behaviour
        raise LLMError(f"inference HTTP error {exc.code} from {url}") from exc
    except URLError as exc:
        raise LLMError(
            f"inference endpoint unreachable: {url} ({exc.reason}). Start the local model server "
            "first (for example: ollama serve && ollama pull qwen3:4b)"
        ) from exc
    except TimeoutError as exc:
        raise LLMError(f"inference request to {url} timed out") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"inference endpoint returned non-JSON body: {raw[:200]!r}") from exc


def _get_json(url: str, timeout: int) -> dict[str, Any]:
    try:
        with urlopen(url, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError) as exc:
        raise LLMError(f"inference endpoint unreachable: {url} ({exc})") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - server specific
        raise LLMError(f"inference endpoint returned non-JSON body: {raw[:200]!r}") from exc


@dataclass
class OllamaClient:
    """Ollama ``/api/chat`` backend."""

    model: str = DEFAULT_MODEL
    endpoint: str = DEFAULT_ENDPOINT
    temperature: float = 0.1
    context_window: int = 32768
    timeout: int = 180
    max_retries: int = 2
    backend: ClassVar[str] = "ollama"

    def __post_init__(self) -> None:
        self.endpoint = assert_local_endpoint(self.endpoint)

    def decide(self, system_prompt: str, step_prompt: str, *, step: int = 0) -> Decision:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": step_prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.context_window,
                "num_predict": 512,
            },
        }
        last_error: Exception | None = None
        for _ in range(max(1, self.max_retries)):
            try:
                data = _post_json(f"{self.endpoint}/api/chat", payload, self.timeout)
            except LLMError as exc:
                last_error = exc
                continue
            message = data.get("message") or {}
            content = str(message.get("content") or "")
            return parse_decision(content, step=step)
        raise LLMError(str(last_error) if last_error else "ollama inference failed")

    def health(self) -> dict[str, Any]:
        try:
            data = _get_json(f"{self.endpoint}/api/tags", min(self.timeout, 10))
        except LLMError as exc:
            return {
                "ok": False,
                "backend": self.backend,
                "endpoint": self.endpoint,
                "error": str(exc),
            }
        models = [str(item.get("name", "")) for item in data.get("models", [])]
        return {
            "ok": self.model in models
            or any(m.split(":")[0] == self.model.split(":")[0] for m in models),
            "backend": self.backend,
            "endpoint": self.endpoint,
            "model": self.model,
            "models": models[:20],
        }


@dataclass
class LlamaCppClient:
    """llama.cpp ``llama-server`` OpenAI-compatible backend."""

    model: str = DEFAULT_MODEL
    endpoint: str = DEFAULT_ENDPOINTS["llamacpp"]
    temperature: float = 0.1
    context_window: int = 32768
    timeout: int = 180
    max_retries: int = 2
    backend: ClassVar[str] = "llamacpp"

    def __post_init__(self) -> None:
        self.endpoint = assert_local_endpoint(self.endpoint)

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
                data = _post_json(f"{self.endpoint}/v1/chat/completions", payload, self.timeout)
            except LLMError as exc:
                last_error = exc
                continue
            choices = data.get("choices") or []
            if not choices:
                last_error = LLMError("llama.cpp returned no choices")
                continue
            message = choices[0].get("message") or {}
            return parse_decision(str(message.get("content") or ""), step=step)
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
        return {
            "ok": bool(data.get("data")),
            "backend": self.backend,
            "endpoint": self.endpoint,
            "models": [str(item.get("id", "")) for item in data.get("data", [])][:20],
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
    """Build a local client from a ``backend[:model]`` / ``replay:path`` spec."""
    cfg = config or ModelConfig.from_env()
    spec = (spec or f"{cfg.backend}:{cfg.model}").strip()
    if spec.startswith("replay:"):
        return ReplayClient(path=spec.split(":", 1)[1])
    backend, _, model = spec.partition(":")
    backend = (backend or cfg.backend).lower()
    model = model or cfg.model
    endpoint = (
        cfg.endpoint if backend == cfg.backend else DEFAULT_ENDPOINTS.get(backend, cfg.endpoint)
    )
    if backend == "ollama":
        return OllamaClient(
            model=model,
            endpoint=endpoint,
            temperature=cfg.temperature,
            context_window=cfg.context_window,
            timeout=cfg.request_timeout,
            max_retries=cfg.max_retries,
        )
    if backend in {"llamacpp", "llama.cpp", "llama_cpp", "llama-server"}:
        return LlamaCppClient(
            model=model,
            endpoint=endpoint if backend == "llamacpp" else DEFAULT_ENDPOINTS["llamacpp"],
            temperature=cfg.temperature,
            context_window=cfg.context_window,
            timeout=cfg.request_timeout,
            max_retries=cfg.max_retries,
        )
    raise LLMError(
        f"unsupported inference backend {backend!r}; use ollama, llamacpp, or replay:<path>"
    )


__all__ = [
    "DEFAULT_ENDPOINTS",
    "LLMClient",
    "LlamaCppClient",
    "OllamaClient",
    "ReplayClient",
    "assert_local_endpoint",
    "build_client",
    "is_loopback_host",
    "parse_decision",
]
