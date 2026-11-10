"""Runtime configuration objects.

Configuration is intentionally explicit and small: paths, budgets, and the local
model specification. Values come from CLI flags first, then environment
variables, then the defaults below.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from cyberpowerfull import DEFAULT_ENDPOINT, DEFAULT_MODEL


@dataclass(frozen=True)
class ModelConfig:
    """Local inference settings. There is no cloud backend by design."""

    backend: str = "ollama"
    model: str = DEFAULT_MODEL
    endpoint: str = DEFAULT_ENDPOINT
    temperature: float = 0.1
    context_window: int = 32768
    request_timeout: int = 180
    max_retries: int = 2

    @classmethod
    def from_env(cls) -> ModelConfig:
        backend = os.environ.get("CYBERPOWERFULL_LLM_BACKEND", "ollama")
        is_llamacpp = backend.lower() in {"llamacpp", "llama.cpp", "llama_cpp", "llama-server"}
        default_endpoint = "http://127.0.0.1:8080" if is_llamacpp else DEFAULT_ENDPOINT
        return cls(
            backend=backend,
            model=os.environ.get("CYBERPOWERFULL_MODEL", DEFAULT_MODEL),
            endpoint=os.environ.get("CYBERPOWERFULL_LLM_ENDPOINT", default_endpoint),
            temperature=float(os.environ.get("CYBERPOWERFULL_TEMPERATURE", "0.1")),
            context_window=int(os.environ.get("CYBERPOWERFULL_CONTEXT_WINDOW", "32768")),
            request_timeout=int(os.environ.get("CYBERPOWERFULL_LLM_TIMEOUT", "180")),
        )

    def with_overrides(self, **kwargs: object) -> ModelConfig:
        clean = {k: v for k, v in kwargs.items() if v is not None}
        return replace(self, **clean)  # type: ignore[arg-type]


@dataclass(frozen=True)
class RunConfig:
    """Everything the orchestrator needs that is not evidence or model output."""

    scope_path: Path = Path("scope.json")
    target: str | None = None
    llm_spec: str = f"ollama:{DEFAULT_MODEL}"
    max_iterations: int = 12
    max_tokens: int = 24_000
    max_seconds: int = 900
    out_dir: Path = Path("artifacts")
    memory_path: Path = Path("artifacts/memory.sqlite3")
    trace_path: Path = Path("traces/latest.json")
    dry_run: bool = False
    verbose: bool = False

    @classmethod
    def from_env(cls) -> RunConfig:
        model = os.environ.get("CYBERPOWERFULL_MODEL", DEFAULT_MODEL)
        backend = os.environ.get("CYBERPOWERFULL_LLM_BACKEND", "ollama")
        return cls(
            scope_path=Path(os.environ.get("CYBERPOWERFULL_SCOPE", "scope.json")),
            llm_spec=os.environ.get("CYBERPOWERFULL_LLM", f"{backend}:{model}"),
            max_iterations=int(os.environ.get("CYBERPOWERFULL_MAX_ITERATIONS", "12")),
            max_tokens=int(os.environ.get("CYBERPOWERFULL_MAX_TOKENS", "24000")),
            max_seconds=int(os.environ.get("CYBERPOWERFULL_MAX_SECONDS", "900")),
        )

    def with_overrides(self, **kwargs: object) -> RunConfig:
        clean = {k: v for k, v in kwargs.items() if v is not None}
        return replace(self, **clean)  # type: ignore[arg-type]

    def ensure_dirs(self) -> None:
        self.out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.memory_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.trace_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)


@dataclass(frozen=True)
class ToolPolicy:
    """Deterministic guardrails applied around every subprocess invocation."""

    timeout_s: float = 300
    max_output_bytes: int = 2_000_000
    # None is useful for direct wrapper use; workers always set the scope limit.
    max_rps: float | None = None
    excluded_networks: tuple[str, ...] = ()
    env_deny_prefixes: tuple[str, ...] = field(
        default=(
            "OPENAI",
            "ANTHROPIC",
            "AZURE_OPENAI",
            "GOOGLE_API",
            "GEMINI",
            "AWS_",
            "AZURE_",
            "CLOUDSDK_",
            "GOOGLE_",
            "GITHUB_",
            "GITLAB_",
            "HUGGINGFACE",
            "HF_TOKEN",
        )
    )

    def sanitized_env(self, base: dict[str, str] | None = None) -> dict[str, str]:
        """Strip common cloud credentials and proxy variables from tool subprocesses.

        This is best-effort hygiene, not a network or filesystem sandbox; tools
        may have access to other credentials and configuration files.
        """
        source = dict(os.environ if base is None else base)
        clean: dict[str, str] = {}
        for key, value in source.items():
            upper = key.upper()
            if any(upper.startswith(prefix) for prefix in self.env_deny_prefixes):
                continue
            if upper in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}:
                continue
            if upper.endswith(("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")):
                continue
            clean[key] = value
        return clean


__all__ = ["ModelConfig", "RunConfig", "ToolPolicy"]
