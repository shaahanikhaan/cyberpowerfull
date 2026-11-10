"""cyberpowerfull - a local-only autonomous penetration-testing agent.

The public surface is deliberately small: a model-backed reasoning loop
(:mod:`cyberpowerfull.brain`), a typed tool layer (:mod:`cyberpowerfull.tools`),
and a deterministic memory layer (:mod:`cyberpowerfull.memory`). There is no
general-purpose chat interface.
"""

from __future__ import annotations

__version__ = "4.0.0"

AGENT_NAME = "cyberpowerfull"

#: Default local open-weight model served by Ollama. No cloud inference exists in
#: this project; the transport layer refuses non-loopback endpoints.
DEFAULT_MODEL = "qwen3:4b"

#: Default local inference endpoint (Ollama).
DEFAULT_ENDPOINT = "http://127.0.0.1:11434"

#: Loopback hosts allowed as inference endpoints (no wildcard binds).
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

__all__ = [
    "AGENT_NAME",
    "DEFAULT_ENDPOINT",
    "DEFAULT_MODEL",
    "LOOPBACK_HOSTS",
    "__version__",
]
