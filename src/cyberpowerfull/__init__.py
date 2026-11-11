"""cyberpowerfull - a local-only autonomous penetration-testing agent.

The public surface is deliberately small: an autonomous decision engine
(:mod:`cyberpowerfull.brain`), a typed tool layer (:mod:`cyberpowerfull.tools`),
and a deterministic memory layer (:mod:`cyberpowerfull.memory`). There is no
general-purpose chat interface.
"""

from __future__ import annotations

__version__ = "5.2.0"

AGENT_NAME = "cyberpowerfull"

#: Default decision-engine id: the built-in deterministic agent. An optional
#: local model server (llama.cpp) can be selected with ``--llm llamacpp``;
#: no cloud inference exists in this project.
DEFAULT_MODEL = "auto-1"

#: Default local inference endpoint (loopback). Only used when a model
#: backend is selected; the default auto agent needs no server.
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
