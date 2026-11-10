"""Layer 1: the model-backed reasoning brain.

Submodules are imported explicitly by callers so that the prompt/skill templating
layer never creates an import cycle:

* :mod:`cyberpowerfull.brain.llm` - local-only inference transport
* :mod:`cyberpowerfull.brain.tda` - task difficulty assessment
* :mod:`cyberpowerfull.brain.attack_tree` - EGATS state
* :mod:`cyberpowerfull.brain.prompt` - Jinja2 system prompt
* :mod:`cyberpowerfull.brain.orchestrator` - root/worker orchestration loop
"""

from __future__ import annotations

__all__: list[str] = []
