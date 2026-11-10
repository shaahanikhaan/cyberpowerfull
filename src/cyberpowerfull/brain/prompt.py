"""System-prompt construction.

The prompt is the behavioural operating system of the agent: every decision, from
tool selection to vulnerability prioritisation, is governed by it. Missing
context raises immediately (StrictUndefined) instead of rendering a partial
contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from cyberpowerfull import __version__
from cyberpowerfull.brain.tda import TDAReport
from cyberpowerfull.models import Phase, utcnow
from cyberpowerfull.skills import skill_names as all_skill_names
from cyberpowerfull.templating import get_environment

PROMPT_VERSION = f"{__version__}-root-agent"
MAIN_TEMPLATE = "brain/system_prompt.jinja"


@dataclass(frozen=True)
class PromptContext:
    """Everything the root agent is allowed to know at one step."""

    target: str
    engagement: str
    phase: Phase
    step: int
    max_iterations: int
    tokens_left: int
    model: str
    scope_block: str
    memory_digest: str
    difficulty: TDAReport
    tree_digest: str
    skill_names: list[str] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    toolchain_summary: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    external_agents: list[str] = field(default_factory=list)
    allowed_actions: tuple[str, ...] = ("delegate", "terminate")
    worker_agents: tuple[str, ...] = ("recon", "scan", "validate", "external")


def _schema_hint(schema: dict[str, Any]) -> str:
    """Compress a JSON schema into one readable argument line."""
    properties: dict[str, Any] = schema.get("properties", {}) or {}
    required = set(schema.get("required", []) or [])
    parts: list[str] = []
    for name, spec in properties.items():
        if "anyOf" in spec:
            non_null = [
                option for option in spec["anyOf"] if option.get("type") not in {None, "null"}
            ]
            spec = non_null[0] if non_null else {"type": "any"}
        type_name = str(spec.get("type", "any"))
        if "enum" in spec:
            type_name = "|".join(str(value) for value in spec["enum"])
        if type_name == "array":
            items = spec.get("items", {}) or {}
            type_name = f"array<{items.get('type', 'any')}>"
        marker = "" if name in required else "?"
        default = spec.get("default")
        default_note = f"={json.dumps(default)}" if default is not None else ""
        parts.append(f"{name}{marker}:{type_name}{default_note}")
    return ", ".join(parts)


def tool_line(tool: dict[str, Any]) -> str:
    """Render one catalogue entry for the prompt."""
    install = "installed" if tool.get("installed") else "binary-missing"
    flags = [
        tool["phase"],
        f"skill={tool['skill']}",
        install,
        "external-agent" if tool.get("external") else "in-process",
        "destructive" if tool.get("destructive") else "non-destructive",
    ]
    capability = tool.get("capability")
    if capability:
        flags.append(f"requires-capability={capability}")
    return (
        f"- {tool['name']} [{', '.join(flags)}]: {tool['description']}\n"
        f"  args: {_schema_hint(tool.get('input_schema', {}))}"
    )


def build_system_prompt(ctx: PromptContext) -> str:
    """Render the complete system prompt for one step."""
    env = get_environment()
    template = env.get_template(MAIN_TEMPLATE)
    return template.render(
        prompt_version=PROMPT_VERSION,
        model=ctx.model,
        generated_at=utcnow().isoformat(),
        engagement=ctx.engagement,
        target=ctx.target,
        phase=ctx.phase.value,
        step=ctx.step,
        max_iterations=ctx.max_iterations,
        tokens_left=ctx.tokens_left,
        scope_block=ctx.scope_block,
        memory_digest=ctx.memory_digest,
        tda=ctx.difficulty.as_context(),
        tda_directive=ctx.difficulty.directive,
        difficulty_level=ctx.difficulty.level.value,
        tree_digest=ctx.tree_digest,
        toolchain_summary=ctx.toolchain_summary or ["toolchain not collected for this step"],
        capabilities=ctx.capabilities,
        external_agents=ctx.external_agents,
        tools=[tool_line(tool) for tool in ctx.tools],
        skills=list(ctx.skill_names or all_skill_names()),
        allowed_actions=list(ctx.allowed_actions),
        worker_agents=list(ctx.worker_agents),
    )


def build_step_prompt(
    ctx: PromptContext,
    *,
    node_id: str | None,
    last_result: dict[str, Any] | None = None,
    known_failures: list[str] | None = None,
) -> str:
    """Render the per-step user message (state only, no instructions in prose)."""
    state = {
        "step": ctx.step,
        "target": ctx.target,
        "phase": ctx.phase.value,
        "attack_node": node_id,
        "difficulty": ctx.difficulty.as_context(),
        "last_tool_result": last_result,
        "known_failures": known_failures or [],
        "budget": {
            "max_iterations": ctx.max_iterations,
            "tokens_left": ctx.tokens_left,
        },
    }
    return (
        "STATE\n"
        + json.dumps(state, indent=1, sort_keys=True, default=str)
        + "\n\nEmit exactly one decision JSON object with keys step, tool, args, reason. "
        "No prose, no markdown fence, no additional keys."
    )


__all__ = [
    "MAIN_TEMPLATE",
    "PROMPT_VERSION",
    "PromptContext",
    "build_step_prompt",
    "build_system_prompt",
    "tool_line",
]
