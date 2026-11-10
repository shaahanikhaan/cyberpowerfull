"""System prompt and skill pack tests: rendering, completeness, tone."""

from __future__ import annotations

import json
import re

import pytest
from jinja2 import UndefinedError

from cyberpowerfull.brain.prompt import (
    PROMPT_VERSION,
    PromptContext,
    build_step_prompt,
    build_system_prompt,
    tool_line,
)
from cyberpowerfull.brain.tda import TaskDifficultyAssessor, TDAInput
from cyberpowerfull.models import Phase
from cyberpowerfull.skills import (
    SKILLS,
    get_skill,
    render_skill,
    render_skills,
    skill_index,
    skill_names,
)
from cyberpowerfull.templating import get_environment
from cyberpowerfull.tools.registry import catalog

REQUIRED_SKILLS = {
    "subdomain_enum",
    "network_services",
    "tls_hardening",
    "api_security",
    "graphql",
    "deserialization",
    "cms_wordpress",
    "cloud_metadata",
    "active_directory",
    "container_kubernetes",
    "credential_testing",
    "exploit_availability",
    "external_validation",
    "authentication_jwt",
    "idor",
    "sql_injection",
    "xss",
    "ssrf",
    "csrf",
    "xxe",
    "rce",
    "business_logic",
    "race_conditions",
    "path_traversal",
    "open_redirect",
    "mass_assignment",
    "file_uploads",
    "information_disclosure",
    "subdomain_takeover",
}

CONVERSATIONAL_PATTERNS = [
    r"\bas an ai\b",
    r"\bi'm sorry\b",
    r"\bi am sorry\b",
    r"\blet me know\b",
    r"\bfeel free\b",
    r"\bhappy to help\b",
    r"\bhow can i help\b",
    r"\bchat\b",
    r"\bchatbot\b",
    r"\bfriendly\b",
    r"\bplease\b",
    r"\bthank you\b",
    r"\bassistant\b",
    r"\bhelpful ai\b",
]


@pytest.fixture
def context(scope) -> PromptContext:
    return PromptContext(
        target="127.0.0.1",
        engagement=scope.engagement,
        phase=Phase.RECON,
        step=1,
        max_iterations=12,
        tokens_left=20_000,
        model="qwen3:4b",
        scope_block=scope.prompt_block(),
        memory_digest="findings_total: 0",
        difficulty=TaskDifficultyAssessor().assess(TDAInput()),
        tree_digest="n1 [open] phase=recon score=0.85 :: map surface",
        skill_names=skill_names(),
        tools=catalog(),
    )


class TestSkillPacks:
    def test_all_required_skills_present(self) -> None:
        assert set(skill_names()) >= REQUIRED_SKILLS
        assert len(SKILLS) == 29

    def test_every_pack_renders(self) -> None:
        for name in skill_names():
            text = render_skill(name, {"target": "127.0.0.1", "difficulty_level": "low"})
            assert text.startswith("## Skill:")
            for section in ("signals:", "validation_criteria:", "evidence_required:"):
                assert section in text

    def test_render_all(self) -> None:
        text = render_skills(None, {"target": "127.0.0.1", "difficulty_level": "low"})
        assert text.count("## Skill:") == 29
        assert "---" in text

    def test_unknown_skill(self) -> None:
        from cyberpowerfull.errors import CyberpowerfullError

        with pytest.raises(CyberpowerfullError, match="unknown skill pack"):
            get_skill("buffer_overflow")

    def test_skill_index(self) -> None:
        index = skill_index()
        assert len(index) == 29
        assert {item["name"] for item in index} == set(skill_names())
        assert all(item["tools"] for item in index)

    def test_template_name(self) -> None:
        assert get_skill("idor").template_name == "skills/packs/idor.md.jinja"


class TestSystemPrompt:
    def test_renders_all_sections(self, context: PromptContext) -> None:
        prompt = build_system_prompt(context)
        for heading in (
            "## 1. root_agent_directive",
            "## 2. core_capabilities",
            "## 3. communication_rules",
            "## 4. execution_guidelines",
            "## 5. authorized_scope",
            "## 6. task_difficulty_assessment",
            "## 7. evidence_guided_attack_tree_search",
            "## 8. memory",
            "## 9. host_toolchain",
            "## 10. tool_catalogue",
            "## 11. skill_packs",
            "## 12. current_objective",
            "## 13. stop_conditions",
            "## 14. safety",
        ):
            assert heading in prompt

    def test_root_agent_restriction_is_explicit(self, context: PromptContext) -> None:
        prompt = build_system_prompt(context)
        assert "orchestration and delegation only" in prompt
        assert "permitted_actions: delegate, terminate" in prompt
        assert "executing a scanner, fuzzer, or exploit binary directly" in prompt

    def test_scope_is_injected(self, context: PromptContext) -> None:
        prompt = build_system_prompt(context)
        assert "in_scope_targets: 127.0.0.1" in prompt
        assert "scope_fingerprint:" in prompt

    def test_all_skill_packs_injected(self, context: PromptContext) -> None:
        prompt = build_system_prompt(context)
        assert prompt.count("## Skill:") == 29
        assert "difficulty_level: medium" in prompt or "difficulty_level: low" in prompt

    def test_tool_catalogue_injected(self, context: PromptContext) -> None:
        prompt = build_system_prompt(context)
        assert "- nmap [scanning" in prompt
        assert "args: target:string" in prompt

    def test_prompt_version_and_model(self, context: PromptContext) -> None:
        prompt = build_system_prompt(context)
        assert PROMPT_VERSION in prompt
        assert "model: qwen3:4b" in prompt

    def test_no_conversational_language(self, context: PromptContext) -> None:
        prompt = build_system_prompt(context)
        lowered = prompt.lower()
        for pattern in CONVERSATIONAL_PATTERNS:
            assert not re.search(pattern, lowered), f"conversational pattern found: {pattern}"

    def test_missing_context_fails_loudly(self) -> None:
        template = get_environment().get_template("brain/system_prompt.jinja")
        with pytest.raises(UndefinedError):
            template.render()

    def test_decision_contract_documented(self, context: PromptContext) -> None:
        prompt = build_system_prompt(context)
        assert "decision_schema:" in prompt
        assert "exactly one JSON object per step" in prompt


class TestStepPrompt:
    def test_is_machine_readable(self, context: PromptContext) -> None:
        prompt = build_step_prompt(context, node_id="n1", known_failures=["nmap: timeout"])
        assert prompt.startswith("STATE\n")
        payload = json.loads(prompt.split("STATE\n", 1)[1].split("\n\nEmit", 1)[0])
        assert payload["attack_node"] == "n1"
        assert payload["known_failures"] == ["nmap: timeout"]
        assert payload["difficulty"]["level"] in {"low", "medium", "high", "critical"}
        assert "Emit exactly one decision JSON object" in prompt

    def test_last_result_embedded(self, context: PromptContext) -> None:
        prompt = build_step_prompt(
            context, node_id="n1", last_result={"tool": "nmap", "status": "ok"}
        )
        assert '"tool": "nmap"' in prompt


class TestToolLine:
    def test_schema_hint_compact(self) -> None:
        entry = {tool["name"]: tool for tool in catalog()}["nmap"]
        line = tool_line(entry)
        assert line.startswith("- nmap")
        assert "ports?:string" in line
        assert "installed" in line or "binary-missing" in line

    def test_enum_rendering(self) -> None:
        entry = {tool["name"]: tool for tool in catalog()}["ffuf"]
        line = tool_line(entry)
        assert "GET" in line
