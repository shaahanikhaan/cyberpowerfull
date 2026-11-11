"""Decision backend tests: strict parsing, auto agent default, cloud refusal."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock
from urllib.error import URLError

import pytest

from cyberpowerfull.brain.agent import AutoAgent
from cyberpowerfull.brain.llm import (
    LlamaCppClient,
    ReplayClient,
    assert_local_endpoint,
    build_client,
    parse_decision,
)
from cyberpowerfull.config import ModelConfig
from cyberpowerfull.errors import LLMError


class _FakeResponse:
    def __init__(self, payload: dict | list) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        return self._body[:size] if size >= 0 else self._body


class TestEndpointPolicy:
    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://127.0.0.1:11434",
            "http://localhost:8080",
            "http://[::1]:8000",
            "http://127.0.1.5:9000",
        ],
    )
    def test_loopback_allowed(self, endpoint: str) -> None:
        assert assert_local_endpoint(endpoint) == endpoint

    @pytest.mark.parametrize(
        "endpoint",
        ["https://api.openai.com", "http://192.168.1.10:11434", "http://0.0.0.0:11434"],
    )
    def test_remote_rejected(self, endpoint: str) -> None:
        with pytest.raises(LLMError, match="non-local"):
            assert_local_endpoint(endpoint)

    def test_garbage_endpoint(self) -> None:
        with pytest.raises(LLMError, match="invalid inference endpoint"):
            assert_local_endpoint("not-a-url")

    def test_client_constructor_enforces_policy(self) -> None:
        with pytest.raises(LLMError):
            LlamaCppClient(endpoint="https://api.anthropic.com")


class TestParseDecision:
    def test_plain_json(self) -> None:
        decision = parse_decision('{"step": 1, "tool": "delegate", "args": {}, "reason": "x"}')
        assert decision.tool == "delegate"

    def test_markdown_fence(self) -> None:
        text = 'Sure\n```json\n{"tool": "terminate", "reason": "done"}\n```\ntrailing'
        decision = parse_decision(text, step=4)
        assert decision.tool == "terminate"
        assert decision.step == 4

    def test_prose_prefix_is_tolerated(self) -> None:
        decision = parse_decision('Here is the decision: {"tool": "delegate", "args": {}}')
        assert decision.tool == "delegate"

    def test_empty_response(self) -> None:
        with pytest.raises(LLMError, match="empty response"):
            parse_decision("")

    def test_no_json(self) -> None:
        with pytest.raises(LLMError, match="no JSON object"):
            parse_decision("I will scan the target now.")

    def test_broken_json(self) -> None:
        with pytest.raises(LLMError):
            parse_decision("{tool: delegate")

    def test_schema_failure(self) -> None:
        with pytest.raises(LLMError, match="schema validation"):
            parse_decision('{"args": {}}')

    def test_non_object(self) -> None:
        with pytest.raises(LLMError, match="no JSON object"):
            parse_decision("[1, 2, 3]")

    def test_step_is_forced(self) -> None:
        decision = parse_decision('{"tool": "terminate", "step": 99}', step=3)
        assert decision.step == 3


class TestAutoBackend:
    def test_health_is_always_ok(self) -> None:
        health = AutoAgent().health()
        assert health["ok"] is True
        assert health["backend"] == "auto"
        assert health["endpoint"] == "in-process"

    def test_uses_no_tokens(self) -> None:
        assert AutoAgent.uses_tokens is False

    def test_first_decision_maps_the_surface(self) -> None:
        agent = AutoAgent()
        decision = agent.decide("system", _state(step=1, target="127.0.0.1"), step=1)
        assert decision.tool == "delegate"
        assert decision.args["tool"] == "tcp_probe"
        assert decision.args["agent"] == "recon"

    def test_never_raises_on_garbage_state(self) -> None:
        decision = AutoAgent().decide("system", "not json at all", step=1)
        assert decision.tool in {"delegate", "terminate"}


def _state(*, step: int, target: str, last: dict | None = None) -> str:
    return (
        "STATE\n"
        + json.dumps(
            {
                "step": step,
                "target": target,
                "phase": "recon",
                "attack_node": None,
                "difficulty": {},
                "last_tool_result": last,
                "known_failures": [],
                "budget": {"max_iterations": 12, "tokens_left": 32000},
            }
        )
        + "\n\nEmit exactly one decision JSON object."
    )


class TestLlamaCppClient:
    def test_decide(self) -> None:
        payload = {"choices": [{"message": {"content": '{"tool": "terminate"}'}}]}
        with mock.patch(
            "cyberpowerfull.brain.llm._local_open", return_value=_FakeResponse(payload)
        ) as patched:
            decision = LlamaCppClient().decide("system", "step")
        assert decision.tool == "terminate"
        assert patched.call_args.args[0].full_url.endswith("/v1/chat/completions")

    def test_no_choices(self) -> None:
        with (
            mock.patch(
                "cyberpowerfull.brain.llm._local_open", return_value=_FakeResponse({"choices": []})
            ),
            pytest.raises(LLMError),
        ):
            LlamaCppClient(max_retries=1).decide("system", "step")

    def test_health(self) -> None:
        payload = {"data": [{"id": "local-gguf"}]}
        with mock.patch(
            "cyberpowerfull.brain.llm._local_open", return_value=_FakeResponse(payload)
        ):
            assert LlamaCppClient().health()["ok"] is True

    def test_unreachable_raises(self) -> None:
        with (
            mock.patch("cyberpowerfull.brain.llm._local_open", side_effect=URLError("refused")),
            pytest.raises(LLMError, match="unreachable"),
        ):
            LlamaCppClient(max_retries=1).decide("system", "step")

    def test_retries_then_fails(self) -> None:
        with (
            mock.patch(
                "cyberpowerfull.brain.llm._local_open", side_effect=URLError("refused")
            ) as patched,
            pytest.raises(LLMError),
        ):
            LlamaCppClient(max_retries=3).decide("system", "step")
        assert patched.call_count == 3


class TestReplayClient:
    def test_replays_in_order(self, tmp_path: Path) -> None:
        path = tmp_path / "decisions.json"
        path.write_text(
            json.dumps(
                {
                    "decisions": [
                        {"tool": "delegate", "args": {"agent": "recon"}},
                        {"tool": "terminate", "reason": "done"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        client = ReplayClient(path=path)
        assert client.remaining == 2
        assert client.decide("s", "p", step=1).step == 1
        assert client.decide("s", "p", step=2).tool == "terminate"
        exhausted = client.decide("s", "p", step=3)
        assert exhausted.tool == "terminate"
        assert exhausted.done is True

    def test_accepts_plain_list_and_prefix(self, tmp_path: Path) -> None:
        path = tmp_path / "decisions.json"
        path.write_text(json.dumps([{"tool": "terminate"}]), encoding="utf-8")
        client = ReplayClient(path=f"replay:{path}")
        assert client.health()["decisions"] == 1

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(LLMError, match="not found"):
            ReplayClient(path=tmp_path / "nope.json")

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{", encoding="utf-8")
        with pytest.raises(LLMError, match="not valid JSON"):
            ReplayClient(path=path)

    def test_invalid_shape(self, tmp_path: Path) -> None:
        path = tmp_path / "shape.json"
        path.write_text('"nope"', encoding="utf-8")
        with pytest.raises(LLMError, match="must be a list"):
            ReplayClient(path=path)

    def test_invalid_decision(self, tmp_path: Path) -> None:
        path = tmp_path / "bad_decision.json"
        path.write_text(json.dumps([{"no_tool": True}]), encoding="utf-8")
        with pytest.raises(LLMError, match="schema validation"):
            ReplayClient(path=path)


class TestBuildClient:
    def test_default_is_auto(self) -> None:
        client = build_client(None, ModelConfig())
        assert isinstance(client, AutoAgent)
        assert client.backend == "auto"

    def test_explicit_auto(self) -> None:
        assert isinstance(build_client("auto", ModelConfig()), AutoAgent)
        assert isinstance(build_client("auto:auto-1", ModelConfig()), AutoAgent)

    def test_ollama_spec_explains_removal(self) -> None:
        with pytest.raises(LLMError, match=r"removed in 5\.0"):
            build_client("ollama:qwen3:4b", ModelConfig())

    def test_llamacpp_default_endpoint(self) -> None:
        client = build_client("llamacpp:local-gguf", ModelConfig())
        assert isinstance(client, LlamaCppClient)
        assert ":8080" in client.endpoint

    def test_replay_spec(self, tmp_path: Path) -> None:
        path = tmp_path / "d.json"
        path.write_text("[]", encoding="utf-8")
        client = build_client(f"replay:{path}", ModelConfig())
        assert isinstance(client, ReplayClient)

    def test_unknown_backend(self) -> None:
        with pytest.raises(LLMError, match="unsupported decision backend"):
            build_client("openai:gpt-4o", ModelConfig())

    def test_endpoint_as_model_is_rejected(self) -> None:
        with pytest.raises(LLMError, match="not a model id"):
            build_client("llamacpp:http://127.0.0.1:8080", ModelConfig())

    def test_remote_endpoint_rejected_for_auto(self) -> None:
        config = ModelConfig(backend="auto", endpoint="http://api.example.com:11434")
        with pytest.raises(LLMError, match="non-local"):
            build_client("auto", config)

    def test_config_endpoint_respected(self) -> None:
        config = ModelConfig(backend="llamacpp", endpoint="http://127.0.0.1:9999")
        client = build_client("llamacpp:model", config)
        assert client.endpoint == "http://127.0.0.1:9999"
