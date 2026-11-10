"""Core model and configuration tests."""

from __future__ import annotations

from pathlib import Path

from cyberpowerfull.config import ModelConfig, RunConfig, ToolPolicy
from cyberpowerfull.models import (
    BudgetState,
    Decision,
    Finding,
    Phase,
    Severity,
    estimate_tokens,
    new_id,
)


class TestSeverity:
    def test_ranking(self) -> None:
        assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank

    def test_coerce_aliases(self) -> None:
        assert Severity.coerce("moderate") is Severity.MEDIUM
        assert Severity.coerce("Informational") is Severity.INFO
        assert Severity.coerce("unknown-value") is Severity.INFO
        assert Severity.coerce(None) is Severity.INFO
        assert Severity.coerce("critical") is Severity.CRITICAL


class TestFindingAndDecision:
    def test_finding_defaults(self) -> None:
        finding = Finding(title="Open port", target="127.0.0.1", severity=Severity.LOW)
        assert finding.id.startswith("f-")
        assert finding.phase is Phase.RECON
        assert finding.verified is False

    def test_decision_requires_tool(self) -> None:
        decision = Decision(tool="delegate", args={"agent": "recon"})
        assert decision.step == 0
        assert decision.args["agent"] == "recon"

    def test_new_id_prefix(self) -> None:
        assert new_id("run-").startswith("run-")
        assert new_id() != new_id()


class TestBudget:
    def test_exhaustion_order(self) -> None:
        budget = BudgetState(max_iterations=1, max_tokens=10, max_seconds=1)
        assert budget.exhausted() is None
        budget.iterations = 1
        assert budget.exhausted() == "iterations"

        tokens = BudgetState(max_iterations=5, max_tokens=10, max_seconds=10)
        tokens.tokens_used = 11
        assert tokens.exhausted() == "tokens"

        seconds = BudgetState(max_iterations=5, max_tokens=10, max_seconds=10)
        seconds.seconds_used = 11
        assert seconds.exhausted() == "seconds"

    def test_left_properties_never_negative(self) -> None:
        budget = BudgetState(max_iterations=1, max_tokens=1, iterations=5, tokens_used=9)
        assert budget.iterations_left == 0
        assert budget.tokens_left == 0

    def test_estimate_tokens(self) -> None:
        assert estimate_tokens("a" * 40) == 10
        assert estimate_tokens("") == 1


class TestConfig:
    def test_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("CYBERPOWERFULL_MODEL", "qwen3:1.7b")
        monkeypatch.setenv("CYBERPOWERFULL_LLM_BACKEND", "llamacpp")
        monkeypatch.setenv("CYBERPOWERFULL_MAX_ITERATIONS", "3")
        monkeypatch.setenv("CYBERPOWERFULL_SCOPE", "custom.json")
        config = RunConfig.from_env()
        assert config.llm_spec == "llamacpp:qwen3:1.7b"
        assert config.max_iterations == 3
        assert config.scope_path == Path("custom.json")

    def test_model_config_env(self, monkeypatch) -> None:
        monkeypatch.setenv("CYBERPOWERFULL_CONTEXT_WINDOW", "8192")
        monkeypatch.setenv("CYBERPOWERFULL_TEMPERATURE", "0.3")
        config = ModelConfig.from_env()
        assert config.context_window == 8192
        assert config.temperature == 0.3

    def test_overrides_ignore_none(self) -> None:
        config = RunConfig().with_overrides(max_iterations=4, target=None)
        assert config.max_iterations == 4
        assert config.target is None

    def test_ensure_dirs(self, tmp_path: Path) -> None:
        config = RunConfig(
            out_dir=tmp_path / "out",
            memory_path=tmp_path / "mem" / "m.sqlite3",
            trace_path=tmp_path / "tr" / "t.json",
        )
        config.ensure_dirs()
        assert (tmp_path / "out").is_dir()
        assert (tmp_path / "mem").is_dir()
        assert (tmp_path / "tr").is_dir()

    def test_sanitized_env_strips_cloud_credentials(self) -> None:
        clean = ToolPolicy().sanitized_env(
            {
                "PATH": "/bin",
                "OPENAI_API_KEY": "x",
                "ANTHROPIC_TOKEN": "y",
                "AWS_SECRET_ACCESS_KEY": "z",
                "SOME_TOKEN": "t",
                "SAFE": "ok",
            }
        )
        assert clean == {"PATH": "/bin", "SAFE": "ok"}
