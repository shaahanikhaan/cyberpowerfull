"""Tests for the easy-to-use CLI surface: --init, --examples, --completion,
playbook did-you-mean, code-target gating, and exit-code hints."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cyberpowerfull import cli
from cyberpowerfull.cli import _EXIT_HINTS, _require_code_target, main
from cyberpowerfull.errors import ScopeViolation
from cyberpowerfull.playbook import get_playbook
from cyberpowerfull.scope import bootstrap_scope


class TestExamples:
    def test_examples_print_recipes(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--examples"]) == 0
        out = capsys.readouterr().out
        assert "cpf example.com" in out
        assert "cpf --init" in out
        assert "--playbook code" in out
        assert "cpf --lab" in out


class TestCompletion:
    @pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
    def test_completion_names_playbooks(
        self, shell: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--completion", shell]) == 0
        out = capsys.readouterr().out
        for name in ("recon", "web", "network", "stealth", "api", "code", "cloud", "full"):
            assert name in out

    def test_completion_rejects_unknown_shell(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--completion", "powershell"])
        assert excinfo.value.code == 2


class TestInitWizard:
    def test_init_refuses_non_tty(self, capsys: pytest.CaptureFixture[str]) -> None:
        # pytest captures stdin: isatty() is False, so the wizard must bail out cleanly.
        assert main(["--init"]) == 2
        err = capsys.readouterr().err
        assert "interactive terminal" in err
        assert "--init-scope" in err

    def test_init_wizard_guided_run_end_to_end(self, tmp_path: Path, monkeypatch) -> None:
        """Recorded-stdin acceptance: answer 5 questions, decline the run, get a scope file."""
        answers = iter(
            [
                "127.0.0.1",  # 1/5 target
                "",  # 2/5 playbook (default recon)
                "",  # 3/5 engagement (default cpf-127-0-0-1)
                "n",  # aggressive?
                "n",  # credential_testing?
                "n",  # passive sources?
                "SOW-TEST-1",  # 5/5 authorization ref
                "yes",  # attestation
                str(tmp_path / "scope.json"),  # scope file
                "n",  # run now? no
            ]
        )
        monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr(cli, "_run_playbook", lambda args: 0)
        assert main(["--init"]) == 0
        scope = json.loads((tmp_path / "scope.json").read_text(encoding="utf-8"))
        assert scope["targets"] == ["127.0.0.1"]
        assert scope["authorized"] is True
        assert scope["authorization_ref"] == "SOW-TEST-1"
        assert scope["capabilities"] == []
        assert scope["allow_passive_sources"] is False

    def test_init_wizard_repo_target_sets_allowed_paths(self, tmp_path: Path, monkeypatch) -> None:
        repo = tmp_path / "myrepo"
        repo.mkdir()
        answers = iter(
            [
                str(repo),  # 1/5 target (existing path -> code default)
                "",  # 2/5 playbook (default code)
                "repo-audit",  # 3/5 engagement
                "n",
                "n",
                "n",
                "SOW-TEST-2",
                "yes",
                str(tmp_path / "scope.json"),
                "n",
            ]
        )
        monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        seen: dict[str, object] = {}
        monkeypatch.setattr(cli, "_run_playbook", lambda args: seen.update(vars(args)) or 0)
        assert main(["--init"]) == 0
        scope = json.loads((tmp_path / "scope.json").read_text(encoding="utf-8"))
        assert scope["targets"] == []
        assert scope["allowed_paths"] == [str(repo.resolve())]


class TestInitScopeAllowedPaths:
    def test_init_scope_accepts_allowed_paths(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "scope.json"
        code = main(
            [
                "--init-scope",
                str(out),
                "--engagement",
                "code-audit",
                "--targets",
                "127.0.0.1",
                "--allowed-paths",
                str(repo),
                "--authorize",
                "--authorization-ref",
                "SOW-1",
            ]
        )
        assert code == 0
        scope = json.loads(out.read_text(encoding="utf-8"))
        assert scope["allowed_paths"] == [str(repo.resolve())]


class TestDidYouMean:
    def test_unknown_playbook_suggests_close_match(self) -> None:
        with pytest.raises(Exception) as excinfo:
            get_playbook("weeb")
        assert "did you mean 'web'" in str(excinfo.value)

    def test_unknown_playbook_without_match_lists_names(self) -> None:
        with pytest.raises(Exception) as excinfo:
            get_playbook("zzzzzz")
        message = str(excinfo.value)
        assert "did you mean" not in message
        assert "recon" in message


class TestRequireCodeTarget:
    def test_allows_path_inside_allowed_root(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        scope = bootstrap_scope(
            engagement="e",
            targets=[],
            authorization_ref="r",
            authorized=True,
            allowed_paths=[str(repo)],
        )
        assert _require_code_target(scope, str(repo)) == str(repo.resolve())

    def test_rejects_sibling_of_allowed_root(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        sibling = tmp_path / "other"
        sibling.mkdir()
        scope = bootstrap_scope(
            engagement="e",
            targets=[],
            authorization_ref="r",
            authorized=True,
            allowed_paths=[str(repo)],
        )
        with pytest.raises(ScopeViolation, match=r"not listed in scope\.allowed_paths"):
            _require_code_target(scope, str(sibling))

    def test_rejects_missing_path(self, tmp_path: Path) -> None:
        scope = bootstrap_scope(
            engagement="e",
            targets=[],
            authorization_ref="r",
            authorized=True,
            allowed_paths=[str(tmp_path)],
        )
        with pytest.raises(ScopeViolation, match="does not exist"):
            _require_code_target(scope, str(tmp_path / "nope"))

    def test_rejects_blank_target(self, tmp_path: Path) -> None:
        scope = bootstrap_scope(
            engagement="e",
            targets=[],
            authorization_ref="r",
            authorized=True,
            allowed_paths=[str(tmp_path)],
        )
        with pytest.raises(ScopeViolation, match="needs --target PATH"):
            _require_code_target(scope, "  ")


class TestExitHints:
    def test_every_hint_mentions_a_fix(self) -> None:
        assert set(_EXIT_HINTS) == {3, 4, 5, 7, 8}
        for hint in _EXIT_HINTS.values():
            assert hint.startswith("hint: ")

    def test_missing_scope_prints_hint(self, tmp_path: Path) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "cyberpowerfull.cli",
                "--scope",
                str(tmp_path / "nope.json"),
                "--target",
                "127.0.0.1",
                "--playbook",
                "recon",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parents[1],
        )
        assert proc.returncode == 3
        assert "cpf --init" in proc.stderr


class TestOnePassDirectoryGuard:
    def test_local_directory_suggests_code_playbook(self, tmp_path: Path, workdir: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        code = main([str(repo), "--i-am-authorized", "--out", str(workdir / "artifacts")])
        assert code != 0
