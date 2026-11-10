"""Self-update tests. Every git/pip call is simulated; nothing touches the network."""

from __future__ import annotations

import sys
from pathlib import Path

import cyberpowerfull
import cyberpowerfull.selfupdate as selfupdate
from cyberpowerfull.selfupdate import CommandResult, find_repo_root, run_update


class ScriptedRunner:
    """A fake ``selfupdate._run`` driven by per-command scripts."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.scripts: dict[str, CommandResult] = {}
        self.default = CommandResult(0, "", "")

    def key(self, argv: list[str]) -> str:
        if argv[:2] == ["git", "rev-parse"] and argv[2:] == ["--show-toplevel"]:
            return "toplevel"
        if argv[:2] == ["git", "rev-parse"]:
            return "sha"
        if argv[:2] == ["git", "status"]:
            return "status"
        if argv[:2] == ["git", "fetch"]:
            return "fetch"
        if argv[:2] == ["git", "rev-list"]:
            return "counts"
        if argv[:2] == ["git", "branch"]:
            return "branch"
        if argv[:2] == ["git", "pull"]:
            return "pull"
        if argv[1:4] == ["-m", "pip", "install"]:
            return "pip"
        if argv[1:2] == ["-c"]:
            return "version"
        return "other"

    def __call__(self, argv: list[str], cwd: Path) -> CommandResult:
        self.calls.append(list(argv))
        return self.scripts.get(self.key(argv), self.default)

    def ran(self, *words: str) -> bool:
        return any(all(any(word in arg for arg in call) for word in words) for call in self.calls)


def _repo_script() -> ScriptedRunner:
    runner = ScriptedRunner()
    runner.scripts["toplevel"] = CommandResult(0, "/repo\n", "")
    runner.scripts["sha"] = CommandResult(0, "abc1234\n", "")
    runner.scripts["status"] = CommandResult(0, "", "")
    runner.scripts["fetch"] = CommandResult(0, "", "")
    runner.scripts["counts"] = CommandResult(0, "0\t0\n", "")
    runner.scripts["branch"] = CommandResult(0, "main\n", "")
    runner.scripts["pull"] = CommandResult(0, "Fast-forward\n", "")
    runner.scripts["pip"] = CommandResult(0, "", "")
    runner.scripts["version"] = CommandResult(0, "9.9.9\n", "")
    return runner


def _install(monkeypatch, runner: ScriptedRunner) -> ScriptedRunner:
    monkeypatch.setattr(selfupdate, "_run", runner)
    return runner


class TestFindRepoRoot:
    def test_returns_none_outside_a_checkout(self, monkeypatch) -> None:
        runner = ScriptedRunner()
        runner.scripts["toplevel"] = CommandResult(128, "", "not a git repository")
        _install(monkeypatch, runner)
        assert find_repo_root() is None

    def test_returns_the_toplevel_inside_a_checkout(self, monkeypatch) -> None:
        _install(monkeypatch, _repo_script())
        assert find_repo_root() == Path("/repo")


class TestRunUpdate:
    def test_not_a_checkout_explains_the_manual_route(self, monkeypatch, capsys) -> None:
        runner = ScriptedRunner()
        runner.scripts["toplevel"] = CommandResult(128, "", "not a git repository")
        _install(monkeypatch, runner)
        assert run_update() == 1
        err = capsys.readouterr().err
        assert "not installed from a git checkout" in err
        assert "git pull" in err

    def test_dirty_tree_refuses_before_any_fetch(self, monkeypatch, capsys) -> None:
        runner = _repo_script()
        runner.scripts["status"] = CommandResult(0, " M cli.py\n?? new.py\n", "")
        _install(monkeypatch, runner)
        assert run_update() == 1
        err = capsys.readouterr().err
        assert "uncommitted" in err
        assert not runner.ran("fetch")
        assert not runner.ran("pull")
        assert not runner.ran("pip")

    def test_force_pulls_over_a_dirty_tree(self, monkeypatch, capsys) -> None:
        runner = _repo_script()
        runner.scripts["status"] = CommandResult(0, " M cli.py\n", "")
        runner.scripts["counts"] = CommandResult(0, "0\t2\n", "")
        _install(monkeypatch, runner)
        assert run_update(force=True) == 0
        assert runner.ran("pull")
        assert "updated cyberpowerfull" in capsys.readouterr().out

    def test_already_up_to_date_pulls_nothing(self, monkeypatch, capsys) -> None:
        runner = _install(monkeypatch, _repo_script())
        assert run_update() == 0
        out = capsys.readouterr().out
        assert "already up to date" in out
        assert cyberpowerfull.__version__ in out
        assert not runner.ran("pull")
        assert not runner.ran("pip")

    def test_local_ahead_commits_are_reported(self, monkeypatch, capsys) -> None:
        runner = _repo_script()
        runner.scripts["counts"] = CommandResult(0, "2\t0\n", "")
        _install(monkeypatch, runner)
        assert run_update() == 0
        assert "2 local commit(s) ahead" in capsys.readouterr().out

    def test_behind_pulls_and_reinstalls(self, monkeypatch, capsys) -> None:
        runner = _repo_script()
        runner.scripts["counts"] = CommandResult(0, "0\t3\n", "")
        _install(monkeypatch, runner)
        assert run_update() == 0
        out = capsys.readouterr().out
        assert "3 commit(s) behind" in out
        assert runner.ran("pull", "--ff-only")
        assert runner.ran("pip", "install")
        assert "updated cyberpowerfull" in out
        assert "9.9.9" in out  # the fresh interpreter probe, not the running process

    def test_editable_install_reinstalls_editable(self, monkeypatch) -> None:
        runner = _repo_script()
        runner.scripts["counts"] = CommandResult(0, "0\t1\n", "")
        _install(monkeypatch, runner)
        monkeypatch.setattr(selfupdate, "_package_dir", lambda: Path("/repo/src/cyberpowerfull"))
        assert run_update() == 0
        pip_calls = [call for call in runner.calls if "pip" in call]
        assert pip_calls and "-e" in pip_calls[0]
        assert pip_calls[0][0] == sys.executable

    def test_non_editable_install_reinstalls_plain(self, monkeypatch) -> None:
        runner = _repo_script()
        runner.scripts["counts"] = CommandResult(0, "0\t1\n", "")
        _install(monkeypatch, runner)
        monkeypatch.setattr(
            selfupdate, "_package_dir", lambda: Path("/usr/lib/python3/site-packages/x")
        )
        assert run_update() == 0
        pip_calls = [call for call in runner.calls if "pip" in call]
        assert pip_calls and "-e" not in pip_calls[0]

    def test_no_upstream_errors_with_the_fix(self, monkeypatch, capsys) -> None:
        runner = _repo_script()
        runner.scripts["counts"] = CommandResult(128, "", "no upstream configured")
        _install(monkeypatch, runner)
        assert run_update() == 1
        err = capsys.readouterr().err
        assert "no upstream" in err
        assert "git branch --set-upstream-to=origin/main" in err
        assert not runner.ran("pull")

    def test_fetch_failure_aborts(self, monkeypatch, capsys) -> None:
        runner = _repo_script()
        runner.scripts["fetch"] = CommandResult(1, "", "could not resolve host")
        _install(monkeypatch, runner)
        assert run_update() == 1
        assert "git fetch" in capsys.readouterr().err
        assert not runner.ran("pull")

    def test_pull_failure_aborts(self, monkeypatch, capsys) -> None:
        runner = _repo_script()
        runner.scripts["counts"] = CommandResult(0, "0\t1\n", "")
        runner.scripts["pull"] = CommandResult(1, "", "divergent branches")
        _install(monkeypatch, runner)
        assert run_update() == 1
        assert "git pull --ff-only" in capsys.readouterr().err
        assert not runner.ran("pip")

    def test_pip_permission_failure_prints_the_sudo_command(self, monkeypatch, capsys) -> None:
        runner = _repo_script()
        runner.scripts["counts"] = CommandResult(0, "0\t1\n", "")
        runner.scripts["pip"] = CommandResult(1, "", "ERROR: Permission denied: '/usr/lib/x'")
        _install(monkeypatch, runner)
        assert run_update() == 1
        err = capsys.readouterr().err
        assert "already updated" in err
        assert "sudo" in err
        assert "pip install" in err

    def test_pip_failure_without_permission_issue_has_no_sudo_hint(
        self, monkeypatch, capsys
    ) -> None:
        runner = _repo_script()
        runner.scripts["counts"] = CommandResult(0, "0\t1\n", "")
        runner.scripts["pip"] = CommandResult(1, "", "ERROR: build failed")
        _install(monkeypatch, runner)
        assert run_update() == 1
        assert "sudo" not in capsys.readouterr().err
