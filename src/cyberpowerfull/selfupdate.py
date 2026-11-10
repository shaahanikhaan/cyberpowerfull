"""Self-update: pull the git checkout and reinstall the running tool.

``cyberpowerfull --update`` answers one question: is this installed copy behind
the repository it came from, and if so, bring it forward. It runs no scan, it
never touches a dirty tree without ``--force``, and it never escalates to sudo
itself: when the reinstall hits a permission error it prints the exact command
the operator must re-run elevated.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import cyberpowerfull


@dataclass(frozen=True)
class CommandResult:
    """The captured outcome of one git/pip invocation."""

    returncode: int
    stdout: str
    stderr: str


def _run(argv: list[str], cwd: Path) -> CommandResult:
    """Run one subprocess. This single seam is what the tests simulate."""
    completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _package_dir() -> Path:
    return Path(cyberpowerfull.__file__).resolve().parent


def find_repo_root() -> Path | None:
    """The git checkout this installed copy lives in, or ``None``.

    An editable install (``pip install -e .``) resolves inside the clone, so
    ``git rev-parse`` walks up to it. A wheel/site-packages copy resolves
    outside any checkout and yields ``None``: there is nothing to pull.
    """
    probe = _run(["git", "rev-parse", "--show-toplevel"], _package_dir())
    if probe.returncode != 0:
        return None
    root = probe.stdout.strip()
    return Path(root) if root else None


def _tail(text: str, lines: int = 8) -> str:
    kept = [line for line in text.strip().splitlines() if line.strip()]
    return "\n".join(kept[-lines:])


def _short_sha(root: Path) -> str:
    probe = _run(["git", "rev-parse", "--short", "HEAD"], root)
    return probe.stdout.strip() or "unknown" if probe.returncode == 0 else "unknown"


def run_update(*, force: bool = False) -> int:
    """Pull the checkout behind this install and reinstall it. Returns 0/1."""
    root = find_repo_root()
    if root is None:
        print(
            "error: this copy of cyberpowerfull is not installed from a git checkout, "
            "so --update has nothing to pull.",
            file=sys.stderr,
        )
        print(
            "to update: cd into your clone of the repository, run `git pull`, then "
            "reinstall with `python -m pip install -e .` (or `python -m pip install .`).",
            file=sys.stderr,
        )
        return 1

    old_version = cyberpowerfull.__version__
    old_sha = _short_sha(root)
    print(f"checkout: {root} (installed version {old_version} at {old_sha})")

    dirty = _run(["git", "status", "--porcelain"], root)
    changed = (
        [line for line in dirty.stdout.splitlines() if line.strip()]
        if dirty.returncode == 0
        else []
    )
    if changed and not force:
        print(
            f"error: refusing to update: {len(changed)} file(s) with uncommitted "
            "changes. Commit them, stash them (`git stash`), or re-run with --force.",
            file=sys.stderr,
        )
        return 1

    fetch = _run(["git", "fetch"], root)
    if fetch.returncode != 0:
        print(f"error: `git fetch` failed in {root}:", file=sys.stderr)
        print(_tail(fetch.stderr or fetch.stdout) or "(no output)", file=sys.stderr)
        return 1

    counts = _run(["git", "rev-list", "--left-right", "--count", "HEAD...@{u}"], root)
    if counts.returncode != 0:
        branch = _run(["git", "branch", "--show-current"], root).stdout.strip() or "<branch>"
        print(
            f"error: branch {branch!r} has no upstream, so --update cannot tell what is new.",
            file=sys.stderr,
        )
        print(
            f"set one with: git branch --set-upstream-to=origin/{branch}",
            file=sys.stderr,
        )
        return 1
    try:
        ahead, behind = (int(part) for part in counts.stdout.split())
    except ValueError:
        print(
            f"error: could not parse `git rev-list` output: {counts.stdout.strip()!r}",
            file=sys.stderr,
        )
        return 1
    if behind == 0:
        extra = f" ({ahead} local commit(s) ahead of upstream)" if ahead else ""
        print(f"already up to date: cyberpowerfull {old_version} at {old_sha}{extra}")
        return 0

    print(f"{behind} commit(s) behind upstream; pulling...")
    pull = _run(["git", "pull", "--ff-only"], root)
    if pull.returncode != 0:
        print(f"error: `git pull --ff-only` failed in {root}:", file=sys.stderr)
        print(_tail(pull.stderr or pull.stdout) or "(no output)", file=sys.stderr)
        return 1
    new_sha = _short_sha(root)

    try:
        editable = _package_dir().is_relative_to(root)
    except OSError:
        editable = False
    pip_argv = [sys.executable, "-m", "pip", "install", "--quiet"]
    pip_argv += ["-e", "."] if editable else ["."]
    print(f"reinstalling: {' '.join(pip_argv)}")
    install = _run(pip_argv, root)
    if install.returncode != 0:
        print("error: the checkout is already updated, but the reinstall failed:", file=sys.stderr)
        print(_tail(install.stderr or install.stdout) or "(no output)", file=sys.stderr)
        if "permission denied" in f"{install.stdout}\n{install.stderr}".lower():
            print(
                "this looks like a system-wide install. Finish it elevated with:",
                file=sys.stderr,
            )
            print(f"  cd {root} && sudo {' '.join(pip_argv)}", file=sys.stderr)
        return 1

    probe = _run(
        [sys.executable, "-c", "import cyberpowerfull; print(cyberpowerfull.__version__)"],
        root,
    )
    new_version = probe.stdout.strip() if probe.returncode == 0 and probe.stdout.strip() else "?"
    print(f"updated cyberpowerfull {old_version} ({old_sha}) -> {new_version} ({new_sha})")
    return 0
