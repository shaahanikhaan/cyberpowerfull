#!/usr/bin/env python3
"""Pre-tag consistency check: version, changelog, badge, and package metadata.

Run by `make release-check` and by the release workflow. Exits non-zero with a
specific message so a release cannot be cut with a stale badge or changelog.
"""

from __future__ import annotations

import pathlib
import re
import sys

import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    init = (ROOT / "src" / "cyberpowerfull" / "__init__.py").read_text()
    changelog = (ROOT / "CHANGELOG.md").read_text()
    readme = (ROOT / "README.md").read_text()

    problems: list[str] = []
    if f'__version__ = "{version}"' not in init:
        problems.append("src/cyberpowerfull/__init__.py does not match pyproject.toml")
    if f"## [{version}]" not in changelog:
        problems.append(f"CHANGELOG.md has no '## [{version}]' section")
    if f"version-{version}-blue" not in readme:
        problems.append("README.md version badge is stale")
    if not re.search(rf"^## \[{re.escape(version)}\]", changelog, re.M):
        problems.append("the changelog heading for this version is not at the top level")

    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print(f"release check ok: v{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
