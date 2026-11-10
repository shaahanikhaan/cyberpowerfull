"""Allow ``python -m cyberpowerfull`` to behave like the CLI."""

from __future__ import annotations

from cyberpowerfull.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
