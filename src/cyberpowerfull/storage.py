"""Small helpers for writing engagement-confidential local artefacts."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_private_text(path: str | Path, content: str) -> Path:
    """Atomically write UTF-8 text with owner-only file permissions on POSIX.

    The temporary file is created in the destination directory, so replacement
    does not follow an existing output symlink and stays on the same filesystem.
    Existing directories retain their own permissions.
    """
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target
