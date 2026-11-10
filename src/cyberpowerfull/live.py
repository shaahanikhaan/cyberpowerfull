"""Live foreground progress display (sn1per-style, zero dependencies).

:class:`LiveDisplay` is the thing an operator watches while a run is going:
every tool start and every tool result is printed the moment it happens, with
elapsed time, finding counts and top severity -- the way sn1per tees each
command it runs.

Two render modes, chosen automatically:

* **live** (stderr is a TTY): a spinner line shows what is running *right
  now*; completed steps print as permanent lines above it.
* **plain** (pipes, files, CI): timestamped ``start`` / ``done`` lines. No
  cursor codes, ever.

Deliberately *not* shown: raw tool stdout. Some tools print secrets
(hydra prints passwords, sqlmap prints dumps), so the display only renders
the sanitized step record (status, counts, severities, finding titles).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, TextIO

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠿"
_CLEAR = "\x1b[2K\r"

_CODES = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "green": "\x1b[32m",
    "red": "\x1b[31m",
    "yellow": "\x1b[33m",
    "cyan": "\x1b[36m",
    "magenta": "\x1b[35m",
}

_STATUS_WORDS = {
    "ok": "done",
    "missing": "skipped: tool not installed",
    "blocked": "blocked by scope",
    "error": "failed",
    "timeout": "timed out",
    "dry_run": "rehearsed",
    "skipped": "skipped",
}


def _supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and bool(stream.isatty())


class LiveDisplay:
    """Foreground progress renderer fed by the runners' step hooks.

    ``step_start`` is called with a small dict (``tool``, ``purpose``/``label``,
    ``index``/``total`` when known); ``progress`` receives the finished
    :class:`~cyberpowerfull.trace.StepRecord`. Both are optional-tolerant:
    missing keys degrade to ``-`` instead of raising, because display code
    must never break a run.
    """

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        total: int | None = None,
        live: bool | None = None,
        color: bool | None = None,
        tick_seconds: float = 0.2,
    ) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._total = total
        self._live = (
            live
            if live is not None
            else (hasattr(self._stream, "isatty") and bool(self._stream.isatty()))
        )
        self._color = color if color is not None else _supports_color(self._stream)
        self._tick = max(tick_seconds, 0.05)
        self._lock = threading.Lock()
        self._running: dict[str, tuple[str, float]] = {}
        self._done = 0
        self._findings = 0
        self._stop: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._frame = 0

    # -- public hooks ----------------------------------------------------
    def step_start(self, info: dict[str, Any] | None) -> None:
        """Announce a step the moment its tool is dispatched."""
        info = info or {}
        tool = str(info.get("tool") or "-")
        label = str(info.get("purpose") or info.get("label") or info.get("id") or "")
        key = f"{tool}#{info.get('index', len(self._running))}"
        now = time.monotonic()
        with self._lock:
            self._running[key] = (f"{tool} {label}".strip(), now)
            if self._live:
                self._ensure_thread_locked()
            else:
                self._write_locked(f"[{self._stamp()}] start {tool} {label}".rstrip() + "\n")

    def progress(self, record: Any) -> None:
        """Render one finished step as a permanent line."""
        tool = str(getattr(record, "tool", None) or getattr(record, "action", "-") or "-")
        result = getattr(record, "result", None) or {}
        status = str(result.get("status", "-"))
        finding_ids = getattr(record, "finding_ids", None) or []
        titles = list(result.get("finding_titles") or [])[:3]
        top = str(result.get("top_severity") or "").upper()
        duration_ms = result.get("duration_ms")
        index = getattr(record, "index", 0) or 0
        with self._lock:
            self._done += 1
            self._findings += len(finding_ids)
            key = next((k for k in self._running if k.startswith(f"{tool}#")), None)
            elapsed: float | None = None
            if key is not None:
                elapsed = time.monotonic() - self._running.pop(key)[1]
            elif isinstance(duration_ms, (int, float)):
                elapsed = duration_ms / 1000.0
            if self._live:
                self._write_locked(_CLEAR)
            line = self._done_line(
                tool=tool,
                status=status,
                findings=len(finding_ids),
                top=top,
                elapsed=elapsed,
                index=index,
            )
            self._write_locked(line + "\n")
            for title in titles:
                if top in {"HIGH", "CRITICAL"}:
                    self._write_locked(
                        f"  {self._paint('!!', 'magenta')} "
                        f"{self._paint(top, 'magenta')}: {title[:120]}\n"
                    )
                    break
            if self._live and not self._running and self._thread is not None:
                self._stop_thread_locked()

    def note(self, text: str) -> None:
        """Print a free-form line without disturbing the spinner."""
        with self._lock:
            if self._live:
                self._write_locked(_CLEAR)
            self._write_locked(text.rstrip("\n") + "\n")

    def close(self) -> None:
        with self._lock:
            if self._live:
                self._write_locked(_CLEAR)
            self._stop_thread_locked()

    # -- rendering ---------------------------------------------------------
    def _done_line(
        self,
        *,
        tool: str,
        status: str,
        findings: int,
        top: str,
        elapsed: float | None,
        index: int,
    ) -> str:
        word = _STATUS_WORDS.get(status, status)
        if status == "ok":
            mark, paint = "✔", "green"
        elif status in {"error", "timeout"}:
            mark, paint = "✘", "red"
        else:
            mark, paint = "○", "yellow"
        counter = f"[{self._done:02d}]"
        if self._total:
            counter = f"[{self._done:02d}/{self._total:02d}]"
        elif index:
            counter = f"[{index:02d}]"
        bits = [f"{counter} {tool:<12} {word}"]
        if findings:
            sev = f", top {top}" if top else ""
            bits.append(f"{findings} finding{'s' if findings != 1 else ''}{sev}")
        if elapsed is not None:
            bits.append(f"{elapsed:.1f}s")
        line = " · ".join(bits)
        return f"{self._paint(mark, paint)} {line}"

    def _spinner_line(self) -> str:
        self._frame += 1
        frame = _SPINNER[self._frame % len(_SPINNER)]
        oldest = min(self._running.values(), key=lambda item: item[1], default=None)
        if oldest is None:
            return ""
        label, started = oldest
        extra = f" +{len(self._running) - 1} more" if len(self._running) > 1 else ""
        counter = f"[{self._done + 1:02d}]"
        if self._total:
            counter = f"[{self._done + 1:02d}/{self._total:02d}]"
        line = (
            f"{frame} {counter} {label[:60]}{extra} "
            f"· {time.monotonic() - started:.0f}s "
            f"· {self._findings} finding{'s' if self._findings != 1 else ''} so far"
        )
        return self._paint(line, "cyan")

    # -- low level -----------------------------------------------------------
    def _paint(self, text: str, color: str) -> str:
        if not self._color:
            return text
        return f"{_CODES[color]}{text}{_CODES['reset']}"

    def _stamp(self) -> str:
        return time.strftime("%H:%M:%S")

    def _write_locked(self, text: str) -> None:
        try:
            self._stream.write(text)
            self._stream.flush()
        except (OSError, ValueError):
            pass

    def _ensure_thread_locked(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._spin, name="cpf-live", daemon=True
        )
        self._thread.start()

    def _stop_thread_locked(self) -> None:
        if self._stop is not None:
            self._stop.set()
        self._thread = None
        self._stop = None

    def _spin(self) -> None:
        stop = self._stop
        while stop is not None and not stop.is_set():
            with self._lock:
                if not self._running:
                    break
                self._write_locked(_CLEAR + self._spinner_line())
            stop.wait(self._tick)


__all__ = ["LiveDisplay"]
