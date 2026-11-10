"""Live foreground display: plain lines, live spinner, safe degradation."""

from __future__ import annotations

import io
import time
from types import SimpleNamespace

from cyberpowerfull.live import LiveDisplay


def _record(
    tool: str = "nmap",
    status: str = "ok",
    findings: int = 0,
    index: int = 1,
    top: str | None = None,
    titles: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        tool=tool,
        action="playbook",
        index=index,
        finding_ids=[f"f-{i}" for i in range(findings)],
        result={
            "status": status,
            "duration_ms": 1250,
            "finding_titles": titles or [],
            "top_severity": top,
        },
    )


class TestPlainMode:
    def test_start_and_done_lines(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, total=4, live=False, color=False)
        display.step_start({"tool": "nmap", "purpose": "top-1000 sweep"})
        display.progress(_record(findings=2, top="high"))
        out = stream.getvalue()
        assert "start nmap top-1000 sweep" in out
        assert "[01/04]" in out
        assert "nmap" in out and "done" in out
        assert "2 findings" in out
        assert "HIGH" in out
        assert "0.0s" in out  # measured live between start and done

    def test_recorded_duration_is_used_without_start(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=False, color=False)
        display.progress(_record(tool="nikto"))
        assert "1.2s" in stream.getvalue()

    def test_status_words(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=False, color=False)
        display.progress(_record(tool="ffuf", status="missing"))
        display.progress(_record(tool="nikto", status="error"))
        display.progress(_record(tool="nuclei", status="blocked"))
        out = stream.getvalue()
        assert "skipped: tool not installed" in out
        assert "failed" in out
        assert "blocked by scope" in out

    def test_high_severity_title_is_highlighted(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=False, color=False)
        display.progress(
            _record(findings=1, top="critical", titles=["Remote code execution in widget"])
        )
        assert "CRITICAL: Remote code execution in widget" in stream.getvalue()

    def test_minimal_record_never_crashes(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=False, color=False)
        display.step_start(None)
        idle = SimpleNamespace(tool=None, action=None, index=0, finding_ids=[], result={})
        display.progress(idle)
        display.note("free line")
        display.close()
        assert "free line" in stream.getvalue()

    def test_broken_stream_is_swallowed(self) -> None:
        class Dead:
            def write(self, text: str) -> None:
                raise OSError("closed")

            def flush(self) -> None:
                raise OSError("closed")

        display = LiveDisplay(stream=Dead(), live=False)  # type: ignore[arg-type]
        display.step_start({"tool": "nmap"})
        display.progress(_record())
        display.close()


class TestLiveMode:
    def test_spinner_runs_and_stops(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=True, color=False, tick_seconds=0.05)
        display.step_start({"tool": "nmap", "purpose": "sweep"})
        time.sleep(0.2)
        assert display._thread is not None
        display.progress(_record())
        assert display._thread is None
        out = stream.getvalue()
        assert "nmap" in out and "done" in out

    def test_parallel_in_flight_counts(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=True, color=False, tick_seconds=0.05)
        display.step_start({"tool": "nmap"})
        display.step_start({"tool": "nikto"})
        time.sleep(0.2)
        display.close()
        assert "+1 more" in stream.getvalue()

    def test_close_is_idempotent(self) -> None:
        display = LiveDisplay(stream=io.StringIO(), live=True, color=False)
        display.close()
        display.close()

    def test_no_color_env_disables_paint(self, monkeypatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        display = LiveDisplay(stream=io.StringIO(), live=False)
        assert display._paint("x", "red") == "x"

    def test_color_codes_present_on_request(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=False, color=True)
        display.progress(_record())
        assert "\x1b[32m" in stream.getvalue()
