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


class TestSanitizeArgv:
    def test_masks_secret_flag_values(self) -> None:
        from cyberpowerfull.live import sanitize_argv

        argv = ["http_probe", "--method", "GET", "--url", "http://x/", "--header", "A: s3cret"]
        assert sanitize_argv(argv) == [
            "http_probe",
            "--method",
            "GET",
            "--url",
            "http://x/",
            "--header",
            "***",
        ]
        assert argv[-1] == "A: s3cret"  # the real argv is untouched

    def test_masks_joined_form(self) -> None:
        from cyberpowerfull.live import sanitize_argv

        assert sanitize_argv(["tool", "--body=secret", "--token", "abc"]) == [
            "tool",
            "--body=***",
            "--token",
            "***",
        ]

    def test_leaves_ports_and_paths_alone(self) -> None:
        from cyberpowerfull.live import sanitize_argv

        argv = ["nmap", "-sV", "-p", "80,443", "127.0.0.1"]
        assert sanitize_argv(argv) == argv


class TestRunChrome:
    def test_banner_names_run_target_and_engagement(self) -> None:
        stream = io.StringIO()
        LiveDisplay(stream=stream, live=False, color=False).banner(
            {
                "kind": "cpf 5.2.0 · playbook web",
                "target": "127.0.0.1",
                "detail": "profile standard",
                "engagement": "demo",
                "steps": 17,
            }
        )
        out = stream.getvalue()
        assert "cpf 5.2.0 · playbook web · target 127.0.0.1" in out
        assert "engagement demo · 17 steps" in out

    def test_group_banner(self) -> None:
        stream = io.StringIO()
        LiveDisplay(stream=stream, live=False, color=False).group_start(
            {"index": 2, "total": 4, "phase": "scanning", "steps": 3}
        )
        assert "GROUP 2/4 · SCANNING · 3 step(s)" in stream.getvalue()

    def test_command_shows_shell_command(self) -> None:
        stream = io.StringIO()
        LiveDisplay(stream=stream, live=False, color=False).command(
            {"tool": "nmap", "argv": ["nmap", "-sV", "127.0.0.1"]}
        )
        assert "[*] nmap: $ nmap -sV 127.0.0.1" in stream.getvalue()

    def test_command_marks_native_and_masks_secrets(self) -> None:
        stream = io.StringIO()
        LiveDisplay(stream=stream, live=False, color=False).command(
            {
                "tool": "http_probe",
                "argv": ["http_probe", "--url", "http://x/", "--header", "A: s3cret"],
                "native": True,
            }
        )
        out = stream.getvalue()
        assert "● http_probe --url http://x/ --header" in out and "***" in out
        assert "(in-process)" in out
        assert "s3cret" not in out

    def test_command_ignores_empty_argv(self) -> None:
        stream = io.StringIO()
        LiveDisplay(stream=stream, live=False, color=False).command({"tool": "nmap"})
        assert stream.getvalue() == ""

    def test_skipped_and_complete(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=False, color=False)
        display.skipped({"id": "recon-nmap", "reason": "binary not installed: nmap"})
        display.complete({"steps": 1, "findings": 2, "elapsed": 61.0})
        out = stream.getvalue()
        assert "○ skipped recon-nmap: binary not installed: nmap" in out
        assert "SCAN COMPLETE · 1 step(s) · 2 finding(s) · 61s" in out


class TestTitlesAndVerbose:
    def test_medium_and_low_titles_print_without_severity_claim(self) -> None:
        stream = io.StringIO()
        display = LiveDisplay(stream=stream, live=False, color=False)
        display.progress(_record(findings=1, top="MEDIUM", titles=["TLS 1.0 offered"]))
        display.progress(_record(findings=1, top="INFO", titles=["Open TCP port 22"]))
        out = stream.getvalue()
        assert "TLS 1.0 offered" in out
        assert "Open TCP port 22" in out
        assert "!!" not in out

    def test_high_titles_keep_alarm_prefix(self) -> None:
        stream = io.StringIO()
        LiveDisplay(stream=stream, live=False, color=False).progress(
            _record(findings=2, top="HIGH", titles=["SQL injection here", "XSS there"])
        )
        out = stream.getvalue()
        assert "!! HIGH: SQL injection here" in out
        assert "!! HIGH: XSS there" in out

    def test_verbose_prints_output_excerpt(self) -> None:
        record = _record(findings=0, top=None)
        record.result["stdout_excerpt"] = "line one\nline two\n"
        stream = io.StringIO()
        LiveDisplay(stream=stream, live=False, color=False, verbose=True).progress(record)
        out = stream.getvalue()
        assert "tool output" in out
        assert "line one" in out

    def test_quiet_default_hides_output_excerpt(self) -> None:
        record = _record(findings=0, top=None)
        record.result["stdout_excerpt"] = "line one\n"
        stream = io.StringIO()
        LiveDisplay(stream=stream, live=False, color=False).progress(record)
        assert "line one" not in stream.getvalue()
