"""Tests for one-command mode: ``cpf TARGET``.

Two things are being protected here. The friendly path has to work with no configuration at
all, and the authorization gate has to survive being made friendly: no attestation, no scope
file, no run, and an existing scope is never widened.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from cyberpowerfull.cli import main
from cyberpowerfull.errors import ScopeError
from cyberpowerfull.models import Finding, Severity
from cyberpowerfull.onepass import (
    DEFAULT_PROFILE,
    PROFILES,
    attestation_reference,
    default_scope_path,
    engagement_name,
    ensure_scope,
    missing_binaries,
    next_steps,
    phase_breakdown,
    profile_for,
    render_plan,
    step_line,
    target_host,
)
from cyberpowerfull.playbook import get_playbook
from cyberpowerfull.reporting import render_run_json, render_sarif, write_reports
from cyberpowerfull.scope import bootstrap_scope
from cyberpowerfull.trace import StepRecord, Trace, TraceRecorder


class TestTargetHost:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("example.com", "example.com"),
            ("Example.COM.", "example.com"),
            ("https://example.com", "example.com"),
            ("https://user:pass@app.example.test:8443/deep/path?q=1#frag", "app.example.test"),
            ("http://198.51.100.7:8080/admin", "198.51.100.7"),
            ("198.51.100.7:22", "198.51.100.7"),
            ("example.com/admin", "example.com"),
            ("http://10.0.0.5", "10.0.0.5"),
        ],
    )
    def test_reduces_input_to_a_host(self, raw: str, expected: str) -> None:
        assert target_host(raw) == expected

    @pytest.mark.parametrize("raw", ["", "   ", "two words", "http://", "not a host!"])
    def test_rejects_input_it_cannot_authorize(self, raw: str) -> None:
        with pytest.raises(ScopeError):
            target_host(raw)


class TestNames:
    def test_scope_path_is_one_file_per_host(self) -> None:
        path = default_scope_path("app.example.test", "engagements")
        assert path.name == "app.example.test.json"
        assert path.parent.name == "engagements"

    def test_scope_path_sanitises_hostile_hosts(self) -> None:
        path = default_scope_path("10.0.0.5")
        assert path.name == "10.0.0.5.json"

    def test_engagement_name_is_stable(self) -> None:
        assert engagement_name("example.com") == "one-pass-example.com"
        assert engagement_name("example.com") == engagement_name("example.com")

    def test_attestation_reference_names_the_claim(self) -> None:
        reference = attestation_reference(None, today=date(2026, 11, 10))
        assert reference == "operator-attested:2026-11-10"
        assert attestation_reference("SOW-2026-014") == "SOW-2026-014"


class TestProfiles:
    def test_every_profile_names_a_real_playbook(self) -> None:
        for profile in PROFILES.values():
            playbook = get_playbook(profile.playbook)
            assert playbook.steps
            assert profile.max_seconds > 0
            assert profile.parallel >= 1

    def test_default_profile_exists(self) -> None:
        assert DEFAULT_PROFILE in PROFILES
        assert profile_for(None) is PROFILES[DEFAULT_PROFILE]

    def test_unknown_profile_is_a_clear_error(self) -> None:
        with pytest.raises(ScopeError) as excinfo:
            profile_for("ultra")
        assert "quick" in str(excinfo.value) and "deep" in str(excinfo.value)

    def test_deep_is_at_least_as_large_as_standard(self) -> None:
        assert PROFILES["deep"].max_seconds >= PROFILES["standard"].max_seconds
        assert PROFILES["deep"].parallel >= PROFILES["standard"].parallel


class TestEnsureScope:
    def test_creates_an_authorized_scope_after_attestation(self, tmp_path: Path) -> None:
        seen: list[str] = []

        def attest(host: str) -> bool:
            seen.append(host)
            return True

        path = tmp_path / "engagements" / "example.com.json"
        scope, written, created = ensure_scope(
            target="https://example.com/login",
            scope_path=path,
            attest=attest,
            today=date(2026, 11, 10),
        )
        assert created is True
        assert written == path
        assert seen == ["example.com"]
        assert scope.authorized is True
        assert scope.targets == ["example.com"]
        assert scope.authorization_ref == "operator-attested:2026-11-10"
        payload = json.loads(path.read_text())
        assert payload["authorized"] is True
        assert "attested" in payload["notes"]

    def test_refuses_to_write_anything_without_attestation(self, tmp_path: Path) -> None:
        path = tmp_path / "engagements" / "example.com.json"
        with pytest.raises(ScopeError) as excinfo:
            ensure_scope(target="example.com", scope_path=path, attest=lambda host: False)
        assert not path.exists()
        assert "written permission" in str(excinfo.value)

    def test_capabilities_follow_the_flags(self, tmp_path: Path) -> None:
        scope, _, _ = ensure_scope(
            target="example.com",
            scope_path=tmp_path / "a.json",
            attest=lambda host: True,
            aggressive=False,
        )
        assert [capability.value for capability in scope.capabilities] == []

        scope, _, _ = ensure_scope(
            target="example.com",
            scope_path=tmp_path / "b.json",
            attest=lambda host: True,
            aggressive=True,
            credentials=True,
        )
        assert {capability.value for capability in scope.capabilities} == {
            "aggressive",
            "credential_testing",
        }

    def test_reuses_an_existing_scope_without_rewriting_it(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.json"
        scope = bootstrap_scope(
            engagement="existing",
            targets=["example.com", "api.example.com"],
            authorized=True,
            authorization_ref="SOW-1",
        )
        from cyberpowerfull.scope import write_scope

        write_scope(path, scope)
        before = path.read_bytes()
        loaded, written, created = ensure_scope(
            target="api.example.com", scope_path=path, attest=lambda host: False
        )
        assert created is False
        assert written == path
        assert loaded.engagement == "existing"
        assert path.read_bytes() == before

    def test_never_widens_an_existing_scope(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.json"
        from cyberpowerfull.scope import write_scope

        write_scope(
            path,
            bootstrap_scope(
                engagement="existing",
                targets=["example.com"],
                authorized=True,
                authorization_ref="SOW-1",
            ),
        )
        with pytest.raises(ScopeError) as excinfo:
            ensure_scope(target="other.example", scope_path=path, attest=lambda host: True)
        assert "not modified" in str(excinfo.value)


class TestPlanAndProgress:
    def test_plan_states_what_will_happen(self, tmp_path: Path) -> None:
        scope, path, _ = ensure_scope(
            target="example.com",
            scope_path=tmp_path / "example.com.json",
            attest=lambda host: True,
        )
        lines = render_plan(
            target="example.com",
            host="example.com",
            profile=profile_for("quick"),
            scope=scope,
            scope_path=path,
            created=True,
            out_dir=tmp_path / "artifacts",
            aggressive=True,
        )
        text = "\n".join(lines)
        assert "example.com" in text
        assert "just created" in text
        assert "recon" in text
        assert "aggressive" in text

    def test_phase_breakdown_counts_real_steps(self) -> None:
        playbook = get_playbook("full")
        text = phase_breakdown(list(playbook.steps))
        assert str(len(playbook.steps)) == str(
            sum(int(part.split()[0]) for part in text.split(","))
        )

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            ("ok", "done"),
            ("missing", "tool not installed"),
            ("blocked", "blocked by scope"),
            ("error", "failed"),
            ("timeout", "timed out"),
        ],
    )
    def test_step_line_is_plain_language(self, status: str, expected: str) -> None:
        record = StepRecord(index=1, action="scan", tool="nmap", result={"status": status})
        assert expected in step_line(record, index=1, total=4)

    def test_step_line_counts_findings(self) -> None:
        record = StepRecord(
            index=2,
            action="scan",
            tool="nuclei",
            result={"status": "ok"},
            finding_ids=["f-1", "f-2"],
        )
        assert "2 findings" in step_line(record, index=2, total=8)


class TestNextSteps:
    def test_install_hint_lists_missing_binaries(self) -> None:
        trace = Trace(run_id="run-1", target="example.com")
        steps = next_steps(
            trace=trace,
            report_path=Path("artifacts/report.md"),
            skipped=[
                "recon-nmap: binary not installed: nmap",
                "recon-nuclei: binary not installed: nuclei",
                "recon-nmap-again: binary not installed: nmap",
            ],
            install_hint_cmd="./run.sh --install-tools",
        )
        text = "\n".join(steps)
        assert "2 missing scanner" in text
        assert "./run.sh --install-tools" in text
        assert missing_binaries(["a: binary not installed: nmap"]) == ["nmap"]

    def test_no_findings_is_reported_as_inconclusive(self) -> None:
        trace = Trace(run_id="run-1", target="example.com")
        text = "\n".join(next_steps(trace=trace, report_path=None, skipped=[]))
        assert "clean bill of health" in text
        assert "--profile deep" in text


def _trace_with_finding() -> Trace:
    recorder = TraceRecorder(
        target="example.com",
        engagement="one-pass-example.com",
        model="none",
        backend="playbook:recon",
        scope_fingerprint="abc123",
        run_id="run-sarif",
    )
    recorder.add_step(
        StepRecord(
            index=1,
            action="scan",
            tool="nuclei",
            finding_ids=["f-sarif"],
            result={"status": "ok"},
        )
    )
    recorder.add_findings(
        [
            Finding(
                id="f-sarif",
                title="Reflected cross-site scripting",
                severity=Severity.HIGH,
                target="example.com",
                endpoint="https://example.com/search?q=x",
                evidence="marker cpf7391 appeared in the response body",
                tool="nuclei",
                cve="CVE-2026-0001",
                cwe="CWE-79",
                confidence=0.8,
                verified=False,
            )
        ]
    )
    recorder.finish(stop_reason="playbook_complete", error=None)
    return recorder.trace


class TestMachineReadableOutput:
    def test_sarif_is_valid_and_honest_about_verification(self, tmp_path: Path) -> None:
        trace = _trace_with_finding()
        sarif = render_sarif(trace)
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "cyberpowerfull"
        assert run["automationDetails"]["id"] == "run-sarif"
        result = run["results"][0]
        assert result["ruleId"] == "CVE-2026-0001"
        assert result["level"] == "error"
        assert result["properties"]["verified"] is False
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
            "https://example.com"
        )
        assert run["tool"]["driver"]["rules"][0]["id"] == "CVE-2026-0001"

    def test_sarif_uses_cwe_when_there_is_no_cve(self) -> None:
        recorder = TraceRecorder(
            target="example.com",
            engagement="e",
            model="none",
            backend="playbook:recon",
            scope_fingerprint="f",
        )
        recorder.add_findings(
            [
                Finding(
                    title="Missing security header",
                    severity=Severity.LOW,
                    target="example.com",
                    cwe="CWE-693",
                    tool="httpx",
                )
            ]
        )
        sarif = render_sarif(recorder.trace)
        assert sarif["runs"][0]["results"][0]["ruleId"] == "CWE-693"
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_run_manifest_records_real_step_statuses(self, tmp_path: Path) -> None:
        trace = _trace_with_finding()
        manifest = render_run_json(trace)
        assert manifest["schema"] == "cyberpowerfull.run/1"
        assert manifest["tool_status"] == {"ok": 1}
        assert manifest["tools_used"] == ["nuclei"]
        assert manifest["findings"] == 1
        assert manifest["verified_findings"] == 0

    def test_write_reports_emits_four_artifacts(self, tmp_path: Path) -> None:
        paths = write_reports(_trace_with_finding(), tmp_path / "out")
        assert set(paths) == {"report", "findings", "sarif", "run"}
        for path in paths.values():
            assert path.is_file() and path.stat().st_size > 0
        assert json.loads(paths["sarif"].read_text())["runs"][0]["results"]


class TestOneCommandCli:
    def _args(self, tmp_path: Path, *extra: str) -> list[str]:
        return [
            "127.0.0.1",
            "--i-am-authorized",
            "--scope-dir",
            str(tmp_path / "engagements"),
            "--out",
            str(tmp_path / "artifacts"),
            "--trace",
            str(tmp_path / "traces" / "latest.json"),
            "--memory",
            str(tmp_path / "artifacts" / "memory.sqlite3"),
            *extra,
        ]

    def test_plan_creates_the_scope_and_sends_nothing(self, tmp_path: Path, capsys) -> None:
        code = main(self._args(tmp_path, "--plan", "--profile", "quick"))
        out = capsys.readouterr().out
        assert code == 0
        assert (tmp_path / "engagements" / "127.0.0.1.json").is_file()
        assert "nothing was sent" in out
        assert not list((tmp_path / "artifacts").glob("report-*.md"))

    def test_without_attestation_it_refuses_and_writes_nothing(
        self, tmp_path: Path, capsys
    ) -> None:
        args = [item for item in self._args(tmp_path) if item != "--i-am-authorized"]
        code = main(args)
        captured = capsys.readouterr()
        assert code == 3
        assert "written permission" in captured.err
        assert not (tmp_path / "engagements" / "127.0.0.1.json").exists()

    def test_existing_scope_without_the_target_is_an_error(self, tmp_path: Path, capsys) -> None:
        scope_path = tmp_path / "scope.json"
        from cyberpowerfull.scope import write_scope

        write_scope(
            scope_path,
            bootstrap_scope(
                engagement="other",
                targets=["192.0.2.10"],
                authorized=True,
                authorization_ref="SOW-1",
            ),
        )
        code = main([*self._args(tmp_path), "--scope", str(scope_path), "--plan"])
        assert code == 3
        assert "not modified" in capsys.readouterr().err

    def test_bare_command_prints_a_quickstart(self, capsys) -> None:
        assert main([]) == 2
        out = capsys.readouterr().out
        assert "cpf example.com" in out
        assert "--lab" in out

    @pytest.mark.parametrize("profile", ["quick", "standard", "deep"])
    def test_dry_run_completes_and_writes_artifacts(
        self, tmp_path: Path, profile: str, capsys
    ) -> None:
        code = main(self._args(tmp_path, "--dry-run", "--profile", profile, "--max-seconds", "30"))
        captured = capsys.readouterr()
        assert code in (0, 6)
        assert "RESULT" in captured.out
        artifacts = sorted(path.name for path in (tmp_path / "artifacts").iterdir())
        assert any(name.endswith(".sarif") for name in artifacts)
        assert any(name.startswith("run-") for name in artifacts)
        assert any(name.startswith("report-") for name in artifacts)

    def test_conflicting_targets_are_a_usage_error(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main([*self._args(tmp_path), "--target", "example.com", "--plan"])
        assert excinfo.value.code == 2
