"""Lab mode and scope bootstrap: the "first run in one command" path."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from cyberpowerfull.cli import main
from cyberpowerfull.errors import ScopeError
from cyberpowerfull.lab import (
    LAB_CANDIDATE_PORTS,
    LAB_TARGET,
    LabServer,
    pick_port,
    port_is_free,
    run_local_lab,
)
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.scope import Scope, bootstrap_scope, load_scope, write_scope


def _socket_scope() -> Scope:
    return Scope(
        engagement="lab-test",
        authorized=True,
        targets=[LAB_TARGET],
    )


class TestPortSelection:
    def test_free_port_is_used(self) -> None:
        port = pick_port()
        assert port in LAB_CANDIDATE_PORTS
        assert port_is_free(port)

    def test_busy_port_is_refused(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
            taken.bind((LAB_TARGET, 0))
            taken.listen(1)
            busy = taken.getsockname()[1]
            assert not port_is_free(busy)
            with pytest.raises(RuntimeError, match="already in use"):
                pick_port(busy)

    def test_no_free_candidate_says_so(self, monkeypatch) -> None:
        monkeypatch.setattr("cyberpowerfull.lab.port_is_free", lambda *a, **k: False)
        with pytest.raises(RuntimeError, match="no free lab port"):
            pick_port()


class TestLabServer:
    def test_serves_a_real_page(self) -> None:
        import urllib.request

        port = pick_port()
        with LabServer(port) as server:
            assert server.url == f"http://{LAB_TARGET}:{port}/"
            with urllib.request.urlopen(server.url, timeout=5) as response:
                body = response.read()
                assert response.status == 200
                assert b"cyberpowerfull local lab" in body
        # The listener is gone once the context manager exits.
        assert port_is_free(port)

    def test_status_endpoint(self) -> None:
        import urllib.request

        with LabServer(pick_port()) as server:
            with urllib.request.urlopen(server.url + "health", timeout=5) as response:
                payload = json.loads(response.read())
            assert payload["status"] == "ok"


class TestLabRun:
    def test_playbook_finds_the_lab_service(self) -> None:
        with MemoryStore(":memory:", run_id="lab-run") as memory:
            result, port = run_local_lab(scope=_socket_scope(), memory=memory, playbook="network")
        assert result.executed == ["net-tcp"]
        assert any(
            str(port) in (finding.endpoint or "") for finding in result.findings
        ), f"port {port} not evidenced: {[f.endpoint for f in result.findings]}"
        assert result.trace.backend == "playbook:network"
        # Steps the host cannot run are disclosed, not silently dropped.
        assert result.trace.skipped
        assert all(":" in entry for entry in result.trace.skipped)

    def test_run_id_is_carried_into_the_trace(self) -> None:
        with MemoryStore(":memory:", run_id="lab-trace-id") as memory:
            result, _port = run_local_lab(
                scope=_socket_scope(),
                memory=memory,
                playbook="network",
                run_id="lab-trace-id",
            )
        assert result.trace.run_id == "lab-trace-id"

    def test_service_is_stopped_even_when_the_playbook_fails(self, monkeypatch) -> None:
        import cyberpowerfull.lab as lab_module

        def explode(*_args, **_kwargs):
            raise RuntimeError("playbook exploded")

        monkeypatch.setattr(
            lab_module,
            "PlaybookRunner",
            lambda **_: type("R", (), {"run": staticmethod(explode)})(),
        )
        recorded: dict[str, int] = {}
        monkeypatch.setattr(
            lab_module,
            "LabServer",
            lambda port: _RecordingServer(port, recorded),
        )
        with (
            MemoryStore(":memory:", run_id="lab-fail") as memory,
            pytest.raises(RuntimeError, match="playbook exploded"),
        ):
            run_local_lab(scope=_socket_scope(), memory=memory, playbook="network")
        assert recorded["stopped"] == 1


class _RecordingServer:
    """Stand-in that records stop() without opening a socket."""

    def __init__(self, port: int, recorded: dict[str, int]) -> None:
        self.port = port
        self._recorded = recorded

    def __enter__(self) -> _RecordingServer:
        return self

    def __exit__(self, *_exc: object) -> None:
        self._recorded["stopped"] = self._recorded.get("stopped", 0) + 1


class TestCliLab:
    def test_lab_command_runs_without_a_model(self, workdir: Path, monkeypatch, capsys) -> None:
        monkeypatch.chdir(workdir)
        code = main(
            [
                "--scope",
                str(workdir / "scope.json"),
                "--lab",
                "--quiet",
                "--out",
                str(workdir / "art"),
                "--trace",
                str(workdir / "trace.json"),
                "--memory",
                str(workdir / "memory.sqlite3"),
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "lab service: http://127.0.0.1:" in out
        assert "findings:" in out
        trace = json.loads((workdir / "trace.json").read_text())
        assert trace["backend"] == "playbook:network"
        assert any("127.0.0.1" in json.dumps(finding) for finding in trace["findings"])

    def test_lab_suggests_the_scope_command_when_none_exists(self, tmp_path: Path, capsys) -> None:
        code = main(["--scope", str(tmp_path / "missing.json"), "--lab", "--quiet"])
        err = capsys.readouterr().err
        assert code == 3
        assert "--init-scope" in err
        assert "--authorization-ref" in err

    def test_lab_refuses_a_scope_that_excludes_loopback(self, workdir: Path, capsys) -> None:
        path = workdir / "narrow.json"
        path.write_text(
            json.dumps(
                {
                    "engagement": "narrow",
                    "authorized": True,
                    "targets": ["192.0.2.10"],
                }
            )
        )
        code = main(["--scope", str(path), "--lab", "--quiet"])
        assert code == 4
        assert "not inside the authorized scope" in capsys.readouterr().err


class TestScopeBootstrap:
    def test_unauthorized_by_default(self) -> None:
        scope = bootstrap_scope(
            engagement="acme",
            targets=["app.example.test"],
            capabilities=["aggressive"],
        )
        assert scope.authorized is False
        assert [capability.value for capability in scope.capabilities] == ["aggressive"]

    def test_authorize_requires_a_reference(self) -> None:
        with pytest.raises(ScopeError, match="authorization-ref"):
            bootstrap_scope(engagement="acme", targets=["app.example.test"], authorized=True)

    def test_unknown_capability_is_rejected(self) -> None:
        with pytest.raises(ScopeError, match="unknown capability"):
            bootstrap_scope(engagement="acme", targets=["app.example.test"], capabilities=["nuke"])

    def test_written_scope_round_trips(self, tmp_path: Path) -> None:
        scope = bootstrap_scope(
            engagement="acme",
            targets=["app.example.test", "10.0.0.0/24"],
            capabilities=["external_agents"],
            authorization_ref="SOW-2026-014",
            authorized=True,
            expires=None,
        )
        path = write_scope(tmp_path / "scope.json", scope)
        loaded = load_scope(path)
        assert loaded.engagement == "acme"
        assert loaded.authorizes("app.example.test")
        assert loaded.authorizes("10.0.0.42")

    def test_existing_file_is_not_overwritten(self, tmp_path: Path) -> None:
        scope = bootstrap_scope(engagement="acme", targets=["127.0.0.1"])
        path = write_scope(tmp_path / "scope.json", scope)
        before = path.read_text()
        with pytest.raises(ScopeError, match="already exists"):
            write_scope(path, scope)
        assert path.read_text() == before
        write_scope(path, scope, force=True)

    def test_cli_init_scope_then_refuses_to_run_when_unauthorized(
        self, tmp_path: Path, capsys
    ) -> None:
        path = tmp_path / "scope.json"
        assert (
            main(
                [
                    "--init-scope",
                    str(path),
                    "--engagement",
                    "acme",
                    "--targets",
                    "app.example.test,10.0.0.5",
                ]
            )
            == 0
        )
        assert "authorized:   NO" in capsys.readouterr().out
        assert main(["--scope", str(path), "--check"]) == 3

    def test_cli_init_scope_authorized(self, tmp_path: Path, capsys) -> None:
        path = tmp_path / "scope.json"
        code = main(
            [
                "--init-scope",
                str(path),
                "--engagement",
                "acme",
                "--targets",
                "app.example.test",
                "--capabilities",
                "aggressive,external_agents",
                "--authorize",
                "--authorization-ref",
                "SOW-2026-014",
                "--expires",
                "2027-01-31",
            ]
        )
        assert code == 0
        data = json.loads(path.read_text())
        assert data["authorized"] is True
        assert data["authorization_ref"] == "SOW-2026-014"
        assert data["capabilities"] == ["aggressive", "external_agents"]
        assert data["expires"] == "2027-01-31"

    def test_cli_init_scope_needs_targets(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--init-scope", str(tmp_path / "s.json"), "--engagement", "acme"])
        assert excinfo.value.code == 2

    def test_cli_init_scope_rejects_bad_expiry(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "--init-scope",
                    str(tmp_path / "s.json"),
                    "--engagement",
                    "acme",
                    "--targets",
                    "127.0.0.1",
                    "--expires",
                    "31-01-2027",
                ]
            )
        assert excinfo.value.code == 2


class TestProjectEntrypoints:
    """The "easy to run" surface has to stay present, or the docs become a lie."""

    def test_makefile_has_the_documented_targets(self) -> None:
        makefile = (Path(__file__).resolve().parents[1] / "Makefile").read_text()
        for target in ("setup", "lab", "doctor", "toolchain", "tools", "test"):
            assert f"\n{target}:" in makefile, target
        assert "$(CLI) --lab" in makefile

    def test_installer_is_executable_and_offers_the_tool_set(self) -> None:
        installer = Path(__file__).resolve().parents[1] / "scripts" / "install.sh"
        assert installer.is_file()
        assert installer.stat().st_mode & 0o111, "install.sh must be executable"
        body = installer.read_text()
        assert "--with-tools" in body
        assert "-m venv" in body
        assert "--lab" in body
        # One unknown package must not abort the whole set; msfconsole's
        # package must be in the set.
        assert "for pkg in" in body
        assert "metasploit-framework" in body

    def test_console_scripts(self) -> None:
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
        assert 'cyberpowerfull = "cyberpowerfull.cli:main"' in pyproject
        assert 'cpf = "cyberpowerfull.cli:main"' in pyproject

    def test_readme_documents_the_easy_start(self) -> None:
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        assert "## Start here" in readme
        assert "./run.sh" in readme
        assert "cpf example.com" in readme
        assert "--i-am-authorized" in readme
        assert "make lab" in readme
        assert "--init-scope" in readme
        assert "--authorization-ref" in readme


class TestLabPortMessages:
    def test_privileged_port_says_not_permitted(self) -> None:
        with pytest.raises(RuntimeError, match=r"not permitted.*above 1023"):
            pick_port(9)

    def test_out_of_range_port_says_in_use(self) -> None:
        with pytest.raises(RuntimeError, match="already in use"):
            pick_port(70000)
