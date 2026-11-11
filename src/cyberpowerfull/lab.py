"""A real, self-contained lab: a loopback HTTP service plus a playbook run.

This is the "make it easy to try" path, and it stays honest: the service is a
genuine socket on ``127.0.0.1`` handled by :mod:`http.server` in a background
thread, and the playbook run uses the same workers, scope checks, capability
gates and parsers as any other engagement. The findings come from a live TCP
connect and are stored in the same trace and report formats.

Nothing is stubbed. If the chosen port is busy the lab says so and stops rather
than pretending to scan something that is not there.
"""

from __future__ import annotations

import errno
import http.server
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cyberpowerfull.playbook import (
    COMMON_TCP_PORTS,
    PlaybookResult,
    PlaybookRunner,
    get_playbook,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cyberpowerfull.memory.store import MemoryStore
    from cyberpowerfull.scope import Scope
    from cyberpowerfull.trace import StepRecord

LAB_TARGET = "127.0.0.1"
LAB_DEFAULT_PLAYBOOK = "network"

#: Ports the native probe always sweeps, unprivileged, and not commonly taken by
#: a desktop service. Used in this order when the operator does not choose one.
LAB_CANDIDATE_PORTS: tuple[int, ...] = tuple(
    port for port in (8080, 8443, 9200, 27017, 6379, 5900, 8008) if port in COMMON_TCP_PORTS
)

_PAGE = b"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>cyberpowerfull lab</title></head>
<body><h1>cyberpowerfull local lab</h1>
<p>This page is served by the lab command on the loopback interface so a real
playbook run has something to find. It contains no application logic and no data.</p>
</body></html>
"""

_STATUS = b'{"status":"ok","service":"cyberpowerfull-lab"}\n'


class _LabHandler(http.server.BaseHTTPRequestHandler):
    """Minimal but real HTTP handler: fixed bodies, correct headers, no logging."""

    server_version = "cyberpowerfull-lab/1.0"
    sys_version = ""

    def do_GET(self) -> None:
        body = _STATUS if self.path.rstrip("/").endswith(("health", "status")) else _PAGE
        content_type = "application/json" if body is _STATUS else "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_PAGE)))
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        return


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _bind_errno(port: int, host: str = LAB_TARGET) -> int | None:
    """None when ``host:port`` binds; otherwise the errno that refused it."""
    if not 0 < port < 65536:
        return errno.EINVAL
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError as exc:
            return exc.errno or errno.EADDRINUSE
    return None


def port_is_free(port: int, host: str = LAB_TARGET) -> bool:
    """True when a TCP listener can be bound on ``host:port`` right now."""
    return _bind_errno(port, host) is None


def pick_port(preferred: int | None = None, host: str = LAB_TARGET) -> int:
    """Choose a port the lab can actually listen on.

    ``preferred`` is honoured when free; otherwise the first free candidate from
    :data:`LAB_CANDIDATE_PORTS`. When nothing is free a :class:`RuntimeError` is
    raised instead of silently scanning a port that the lab does not own.
    """
    if preferred is not None:
        refused = _bind_errno(preferred, host)
        if refused is not None:
            if refused in (errno.EACCES, errno.EPERM):
                raise RuntimeError(
                    f"port {preferred} is not permitted on {host} (privileged port); "
                    "pass --lab-port with a port above 1023"
                )
            raise RuntimeError(
                f"port {preferred} is already in use on {host}; pass --lab-port with a free port"
            )
        return preferred
    for candidate in LAB_CANDIDATE_PORTS:
        if port_is_free(candidate, host):
            return candidate
    raise RuntimeError(
        "no free lab port among "
        + ", ".join(str(port) for port in LAB_CANDIDATE_PORTS)
        + "; free one or pass --lab-port"
    )


@dataclass
class LabServer:
    """A running loopback HTTP service, started and stopped by the lab command."""

    port: int
    host: str = LAB_TARGET

    def __post_init__(self) -> None:
        self._httpd = _Server((self.host, self.port), _LabHandler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name=f"cpf-lab-{self.port}",
            daemon=True,
        )

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def start(self) -> LabServer:
        self._thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((self.host, self.port), timeout=0.2):
                    return self
            except OSError:
                time.sleep(0.02)
        self.stop()
        raise RuntimeError(f"lab service did not accept a connection on {self.url}")

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread.is_alive():
            self._thread.join(timeout=5)

    def __enter__(self) -> LabServer:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()


def run_local_lab(
    *,
    scope: Scope,
    memory: MemoryStore,
    playbook: str = LAB_DEFAULT_PLAYBOOK,
    port: int | None = None,
    parallel: int | None = None,
    max_steps: int | None = None,
    dry_run: bool = False,
    run_id: str | None = None,
    progress: Callable[[StepRecord], None] | None = None,
    step_start: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[PlaybookResult, int]:
    """Serve a real page on loopback, run a playbook against it, then shut down.

    Returns ``(result, port)``. The service is always stopped, including when the
    playbook raises.
    """
    chosen = pick_port(port)
    with LabServer(chosen) as server:
        runner = PlaybookRunner(
            scope=scope,
            target=LAB_TARGET,
            memory=memory,
            dry_run=dry_run,
            parallel=parallel,
            # The runner requires a concrete step budget; the CLI default is 80.
            max_steps=max_steps or 80,
            run_id=run_id,
        )
        result = runner.run(get_playbook(playbook), progress=progress, step_start=step_start)
        assert server.port == chosen
    return result, chosen


__all__ = [
    "LAB_CANDIDATE_PORTS",
    "LAB_DEFAULT_PLAYBOOK",
    "LAB_TARGET",
    "LabServer",
    "pick_port",
    "port_is_free",
    "run_local_lab",
]
