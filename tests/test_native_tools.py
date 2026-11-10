"""Native HTTP probe, CVE correlation tool, and native_scan helpers.

Everything here runs against a local ThreadingHTTPServer: no scanner binaries and
no internet access are required.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from cyberpowerfull.native_scan import (
    components_from_http,
    components_from_nmap_xml,
    http_facts,
    parse_cpe_uri,
    parse_ports,
    resolve,
    scan_ports,
)
from cyberpowerfull.tools.cve_correlate import CveCorrelateTool
from cyberpowerfull.tools.http_probe import HttpProbeTool, probe_http

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6p1">
          <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name="unknown"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/reflect":
            body = f"<html>you searched for {query.get('q', [''])[0]}</html>".encode()
            self._send(200, body, {"Content-Type": "text/html"})
        elif parsed.path == "/redirect":
            target = query.get("next", ["/"])[0]
            self._send(302, b"", {"Location": target})
        elif parsed.path == "/dberror":
            self._send(
                200,
                b"You have an error in your SQL syntax; check the manual",
                {"Content-Type": "text/plain"},
            )
        elif parsed.path == "/methods":
            self._send(200, b"ok", {"Allow": "GET, POST, PUT, DELETE"})
        elif parsed.path == "/boom":
            self._send(500, b"internal error", {})
        else:
            self._send(200, b"hello", {"Server": "nginx/1.24.0"})

    def do_OPTIONS(self) -> None:
        self._send(204, b"", {"Allow": "GET, POST, PUT, DELETE"})

    def _send(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def server() -> Iterator[tuple[str, int]]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _url(server: tuple[str, int], path: str) -> str:
    host, port = server
    return f"http://{host}:{port}{path}"


# -- port and inventory helpers -------------------------------------------------
def test_parse_ports_expands_ranges() -> None:
    assert parse_ports("80,443,8000-8002,80") == [80, 443, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        parse_ports("9000-8000")
    with pytest.raises(ValueError):
        parse_ports("70000")


def test_scan_ports_finds_the_local_listener(server: tuple[str, int]) -> None:
    host, port = server
    open_ports = scan_ports(host, [port], timeout=1.0)
    assert open_ports == [{"port": port, "open": True}]
    closed = scan_ports(host, [1], timeout=0.2)
    assert closed == []


def test_resolve_localhost() -> None:
    result = resolve("127.0.0.1")
    assert result["addresses"] == ["127.0.0.1"]
    assert result["error"] is None


def test_parse_cpe_uri_variants() -> None:
    assert parse_cpe_uri("cpe:/a:openbsd:openssh:9.6p1") == {
        "vendor": "openbsd",
        "product": "openssh",
        "version": "9.6p1",
    }
    assert parse_cpe_uri("cpe:/o:linux:linux_kernel")["version"] is None
    assert parse_cpe_uri("nonsense")["product"] is None


def test_components_from_nmap_xml_uses_cpe_and_open_ports() -> None:
    components = components_from_nmap_xml(NMAP_XML, "127.0.0.1")
    by_port = {item.port: item for item in components}
    assert set(by_port) == {22, 8080}
    assert by_port[22].product == "openssh"
    assert by_port[22].version == "9.6p1"
    assert by_port[22].source == "nmap"
    assert by_port[8080].product == "Apache httpd"
    assert components_from_nmap_xml("<not-xml", "host") == []
    assert components_from_nmap_xml("", "host") == []


def test_components_from_http_banners() -> None:
    components = components_from_http(
        [{"url": "http://host/", "server": "nginx/1.24.0", "powered_by": None}], "host"
    )
    assert len(components) == 1
    assert components[0].product == "nginx"
    assert components[0].version == "1.24.0"
    assert components_from_http([{"server": None}], "host") == []


def test_http_facts_against_local_server(server: tuple[str, int]) -> None:
    facts = http_facts(_url(server, "/"))
    assert facts["status"] == 200
    assert facts["server"] == "nginx/1.24.0"
    assert facts["error"] is None


# -- native probe ---------------------------------------------------------------
def test_probe_reflects_marker(server: tuple[str, int]) -> None:
    result = probe_http(_url(server, "/reflect?q=cpfmarker"), marker="cpfmarker")
    assert result["status"] == 200
    assert result["marker_reflected"] is True
    assert result["body_sha256"]


def test_probe_detects_external_redirect(server: tuple[str, int]) -> None:
    result = probe_http(_url(server, "/redirect?next=https%3A%2F%2Fexample.org%2F"))
    assert result["status"] == 302
    assert result["redirect"]["external"] is True
    assert result["redirect"]["host"] == "example.org"
    assert "followed" not in result, "external redirects must never be followed"


def test_probe_follows_same_host_redirect(server: tuple[str, int]) -> None:
    result = probe_http(_url(server, "/redirect?next=/"))
    assert result["redirect"]["external"] is False
    assert result["followed"]["status"] == 200


def test_probe_reports_connection_errors() -> None:
    result = probe_http("http://127.0.0.1:1/", timeout=1.0)
    assert "error" in result


def test_http_probe_tool_parses_reflection_and_db_error(server: tuple[str, int]) -> None:
    tool = HttpProbeTool()
    reflected = tool.run(
        {
            "target": _url(server, "/reflect?q=cpfmarker"),
            "marker": "cpfmarker",
        }
    )
    assert reflected.status.value == "ok", reflected.error
    titles = {finding.title for finding in reflected.findings}
    assert "Marker reflected in response body" in titles
    marker_findings = [item for item in reflected.findings if "Marker" in item.title]
    assert marker_findings and all(item.verified is False for item in marker_findings)

    dberror = tool.run({"target": _url(server, "/dberror")})
    titles = {finding.title for finding in dberror.findings}
    assert "Verbose database error returned to the client" in titles


def test_http_probe_tool_redirect_and_methods(server: tuple[str, int]) -> None:
    tool = HttpProbeTool()
    redirect = tool.run({"target": _url(server, "/redirect?next=https%3A%2F%2Fevil.example%2F")})
    assert any("Open redirect" in finding.title for finding in redirect.findings)
    assert any(finding.verified for finding in redirect.findings)

    methods = tool.run({"target": _url(server, "/methods"), "method": "OPTIONS"})
    assert any("HTTP methods advertised" in finding.title for finding in methods.findings)


def test_http_probe_tool_error_status_and_validation(server: tuple[str, int]) -> None:
    tool = HttpProbeTool()
    dead = tool.run({"target": "http://127.0.0.1:1/"})
    assert dead.status.value == "error"
    assert dead.error

    bad_path = tool.run({"target": _url(server, "/"), "path": "no-slash"})
    assert bad_path.status.value == "error"

    crlf = tool.run({"target": _url(server, "/"), "headers": {"X-Test": "a\r\nX-Evil: 1"}})
    assert crlf.status.value == "error"


# -- cve correlation tool -------------------------------------------------------
def test_cve_correlate_tool_end_to_end(tmp_path: Path) -> None:
    store_path = tmp_path / "intel.sqlite3"
    result = CveCorrelateTool().run(
        {
            "target": "127.0.0.1",
            "components": [
                {"product": "log4j", "version": "2.14.1", "source": "nmap"},
                {"product": "nginx", "version": "1.24.0", "source": "http_probe"},
            ],
            "intel_store": str(store_path),
            "min_severity": "high",
        }
    )
    assert result.status.value == "ok", result.error
    cves = {finding.cve for finding in result.findings}
    assert "CVE-2021-44228" in cves
    assert all(finding.verified is False for finding in result.findings)
    assert all(finding.tool == "cve_correlate" for finding in result.findings)
    assert result.observations

    payload = json.loads(result.stdout)
    assert payload["corpus"]["total"] >= 12


def test_cve_correlate_requires_a_component() -> None:
    result = CveCorrelateTool().run({"target": "127.0.0.1", "components": []})
    assert result.status.value == "error"
