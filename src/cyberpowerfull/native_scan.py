"""Native scanning helpers used by the bash toolkit.

Pure standard library: port discovery, HTTP banner facts, name resolution, and
component inventory from nmap XML. The bash scripts in ``tools/bash`` call this
module so their behaviour is testable Python, not hand-rolled shell parsing.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from cyberpowerfull.errors import ScopeViolation
from cyberpowerfull.intel.models import Component
from cyberpowerfull.tools.http_probe import probe_http

#: Ports worth a connect attempt on a first pass (service diversity, no sweep).
COMMON_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    3000,
    3306,
    3389,
    5000,
    5432,
    5900,
    6379,
    8000,
    8008,
    8080,
    8081,
    8443,
    8888,
    9000,
    9090,
    9200,
    11211,
    27017,
)


def parse_ports(spec: str) -> list[int]:
    """Parse ``80,443,8000-8010`` into a sorted, de-duplicated port list."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"invalid port range: {chunk!r}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    invalid = [port for port in ports if not 1 <= port <= 65535]
    if invalid:
        raise ValueError(f"ports out of range: {invalid[:5]}")
    return sorted(ports)


def scan_ports(
    host: str,
    ports: Iterable[int] = COMMON_PORTS,
    *,
    timeout: float = 0.6,
    workers: int = 32,
) -> list[dict[str, Any]]:
    """TCP connect scan. Returns one record per open port, sorted."""
    results: list[dict[str, Any]] = []

    def probe(port: int) -> dict[str, Any] | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return {"port": port, "open": True}
        except (OSError, ValueError):
            return None

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 128))) as pool:
        for record in pool.map(probe, list(ports)):
            if record is not None:
                results.append(record)
    return sorted(results, key=lambda item: item["port"])


def resolve(host: str) -> dict[str, Any]:
    """Resolve a hostname to addresses without raising for lookup failures."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        return {"host": host, "addresses": [], "error": f"{exc.__class__.__name__}: {exc}"}
    addresses = sorted({info[4][0] for info in infos})
    return {"host": host, "addresses": addresses, "error": None}


def http_facts(url: str, *, timeout: float = 8.0) -> dict[str, Any]:
    """Banner-level HTTP facts for one URL."""
    result = probe_http(url, timeout=timeout, capture_bytes=16384)
    headers = result.get("headers") or {}
    return {
        "url": url,
        "status": result.get("status"),
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "content_type": headers.get("content-type"),
        "location": result.get("location"),
        "error": result.get("error"),
    }


def parse_cpe_uri(value: str) -> dict[str, str | None]:
    """Parse a CPE 2.2 URI (``cpe:/a:apache:http_server:2.4.49``)."""
    text = value.strip()
    if not text.startswith("cpe:/"):
        return {"vendor": None, "product": None, "version": None}
    parts = text[len("cpe:/") :].split(":")
    if len(parts) >= 2:
        parts = parts[1:]
    vendor = parts[0] if len(parts) > 0 and parts[0] not in {"*", "-"} else None
    product = parts[1] if len(parts) > 1 and parts[1] not in {"*", "-"} else None
    version = parts[2] if len(parts) > 2 and parts[2] not in {"*", "-"} else None
    return {"vendor": vendor, "product": product, "version": version}


def components_from_nmap_xml(xml_text: str, target: str) -> list[Component]:
    """Parse nmap XML into components (CPE data preferred over free-text banners)."""
    components: list[Component] = []
    if not xml_text.strip():
        return components
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return components
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        port_id = port.get("portid")
        service = port.find("service")
        if service is None:
            continue
        product = service.get("product")
        version = service.get("version")
        vendor = None
        for cpe in service.findall("cpe"):
            parsed = parse_cpe_uri(cpe.text or "")
            if parsed.get("product"):
                vendor = parsed.get("vendor") or vendor
                product = parsed.get("product") or product
                version = parsed.get("version") or version
                break
        name = service.get("name")
        if not product and name in {None, "unknown"}:
            continue
        components.append(
            Component(
                product=str(product or name),
                vendor=vendor,
                version=str(version) if version else None,
                port=int(port_id) if port_id and port_id.isdigit() else None,
                endpoint=f"{target}:{port_id}",
                source="nmap",
                confidence=0.8 if product else 0.5,
            )
        )
    return components


def components_from_nmap(path: str | Path, target: str) -> list[Component]:
    xml_text = Path(path).read_text(encoding="utf-8", errors="replace")
    return components_from_nmap_xml(xml_text, target)


def components_from_http(records: Iterable[dict[str, Any]], target: str) -> list[Component]:
    """Build components from ``http_facts`` records (Server / X-Powered-By)."""
    components: list[Component] = []
    for record in records:
        for banner_key in ("server", "powered_by"):
            banner = record.get(banner_key)
            if not isinstance(banner, str) or not banner.strip():
                continue
            product, _, remainder = banner.strip().partition("/")
            version = remainder.split(" ")[0] if remainder else None
            components.append(
                Component(
                    product=product,
                    version=version or None,
                    endpoint=record.get("url") or target,
                    source="http_probe",
                    confidence=0.6,
                )
            )
    return components


def _load_scope(path: str | None):
    if not path:
        return None
    from cyberpowerfull.scope import load_scope

    return load_scope(path)


def _require(scope: Any, target: str) -> None:
    if scope is not None:
        scope.require(target)


def _dispatch(args: argparse.Namespace) -> Any:
    scope = _load_scope(args.scope)
    if args.command == "resolve":
        _require(scope, args.host)
        return resolve(args.host)
    if args.command == "ports":
        _require(scope, args.host)
        ports = COMMON_PORTS if args.ports == "common" else parse_ports(args.ports)
        return {"host": args.host, "open_ports": scan_ports(args.host, ports, timeout=args.timeout)}
    if args.command == "http":
        from urllib.parse import urlparse

        _require(scope, urlparse(args.url).hostname or args.url)
        return http_facts(args.url)
    if args.command == "inventory":
        components: list[Component] = []
        if args.nmap_xml:
            components.extend(components_from_nmap(args.nmap_xml, args.target))
        if args.http_json:
            records = json.loads(Path(args.http_json).read_text(encoding="utf-8"))
            components.extend(components_from_http(records, args.target))
        payload = {
            "target": args.target,
            "count": len(components),
            "components": [json.loads(component.model_dump_json()) for component in components],
        }
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload
    raise ValueError(f"unknown command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cyberpowerfull.native_scan",
        description="Native scanning helpers for the cyberpowerfull bash toolkit.",
    )
    parser.add_argument(
        "--scope", metavar="PATH", help="scope.json; when given, every target is gated"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    resolve_parser = sub.add_parser("resolve", help="resolve a hostname")
    resolve_parser.add_argument("--host", required=True)

    ports_parser = sub.add_parser("ports", help="TCP connect scan")
    ports_parser.add_argument("--host", required=True)
    ports_parser.add_argument("--ports", default="common")
    ports_parser.add_argument("--timeout", type=float, default=0.6)

    http_parser = sub.add_parser("http", help="HTTP banner facts")
    http_parser.add_argument("--url", required=True)

    inventory_parser = sub.add_parser("inventory", help="build components from scan output")
    inventory_parser.add_argument("--target", required=True)
    inventory_parser.add_argument("--nmap-xml", default=None)
    inventory_parser.add_argument("--http-json", default=None, help="JSON list of http facts")
    inventory_parser.add_argument("--out", default=None)

    args = parser.parse_args(argv)
    try:
        payload = _dispatch(args)
    except ScopeViolation as exc:
        print(f"out of scope: {exc}", file=sys.stderr)
        return 4
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = [
    "COMMON_PORTS",
    "components_from_http",
    "components_from_nmap",
    "components_from_nmap_xml",
    "http_facts",
    "main",
    "parse_cpe_uri",
    "parse_ports",
    "resolve",
    "scan_ports",
]
