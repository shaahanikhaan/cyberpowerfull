"""Payload catalogue and generator: coverage, safety guard, request rendering."""

from __future__ import annotations

import base64
import json

import pytest
from pydantic import ValidationError

from cyberpowerfull.errors import CyberpowerfullError, PolicyViolation
from cyberpowerfull.payloads import (
    DEFAULT_MARKER,
    PAYLOADS,
    Payload,
    audit,
    build_jwt_none,
    catalog,
    generate,
    render_payload,
    resolve_skill,
    select,
    skills,
)
from cyberpowerfull.tools.payload import PayloadArgs, PayloadTool


def test_catalogue_is_unique_and_clean() -> None:
    ids = [item.id for item in PAYLOADS]
    assert len(ids) == len(set(ids))
    report = audit()
    assert report.clean, report.violations
    assert report.total == len(PAYLOADS)
    assert report.total >= 50


def test_catalogue_covers_the_expected_skills() -> None:
    covered = set(skills())
    expected = {
        "xss",
        "sql_injection",
        "ssti",
        "ssrf",
        "path_traversal",
        "open_redirect",
        "command_injection",
        "xxe",
        "jwt",
        "idor",
        "mass_assignment",
        "cache_poisoning",
        "crlf_injection",
        "api_enumeration",
    }
    assert expected <= covered


def test_every_payload_documents_its_signal() -> None:
    for item in PAYLOADS:
        assert item.expected_signal, item.id
        assert item.technique, item.id
        assert item.context, item.id


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("sqli", "sql_injection"),
        ("SQL", "sql_injection"),
        ("cmdi", "command_injection"),
        ("lfi", "path_traversal"),
        ("cache", "cache_poisoning"),
    ],
)
def test_skill_aliases(alias: str, canonical: str) -> None:
    assert resolve_skill(alias) == canonical


def test_select_by_skill_and_ids() -> None:
    xss = select("xss")
    assert {item.skill for item in xss} == {"xss"}
    picked = select(ids=["xss_html_script"])
    assert [item.id for item in picked] == ["xss_html_script"]
    assert select(None, ids=["does-not-exist"]) == ()


def test_catalog_is_serialisable() -> None:
    payload = json.dumps(catalog())
    assert "xss_html_script" in payload


def test_query_rendering_encodes_the_value() -> None:
    entry = next(item for item in PAYLOADS if item.id == "xss_html_script")
    rendered = render_payload(entry, target="http://127.0.0.1:8080/search", param="q")
    assert rendered.url.startswith("http://127.0.0.1:8080/search?q=")
    assert "%3Cscript%3E" in rendered.url
    assert DEFAULT_MARKER in rendered.url
    assert rendered.method == "GET"
    assert rendered.expected_signal


def test_path_rendering_joins_cleanly() -> None:
    entry = next(item for item in PAYLOADS if item.id == "api_openapi_path")
    rendered = render_payload(entry, target="http://host/api")
    assert rendered.url == "http://host/api/openapi.json"


def test_header_rendering_for_jwt_and_cache_poisoning() -> None:
    jwt_entry = next(item for item in PAYLOADS if item.id == "jwt_alg_none")
    rendered = render_payload(jwt_entry, target="http://host/admin")
    assert rendered.headers["Authorization"].startswith("Bearer eyJ")
    assert rendered.url == "http://host/admin"

    cache_entry = next(item for item in PAYLOADS if item.id == "cache_poison_forwarded_host")
    poisoned = render_payload(cache_entry, target="http://host/")
    assert DEFAULT_MARKER in poisoned.headers["X-Forwarded-Host"]


def test_body_rendering_sets_content_type() -> None:
    xxe = next(item for item in PAYLOADS if item.id == "xxe_internal_entity")
    rendered = render_payload(xxe, target="http://host/xml")
    assert rendered.headers["Content-Type"] == "application/xml"
    assert rendered.body is not None and DEFAULT_MARKER in rendered.body
    assert rendered.url == "http://host/xml"

    graphql = next(item for item in PAYLOADS if item.id == "api_graphql_introspection")
    rendered_json = render_payload(graphql, target="http://host/graphql")
    assert rendered_json.headers["Content-Type"] == "application/json"


def test_jwt_none_token_is_unsigned_and_marked() -> None:
    token = build_jwt_none(marker="cpfabc", subject="admin")
    header, claims, signature = token.split(".")
    assert signature == ""
    decoded_header = json.loads(base64.urlsafe_b64decode(header + "=="))
    decoded_claims = json.loads(base64.urlsafe_b64decode(claims + "=="))
    assert decoded_header == {"alg": "none", "typ": "JWT"}
    assert decoded_claims["marker"] == "cpfabc"
    assert decoded_claims["role"] == "admin"


def test_generate_limits_and_unknown_skill() -> None:
    rendered = generate("xss", target="http://host/search", max_payloads=2)
    assert len(rendered) == 2
    with pytest.raises(CyberpowerfullError):
        generate("no-such-skill", target="http://host/")


def test_forbidden_payload_is_refused() -> None:
    bad = Payload(
        id="bad",
        skill="command_injection",
        technique="destructive",
        context="shell",
        template="; rm -rf /",
        expected_signal="nope",
    )
    assert bad.contains_forbidden() == "rm -rf"
    with pytest.raises(PolicyViolation):
        render_payload(bad, target="http://host/")


def test_payload_tool_generates_without_findings() -> None:
    tool = PayloadTool()
    result = tool.run(
        {
            "target": "http://127.0.0.1:8080/search",
            "skill": "sqli",
            "param": "id",
            "max_payloads": 3,
        }
    )
    assert result.status.value == "ok", result.error
    assert result.findings == []
    payload = json.loads(result.stdout)
    assert payload["count"] == 3
    assert payload["skill"] == "sql_injection"
    assert all(item["skill"] == "sql_injection" for item in payload["payloads"])
    assert result.observations, "the model must see what was generated"


def test_payload_tool_validates_skill_and_marker() -> None:
    tool = PayloadTool()
    unknown = tool.run({"target": "http://127.0.0.1/", "skill": "wat"})
    assert unknown.status.value == "error"
    assert "unknown payload skill" in (unknown.error or "")

    bad_marker = tool.run({"target": "http://127.0.0.1/", "skill": "xss", "marker": "a b"})
    assert bad_marker.status.value == "error"


def test_payload_args_reject_bad_marker_directly() -> None:
    with pytest.raises(ValidationError):
        PayloadArgs(target="http://127.0.0.1/", marker="-")
