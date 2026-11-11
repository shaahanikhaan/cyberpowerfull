"""SARIF 2.1.0 conformance: our emitted SARIF must validate against the official
OASIS schema (vendored at tests/fixtures/sarif-schema-2.1.0.json, sha 0f58372),
and every physicalLocation URI must be a valid URI reference for the endpoint
forms we emit (URL, host:port, file:line, bare host, empty)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
import pytest

from cyberpowerfull.models import Finding
from cyberpowerfull.reporting import render_sarif
from cyberpowerfull.trace import TraceRecorder
from tests.test_trace_reporting import sample_finding, sample_trace

SCHEMA = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "sarif-schema-2.1.0.json").read_text(
        encoding="utf-8"
    )
)


def _trace_with(*findings: Finding):
    recorder = TraceRecorder(
        target="127.0.0.1",
        engagement="sarif-conformance",
        model="auto-1",
        backend="auto",
        scope_fingerprint="deadbeef" * 8,
        run_id="run-sarif",
    )
    recorder.add_findings(list(findings))
    return recorder.finish(stop_reason="agent_terminated")


def _finding(**overrides) -> Finding:
    base = sample_finding().model_dump()
    base.update(overrides)
    return Finding(**base)


def _uris(document: dict) -> list[str]:
    uris = []
    for run in document["runs"]:
        for result in run.get("results", []):
            for location in result.get("locations", []):
                uris.append(location["physicalLocation"]["artifactLocation"]["uri"])
    return uris


class TestSarifSchema:
    def test_sample_trace_validates(self) -> None:
        jsonschema.validate(render_sarif(sample_trace()), SCHEMA)

    @pytest.mark.parametrize(
        "endpoint,target",
        [
            ("http://127.0.0.1/item?id=1", "127.0.0.1"),  # URL
            ("127.0.0.1:443", "127.0.0.1"),  # host:port
            ("app/views.py:42", "local-repo"),  # file:line (code playbook)
            ("", "example.com"),  # empty endpoint falls back to target
            ("example.com", "example.com"),  # bare host
            ("https://app.example.test:8443/a/b?x=1#f", "app.example.test"),  # full URL
        ],
    )
    def test_endpoint_forms_validate_and_point_somewhere(self, endpoint: str, target: str) -> None:
        trace = _trace_with(_finding(endpoint=endpoint, target=target))
        document = render_sarif(trace)
        jsonschema.validate(document, SCHEMA)
        (uri,) = _uris(document)
        assert uri and uri != "unknown"
        # A valid URI reference: parses and carries no whitespace.
        assert uri == uri.strip() and not any(char.isspace() for char in uri)
        assert urlsplit(uri if "://" in uri else f"scheme:{uri}")

    def test_empty_run_validates(self) -> None:
        document = render_sarif(_trace_with())
        jsonschema.validate(document, SCHEMA)
        assert document["runs"][0]["results"] == []

    def test_rule_index_matches_rules_array(self) -> None:
        trace = _trace_with(
            _finding(title="SQL injection here", cwe="CWE-89", cve=""),
            _finding(title="Reflected XSS there", cwe="CWE-79", cve=""),
        )
        document = render_sarif(trace)
        jsonschema.validate(document, SCHEMA)
        rules = document["runs"][0]["tool"]["driver"]["rules"]
        for result in document["runs"][0]["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
