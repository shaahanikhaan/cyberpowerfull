"""CLI surface for the intel layer: status, import, correlate, payloads."""

from __future__ import annotations

import json
from pathlib import Path

from cyberpowerfull.cli import main

KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1111",
            "vendorProject": "Acme",
            "product": "Gateway",
            "vulnerabilityName": "Acme Gateway auth bypass",
            "dateAdded": "2026-01-05",
            "shortDescription": "Exploited in the wild.",
            "knownRansomwareCampaignUse": "Unknown",
        }
    ]
}


def _store(tmp_path: Path) -> str:
    return str(tmp_path / "intel.sqlite3")


def test_intel_status_seeds_and_prints(tmp_path: Path, capsys) -> None:
    rc = main(["--intel-status", "--intel-store", _store(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "advisory corpus" in out
    assert "kev entries" in out
    assert "years" in out


def test_intel_status_json(tmp_path: Path, capsys) -> None:
    rc = main(["--intel-status", "--json", "--intel-store", _store(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["total"] >= 12


def test_correlate_cli_finds_log4shell(tmp_path: Path, capsys) -> None:
    rc = main(
        [
            "--correlate",
            "log4j=2.14.1;nginx=1.24.0",
            "--target",
            "127.0.0.1",
            "--intel-store",
            _store(tmp_path),
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE-2021-44228" in out
    assert "unverified" in out


def test_correlate_cli_json_and_no_match(tmp_path: Path, capsys) -> None:
    rc = main(
        [
            "--correlate",
            "nginx=1.24.0",
            "--json",
            "--intel-store",
            _store(tmp_path),
        ]
    )
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == []

    rc = main(["--correlate", "nginx=1.24.0", "--intel-store", _store(tmp_path)])
    assert "no advisory matches" in capsys.readouterr().out


def test_import_feed_cli(tmp_path: Path, capsys) -> None:
    feed = tmp_path / "kev.json"
    feed.write_text(json.dumps(KEV), encoding="utf-8")
    store = _store(tmp_path)
    rc = main(["--import-feed", str(feed), "--intel-store", store])
    out = capsys.readouterr().out
    assert rc == 0
    assert "imported=1" in out

    rc = main(["--correlate", "acme gateway", "--json", "--intel-store", store])
    findings = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert any(item["cve"] == "CVE-2026-1111" for item in findings)


def test_import_feed_missing_file_reports_error(tmp_path: Path, capsys) -> None:
    rc = main(["--import-feed", str(tmp_path / "absent.json"), "--intel-store", _store(tmp_path)])
    captured = capsys.readouterr()
    assert rc != 0
    assert "not found" in captured.err


def test_payload_cli_requires_target(capsys) -> None:
    rc = main(["--payload", "xss"])
    assert rc != 0


def test_payload_cli_prints_request_and_signal(capsys) -> None:
    rc = main(["--payload", "sqli", "--target", "http://127.0.0.1/search", "--payload-param", "id"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "sql_injection" in out
    assert "expect:" in out
    assert "known skills" in out


def test_payload_cli_json(capsys) -> None:
    rc = main(["--payload", "xss", "--target", "http://127.0.0.1/", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert isinstance(payload, list) and payload
    assert {item["skill"] for item in payload} == {"xss"}
    assert payload[0]["curl"][0] == "curl"
