"""Intel layer: versioning, store merging, feed import, and correlation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from cyberpowerfull.errors import CyberpowerfullError
from cyberpowerfull.intel import (
    Advisory,
    AdvisoryStore,
    Component,
    CveCorrelator,
    correlate,
    import_feed,
    load_store,
    product_matches,
    require_store,
    seed_bundled,
)
from cyberpowerfull.intel.importer import detect_format, parse_cpe
from cyberpowerfull.intel.models import VersionRange
from cyberpowerfull.intel.versioning import (
    compare_versions,
    normalize_product,
    version_in_range,
    version_key,
)
from cyberpowerfull.models import Severity


# -- versioning -----------------------------------------------------------------
@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("2.4.49", "2.4.50", -1),
        ("2.15.0", "2.14.1", 1),
        ("8.5p1", "9.8p1", -1),
        ("9.6p1", "9.6p1", 0),
        ("1.0", "1.0.1", -1),
        ("1.0-rc1", "1.0", -1),
        ("1.0", "1.0-rc1", 1),
        ("2.0-beta9", "2.0.0", -1),
        ("10.2.9", "10.2.10", -1),
    ],
)
def test_compare_versions_ordering(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected


def test_version_key_separates_prerelease_and_numbers() -> None:
    assert any(rank == 0 for rank, _ in version_key("1.0-rc1"))
    assert all(rank == 2 for rank, _ in version_key("1.0"))
    assert version_key("1.0a")[-1][0] == 1


@pytest.mark.parametrize(
    ("spec", "version", "expected"),
    [
        ({"introduced": "2.0.0", "fixed": "2.15.0"}, "2.14.1", True),
        ({"introduced": "2.0.0", "fixed": "2.15.0"}, "2.15.0", False),
        ({"introduced": "2.0.0", "fixed": "2.15.0"}, "1.2.17", False),
        ({"introduced": "9.0.0", "last_affected": "9.0.30"}, "9.0.30", True),
        ({"introduced": "9.0.0", "last_affected": "9.0.30"}, "9.0.31", False),
        ({"exact": "2.4.49"}, "2.4.49", True),
        ({"exact": "2.4.49"}, "2.4.50", False),
        ({}, "anything", True),
        ({"introduced": "8.5p1", "fixed": "9.8p1"}, "8.9p1", True),
    ],
)
def test_version_in_range(spec: dict, version: str, expected: bool) -> None:
    assert version_in_range(version, VersionRange(**spec)) is expected


def test_version_in_range_rejects_missing_version_when_bounded() -> None:
    assert version_in_range(None, VersionRange(introduced="1.0", fixed="2.0")) is False


@pytest.mark.parametrize(
    ("product", "advisory_product", "expected"),
    [
        ("apache httpd", "http_server", True),
        ("httpd", "http_server", True),
        ("Apache HTTP Server", "http_server", True),
        ("nginx", "http_server", False),
        ("big-ip", "big_ip", True),
        ("BIG IP", "big_ip", True),
        ("OpenSSH", "openssh", True),
        ("spring-core", "spring_framework", True),
        ("tomcat", "tomcat", True),
        ("postgresql", "postgres", True),
    ],
)
def test_product_matches(product: str, advisory_product: str, expected: bool) -> None:
    assert product_matches(product, advisory_product) is expected


def test_normalize_product_variants() -> None:
    assert normalize_product("Apache-HTTP_Server") == "apachehttpserver"
    assert normalize_product("  OpenSSH ") == "openssh"
    assert normalize_product("") == ""


def test_version_range_model_contains() -> None:
    assert VersionRange(introduced="2.0.0", fixed="2.15.0").contains("2.14.1") is True
    assert VersionRange(introduced="2.0.0", fixed="2.15.0").contains("2.15.0") is False


# -- store / importer -----------------------------------------------------------
def _advisory(**overrides) -> Advisory:
    data = {
        "id": "CVE-2099-0001",
        "source": "custom",
        "title": "synthetic",
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "product": "demo",
        "vendor": "acme",
        "ranges": [{"introduced": "1.0", "fixed": "1.2"}],
    }
    data.update(overrides)
    return Advisory(**data)


def test_store_upsert_counts_and_merges() -> None:
    store = AdvisoryStore(":memory:")
    first = store.upsert_many([_advisory()], source="custom")
    assert (first.imported, first.updated) == (1, 0)

    second = store.upsert_many([_advisory(severity=Severity.CRITICAL, kev=True, cvss=9.8)])
    assert (second.imported, second.updated) == (0, 1)
    merged = store.get("CVE-2099-0001")
    assert merged is not None
    assert merged.severity is Severity.CRITICAL
    assert merged.kev is True
    assert merged.cvss == 9.8
    store.close()


def test_store_rejects_malformed_ids_and_sorts_stats() -> None:
    with pytest.raises(ValidationError):
        _advisory(id="NOT-A-CVE")
    with pytest.raises(ValidationError):
        _advisory(id="CVE-24-1")
    store = AdvisoryStore(":memory:")
    summary = store.upsert_many(
        [
            _advisory(id="CVE-2024-0002", published="2024-05-01"),
            _advisory(id="CVE-2021-0003", published="2021-01-01", kev=True),
            _advisory(id="GHSA-aaaa-bbbb-cccc", published="2023-06-01"),
        ]
    )
    assert summary.imported == 3
    store.upsert_many([_advisory(id="CVE-2024-0002", published="2024-05-01")])

    stats = store.stats()
    assert stats["total"] == 3
    assert stats["years"] == ["2021", "2023", "2024"]
    assert stats["kev"] == 1
    assert stats["severities"]["high"] == 3
    store.close()


def test_parse_cpe() -> None:
    parsed = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    assert parsed == {"vendor": "apache", "product": "log4j", "version": "2.14.1"}
    assert parse_cpe("not-a-cpe")["product"] is None


NVD2_FEED = {
    "resultsPerPage": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2025-9999",
                "published": "2025-03-04T10:00:00.000",
                "descriptions": [
                    {"lang": "es", "value": "descripcion"},
                    {"lang": "en", "value": "An issue in AcmeWidget 3.x allows bypass."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.1,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:acme:acme_widget:3.0:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "3.0.0",
                                        "versionEndExcluding": "3.4.2",
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [{"url": "https://example.org/advisory"}],
            }
        }
    ],
}


KEV_FEED = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2025-9999",
            "vendorProject": "Acme",
            "product": "AcmeWidget",
            "vulnerabilityName": "AcmeWidget auth bypass",
            "dateAdded": "2025-03-10",
            "dueDate": "2025-03-31",
            "shortDescription": "Known exploited bypass.",
            "knownRansomwareCampaignUse": "Known",
        }
    ]
}


def test_import_nvd2_and_kev_merge(tmp_path: Path) -> None:
    nvd_path = tmp_path / "nvd.json"
    kev_path = tmp_path / "kev.json"
    nvd_path.write_text(json.dumps(NVD2_FEED), encoding="utf-8")
    kev_path.write_text(json.dumps(KEV_FEED), encoding="utf-8")

    assert detect_format(NVD2_FEED) == "nvd2"
    assert detect_format(KEV_FEED) == "kev"

    store = AdvisoryStore(":memory:")
    summary = import_feed(store, nvd_path)
    assert summary.imported == 1
    advisory = store.get("CVE-2025-9999")
    assert advisory is not None
    assert advisory.severity is Severity.CRITICAL
    assert advisory.cvss == 9.1
    assert advisory.cwe == "CWE-287"
    assert advisory.product == "acme_widget"
    assert advisory.affects("acme widget", "3.1.0") is True
    assert advisory.affects("acme widget", "3.4.2") is False

    kev_summary = import_feed(store, kev_path, "kev")
    assert kev_summary.updated == 1
    merged = store.get("CVE-2025-9999")
    assert merged is not None and merged.kev and merged.exploited_in_wild
    assert merged.kev_due == "2025-03-31"
    assert merged.cvss == 9.1  # NVD scoring survives the KEV merge
    assert "ransomware" in (merged.note or "")
    store.close()


def test_import_nvd11_feed(tmp_path: Path) -> None:
    feed = {
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-2019-0001"},
                    "description": {
                        "description_data": [{"lang": "en", "value": "Legacy format issue."}]
                    },
                },
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}
                },
                "publishedDate": "2019-01-02T00:00Z",
            }
        ]
    }
    path = tmp_path / "nvd11.json"
    path.write_text(json.dumps(feed), encoding="utf-8")
    store = AdvisoryStore(":memory:")
    summary = import_feed(store, path)
    assert summary.imported == 1
    advisory = store.get("CVE-2019-0001")
    assert advisory is not None and advisory.severity is Severity.MEDIUM
    store.close()


def test_import_missing_or_invalid_feed(tmp_path: Path) -> None:
    store = AdvisoryStore(":memory:")
    with pytest.raises(CyberpowerfullError):
        import_feed(store, tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(CyberpowerfullError):
        import_feed(store, bad)
    with pytest.raises(CyberpowerfullError):
        import_feed(store, bad, "unknown-format")
    store.close()


def test_custom_feed_counts_skipped_rows(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    path.write_text(
        json.dumps(
            {
                "advisories": [
                    _advisory(id="CVE-2099-0100").model_dump(mode="json"),
                    {"id": "broken"},
                ]
            }
        ),
        encoding="utf-8",
    )
    store = AdvisoryStore(":memory:")
    summary = import_feed(store, path, "custom")
    assert summary.imported == 1
    assert summary.errors == 1
    store.close()


# -- correlation ----------------------------------------------------------------
def test_bundled_seed_and_log4shell_match() -> None:
    store = load_store(":memory:")
    stats = store.stats()
    assert stats["total"] >= 12
    assert stats["kev"] >= 8

    findings = correlate(
        [Component(product="log4j", version="2.14.1", source="nmap", confidence=0.8)],
        store=store,
        target="127.0.0.1",
    )
    cves = {finding.cve for finding in findings}
    assert "CVE-2021-44228" in cves
    finding = next(item for item in findings if item.cve == "CVE-2021-44228")
    assert finding.verified is False
    assert finding.severity is Severity.CRITICAL
    assert finding.tool == "cve_correlate"
    assert "fixed in 2.15.0" in finding.remediation
    assert finding.cvss == 10.0
    store.close()


def test_correlator_skips_fixed_and_unrelated_versions() -> None:
    store = load_store(":memory:")
    correlator = CveCorrelator(store)
    assert correlator.match_component(Component(product="log4j", version="2.17.1")) == []
    assert correlator.match_component(Component(product="nginx", version="1.24.0")) == []
    matches = correlator.match_component(Component(product="openssh", version="9.6p1"))
    assert [match.advisory.id for match in matches] == ["CVE-2024-6387"]
    store.close()


def test_unversioned_component_caps_severity_and_confidence() -> None:
    store = load_store(":memory:")
    matches = CveCorrelator(store).match_component(Component(product="big-ip"))
    assert matches, "product-level advisory should still surface as a candidate"
    match = matches[0]
    assert match.advisory.id == "CVE-2022-1388"
    assert match.severity is Severity.MEDIUM
    assert match.confidence <= 0.6
    assert "unversioned" in match.rationale
    store.close()


def test_min_cvss_filter_and_deduplication() -> None:
    store = load_store(":memory:")
    component = Component(product="log4j", version="2.14.1")
    high_only = correlate([component], store=store, target="host", min_cvss=9.5)
    everything = correlate([component], store=store, target="host")
    assert all((item.cvss or 0) >= 9.5 for item in high_only)
    assert len(everything) >= len(high_only)
    seen: set[str] = set()
    once = correlate([component, component], store=store, target="host", seen=seen)
    twice = correlate([component, component], store=store, target="host", seen=seen)
    assert once and not twice, "the same CVE/component pair must not repeat"


def test_require_store_seeds_a_fresh_corpus(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.sqlite3"
    store = require_store(fresh)
    try:
        assert store.stats()["total"] >= 12
    finally:
        store.close()


def test_seed_bundled_is_idempotent() -> None:
    store = AdvisoryStore(":memory:")
    seed_bundled(store)
    first = store.stats()["total"]
    seed_bundled(store)
    assert store.stats()["total"] == first
    store.close()
