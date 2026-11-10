"""Offline advisory import: NVD 2.0/1.1, CISA KEV, and the native format.

Nothing here touches the network. The operator fetches a feed with
``tools/bash/cve_hunt.sh --import-feed`` (or any other means) and imports the
file; the agent then correlates imported advisories against observed components.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberpowerfull.errors import CyberpowerfullError
from cyberpowerfull.intel.models import Advisory, ImportSummary, VersionRange
from cyberpowerfull.intel.store import AdvisoryStore
from cyberpowerfull.models import Severity


def load_json(path: str | Path) -> Any:
    feed_path = Path(path)
    if not feed_path.exists():
        raise CyberpowerfullError(f"advisory feed not found: {feed_path}")
    try:
        return json.loads(feed_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CyberpowerfullError(f"advisory feed is not valid JSON: {feed_path}: {exc}") from exc


def detect_format(payload: Any) -> str:
    """Best-effort format detection for ``--feed-format auto``."""
    if isinstance(payload, list):
        return "custom"
    if not isinstance(payload, dict):
        return "unknown"
    if "CVE_Items" in payload:
        return "nvd11"
    if "vulnerabilities" in payload:
        items = payload.get("vulnerabilities") or []
        first = items[0] if items and isinstance(items[0], dict) else {}
        if "cve" in first:
            return "nvd2"
        if "cveID" in first:
            return "kev"
        return "unknown"
    if "advisories" in payload:
        return "custom"
    if "cve" in payload:
        return "nvd2-single"
    return "unknown"


def _severity_from(score: float | None, label: str | None) -> Severity:
    if label:
        return Severity.coerce(label)
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def parse_cpe(criteria: str) -> dict[str, str | None]:
    """Extract vendor, product and version from a CPE 2.3 string."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return {"vendor": None, "product": None, "version": None}
    vendor = parts[3] if parts[3] not in {"*", "-"} else None
    product = parts[4] if parts[4] not in {"*", "-"} else None
    version = parts[5] if parts[5] not in {"*", "-"} else None
    return {"vendor": vendor, "product": product, "version": version}


def _nvd2_advisory(item: dict[str, Any]) -> Advisory | None:
    cve = item.get("cve")
    if not isinstance(cve, dict) or not cve.get("id"):
        return None
    identifier = str(cve["id"]).upper()
    description = ""
    for entry in cve.get("descriptions", []) or []:
        if isinstance(entry, dict) and entry.get("lang") == "en":
            description = str(entry.get("value") or "")
            break
    metrics = cve.get("metrics", {}) or {}
    score: float | None = None
    label: str | None = None
    vector: str | None = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = entries[0] if isinstance(entries[0], dict) else {}
        data = entry.get("cvssData", {}) or {}
        raw_score = data.get("baseScore")
        if isinstance(raw_score, int | float):
            score = float(raw_score)
        label = data.get("baseSeverity") or entry.get("baseSeverity")
        vector = data.get("vectorString") or vector
        break
    cwe = None
    for weakness in cve.get("weaknesses", []) or []:
        for entry in weakness.get("description", []) or []:
            value = str(entry.get("value") or "")
            if value.upper().startswith("CWE-"):
                cwe = value.upper()
                break
        if cwe:
            break
    ranges: list[VersionRange] = []
    vendor: str | None = None
    product: str | None = None
    for configuration in cve.get("configurations", []) or []:
        for node in configuration.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable", True):
                    continue
                cpe = parse_cpe(str(match.get("criteria") or ""))
                vendor = vendor or cpe["vendor"]
                product = product or cpe["product"]
                version_range = VersionRange(
                    introduced=match.get("versionStartIncluding"),
                    fixed=match.get("versionEndExcluding"),
                    last_affected=match.get("versionEndIncluding"),
                    exact=(
                        cpe["version"]
                        if not (
                            match.get("versionStartIncluding") or match.get("versionEndExcluding")
                        )
                        else None
                    ),
                )
                if not version_range.is_empty():
                    ranges.append(version_range)
    references = [
        str(ref.get("url"))
        for ref in (cve.get("references", []) or [])
        if isinstance(ref, dict) and ref.get("url")
    ][:10]
    return Advisory(
        id=identifier,
        source="nvd",
        title=(description[:200] or identifier),
        description=description,
        severity=_severity_from(score, label),
        cvss=score,
        cvss_vector=vector,
        published=str(cve.get("published") or "")[:10] or None,
        cwe=cwe,
        vendor=vendor,
        product=product,
        ranges=ranges,
        references=references,
    )


def _nvd11_advisory(item: dict[str, Any]) -> Advisory | None:
    cve = item.get("cve", {}) or {}
    meta = cve.get("CVE_data_meta", {}) or {}
    identifier = str(meta.get("ID") or "").upper()
    if not identifier:
        return None
    description = ""
    for entry in (cve.get("description", {}) or {}).get("description_data", []) or []:
        if entry.get("lang") == "en":
            description = str(entry.get("value") or "")
            break
    impact = item.get("impact", {}) or {}
    score: float | None = None
    label: str | None = None
    for key in ("baseMetricV3", "baseMetricV2"):
        block = impact.get(key) or {}
        data = block.get("cvssV3") or block.get("cvssV2") or {}
        raw_score = data.get("baseScore")
        if isinstance(raw_score, int | float):
            score = float(raw_score)
            label = data.get("baseSeverity")
            break
    return Advisory(
        id=identifier,
        source="nvd",
        title=(description[:200] or identifier),
        description=description,
        severity=_severity_from(score, label),
        cvss=score,
        published=str(item.get("publishedDate") or "")[:10] or None,
    )


def import_nvd(store: AdvisoryStore, path: str | Path) -> ImportSummary:
    payload = load_json(path)
    fmt = detect_format(payload)
    if fmt == "nvd2-single":
        items = [payload]
    elif fmt == "nvd11":
        items = payload.get("CVE_Items", [])
    else:
        items = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    advisories: list[Advisory] = []
    errors = 0
    for item in items:
        advisory = _nvd11_advisory(item) if fmt == "nvd11" else _nvd2_advisory(item)
        if advisory is None:
            errors += 1
            continue
        advisories.append(advisory)
    summary = store.upsert_many(advisories, source="nvd")
    summary.path = str(path)
    summary.errors += errors
    return summary


def import_kev(store: AdvisoryStore, path: str | Path) -> ImportSummary:
    payload = load_json(path)
    items = payload.get("vulnerabilities", []) if isinstance(payload, dict) else payload
    advisories: list[Advisory] = []
    errors = 0
    for item in items or []:
        if not isinstance(item, dict) or not item.get("cveID"):
            errors += 1
            continue
        identifier = str(item["cveID"]).upper()
        existing = store.get(identifier)
        name = str(item.get("vulnerabilityName") or "")
        advisories.append(
            Advisory(
                id=identifier,
                source="kev",
                title=name or (existing.title if existing else identifier),
                description=str(
                    item.get("shortDescription") or (existing.description if existing else "")
                ),
                severity=existing.severity if existing else Severity.HIGH,
                cvss=existing.cvss if existing else None,
                published=str(item.get("dateAdded") or "") or None,
                cwe=existing.cwe if existing else None,
                vendor=str(item.get("vendorProject") or "") or None,
                product=str(item.get("product") or "") or None,
                ranges=existing.ranges if existing else [],
                references=[f"https://nvd.nist.gov/vuln/detail/{identifier}"],
                kev=True,
                kev_due=str(item.get("dueDate") or "") or None,
                exploited_in_wild=True,
                note=(
                    "CISA KEV: known exploitation in the wild; "
                    f"ransomware use={item.get('knownRansomwareCampaignUse', 'Unknown')}"
                ),
            )
        )
    summary = store.upsert_many(advisories, source="kev")
    summary.path = str(path)
    summary.errors += errors
    return summary


def import_custom(store: AdvisoryStore, path: str | Path) -> ImportSummary:
    payload = load_json(path)
    items = payload.get("advisories", payload) if isinstance(payload, dict) else payload
    advisories: list[Advisory] = []
    errors = 0
    for item in items or []:
        try:
            advisory = Advisory.model_validate(item)
        except Exception:
            errors += 1
            continue
        advisories.append(advisory)
    summary = store.upsert_many(advisories, source="custom")
    summary.path = str(path)
    summary.errors += errors
    return summary


def import_feed(store: AdvisoryStore, path: str | Path, fmt: str = "auto") -> ImportSummary:
    """Import one feed file using the selected (or auto-detected) format."""
    if fmt == "auto":
        fmt = detect_format(load_json(path))
        if fmt == "nvd2-single":
            fmt = "nvd2"
    if fmt in {"nvd", "nvd2", "nvd11"}:
        return import_nvd(store, path)
    if fmt in {"kev", "cisa-kev"}:
        return import_kev(store, path)
    if fmt in {"custom", "native"}:
        return import_custom(store, path)
    raise CyberpowerfullError(
        f"unsupported advisory feed format {fmt!r}; use auto, nvd, nvd11, kev, or custom"
    )


__all__ = [
    "detect_format",
    "import_custom",
    "import_feed",
    "import_kev",
    "import_nvd",
    "load_json",
    "parse_cpe",
]
