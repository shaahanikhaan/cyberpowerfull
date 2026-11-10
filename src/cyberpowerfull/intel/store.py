"""Local advisory corpus storage (SQLite).

The corpus is reference data, not run memory: it is imported, refreshed and
merged, while run-time evidence stays in the append-only memory layer.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from cyberpowerfull.intel.models import Advisory, ImportSummary, VersionRange

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss REAL,
    cvss_vector TEXT,
    published TEXT,
    cwe TEXT,
    vendor TEXT,
    product TEXT,
    ranges_json TEXT NOT NULL,
    references_json TEXT NOT NULL,
    kev INTEGER NOT NULL,
    kev_due TEXT,
    exploited_in_wild INTEGER NOT NULL,
    note TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_advisories_product ON advisories(product);
CREATE INDEX IF NOT EXISTS idx_advisories_kev ON advisories(kev);
"""


class AdvisoryStore:
    """SQLite-backed advisory corpus with merge-on-import semantics."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- writes ------------------------------------------------------------
    def upsert_many(
        self, advisories: Iterable[Advisory], *, source: str | None = None
    ) -> ImportSummary:
        summary = ImportSummary(source=source or "custom")
        for advisory in advisories:
            existing = self.get(advisory.id)
            if existing is None:
                self._insert(advisory)
                summary.imported += 1
                continue
            merged = merge_advisories(existing, advisory)
            if merged == existing:
                summary.skipped += 1
                continue
            self._insert(merged, replace=True)
            summary.updated += 1
        self._conn.commit()
        return summary

    def _insert(self, advisory: Advisory, *, replace: bool = False) -> None:
        verb = "INSERT OR REPLACE" if replace else "INSERT"
        self._conn.execute(
            f"{verb} INTO advisories (id, source, title, description, severity, cvss, "
            "cvss_vector, published, cwe, vendor, product, ranges_json, references_json, "
            "kev, kev_due, exploited_in_wild, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                advisory.id,
                advisory.source,
                advisory.title,
                advisory.description,
                advisory.severity.value,
                advisory.cvss,
                advisory.cvss_vector,
                advisory.published,
                advisory.cwe,
                advisory.vendor,
                advisory.product,
                json.dumps([item.model_dump() for item in advisory.ranges]),
                json.dumps(advisory.references),
                int(advisory.kev),
                advisory.kev_due,
                int(advisory.exploited_in_wild),
                advisory.note,
            ),
        )

    # -- reads -------------------------------------------------------------
    def get(self, advisory_id: str) -> Advisory | None:
        row = self._conn.execute(
            "SELECT * FROM advisories WHERE id = ?", (advisory_id.upper(),)
        ).fetchone()
        return None if row is None else _row_to_advisory(row)

    def all(self) -> list[Advisory]:
        rows = self._conn.execute("SELECT * FROM advisories ORDER BY id").fetchall()
        return [_row_to_advisory(row) for row in rows]

    def by_product(self, product: str) -> list[Advisory]:
        from cyberpowerfull.intel.models import product_matches

        return [
            advisory
            for advisory in self.all()
            if advisory.product and product_matches(product, advisory.product)
        ]

    def stats(self) -> dict[str, object]:
        total = self._conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        kev = self._conn.execute("SELECT COUNT(*) FROM advisories WHERE kev = 1").fetchone()[0]
        products = self._conn.execute(
            "SELECT COUNT(DISTINCT product) FROM advisories WHERE product IS NOT NULL"
        ).fetchone()[0]
        years = [
            row[0]
            for row in self._conn.execute(
                "SELECT DISTINCT substr(published, 1, 4) AS year FROM advisories "
                "WHERE published IS NOT NULL ORDER BY year"
            ).fetchall()
            if row[0]
        ]
        severities = {
            row[0]: int(row[1])
            for row in self._conn.execute(
                "SELECT severity, COUNT(*) FROM advisories GROUP BY severity"
            ).fetchall()
        }
        return {
            "total": int(total),
            "kev": int(kev),
            "products": int(products),
            "years": years,
            "severities": severities,
            "path": self.path,
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> AdvisoryStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _row_to_advisory(row: sqlite3.Row) -> Advisory:
    payload = dict(row)
    ranges = [VersionRange.model_validate(item) for item in json.loads(payload["ranges_json"])]
    return Advisory(
        id=payload["id"],
        source=payload["source"],
        title=payload["title"],
        description=payload["description"],
        severity=payload["severity"],
        cvss=payload["cvss"],
        cvss_vector=payload["cvss_vector"],
        published=payload["published"],
        cwe=payload["cwe"],
        vendor=payload["vendor"],
        product=payload["product"],
        ranges=ranges,
        references=json.loads(payload["references_json"]),
        kev=bool(payload["kev"]),
        kev_due=payload["kev_due"],
        exploited_in_wild=bool(payload["exploited_in_wild"]),
        note=payload["note"],
    )


def _max_cvss(left: float | None, right: float | None) -> float | None:
    """Keep the highest score seen: a later feed must not lower a known score."""
    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)


def merge_advisories(existing: Advisory, incoming: Advisory) -> Advisory:
    """Merge a second feed into an existing record without losing detail."""
    severity = (
        incoming.severity if incoming.severity.rank > existing.severity.rank else existing.severity
    )
    return existing.model_copy(
        update={
            "severity": severity,
            "cvss": _max_cvss(existing.cvss, incoming.cvss),
            "source": existing.source if existing.source != "bundled" else incoming.source,
            "cvss_vector": existing.cvss_vector or incoming.cvss_vector,
            "title": existing.title or incoming.title,
            "description": existing.description or incoming.description,
            "published": existing.published or incoming.published,
            "cwe": existing.cwe or incoming.cwe,
            "vendor": existing.vendor or incoming.vendor,
            "product": existing.product or incoming.product,
            "ranges": existing.ranges or incoming.ranges,
            "references": list(dict.fromkeys([*existing.references, *incoming.references]))[:20],
            "kev": existing.kev or incoming.kev,
            "kev_due": existing.kev_due or incoming.kev_due,
            "exploited_in_wild": existing.exploited_in_wild or incoming.exploited_in_wild,
            "note": existing.note or incoming.note,
        }
    )


__all__ = ["AdvisoryStore", "merge_advisories"]
