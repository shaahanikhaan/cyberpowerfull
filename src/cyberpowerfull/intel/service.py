"""High-level intel entry points shared by the CLI, tools, and bash toolkit."""

from __future__ import annotations

from pathlib import Path

from cyberpowerfull.errors import CyberpowerfullError
from cyberpowerfull.intel.correlator import CveCorrelator, correlate_components
from cyberpowerfull.intel.importer import import_feed
from cyberpowerfull.intel.models import Component, ImportSummary
from cyberpowerfull.intel.store import AdvisoryStore
from cyberpowerfull.models import Finding, Severity

BUNDLED_PATH = Path(__file__).resolve().parent / "data" / "bundled_advisories.json"

#: Default on-disk corpus location (git-ignored; rebuilt by import).
DEFAULT_INTEL_PATH = Path("intel/advisories.sqlite3")


def seed_bundled(store: AdvisoryStore) -> ImportSummary:
    """Load the shipped, verified snapshot into a store (idempotent)."""
    return import_feed(store, BUNDLED_PATH, "custom")


def load_store(path: str | Path | None = None, *, seed: bool = True) -> AdvisoryStore:
    """Open the advisory corpus, seeding the bundled snapshot when it is empty."""
    target = Path(path) if path is not None else DEFAULT_INTEL_PATH
    if str(target) == ":memory:":
        store = AdvisoryStore(":memory:")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        store = AdvisoryStore(target)
    if seed and not store.all():
        seed_bundled(store)
    return store


def require_store(path: str | Path | None = None) -> AdvisoryStore:
    """Open a store and guarantee it contains at least one advisory."""
    store = load_store(path)
    if not store.all():
        store.close()
        raise CyberpowerfullError(
            "advisory corpus is empty: import a feed with "
            "`cyberpowerfull --import-feed <nvd.json>` or run tools/bash/cve_hunt.sh"
        )
    return store


def correlate(
    components: list[Component],
    *,
    store: AdvisoryStore | None = None,
    target: str,
    min_cvss: float = 0.0,
    min_severity: Severity = Severity.INFO,
    seen: set[str] | None = None,
) -> list[Finding]:
    """Return candidate CVE findings for observed components."""
    owned = store is None
    advisory_store = store or load_store()
    try:
        correlator = CveCorrelator(advisory_store, min_cvss=min_cvss)
        findings, _ = correlate_components(components, correlator, target=target, seen=seen)
        if min_severity.rank > Severity.INFO.rank:
            findings = [item for item in findings if item.severity.rank >= min_severity.rank]
        return findings
    finally:
        if owned:
            advisory_store.close()


__all__ = [
    "BUNDLED_PATH",
    "DEFAULT_INTEL_PATH",
    "correlate",
    "load_store",
    "require_store",
    "seed_bundled",
]
