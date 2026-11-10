"""Offline vulnerability intelligence: advisory corpus, import, correlation.

Everything in this package is local. Feeds are imported from files that the
operator fetched; no request is ever made by the agent itself.
"""

from __future__ import annotations

from cyberpowerfull.intel.correlator import CveCorrelator, Match, correlate_components
from cyberpowerfull.intel.importer import import_feed
from cyberpowerfull.intel.models import (
    Advisory,
    Component,
    ImportSummary,
    VersionRange,
    product_matches,
)
from cyberpowerfull.intel.service import correlate, load_store, require_store, seed_bundled
from cyberpowerfull.intel.store import AdvisoryStore

__all__ = [
    "Advisory",
    "AdvisoryStore",
    "Component",
    "CveCorrelator",
    "ImportSummary",
    "Match",
    "VersionRange",
    "correlate",
    "correlate_components",
    "import_feed",
    "load_store",
    "product_matches",
    "require_store",
    "seed_bundled",
]
