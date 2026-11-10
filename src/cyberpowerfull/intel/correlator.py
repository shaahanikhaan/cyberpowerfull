"""Component -> advisory correlation ("which CVEs might apply here?").

This is candidate generation, never confirmation: a component that falls inside
an advisory range produces an unverified finding with a confidence score and the
matching rationale. Confirmation requires a template check, an authenticated
version comparison, or a payload proof.

Correlation is also the honest answer to "find new CVEs automatically": the agent
matches observed products/versions against an imported, current advisory corpus —
including 2025-2026 entries — without ever inventing an advisory of its own.
"""

from __future__ import annotations

from dataclasses import dataclass

from cyberpowerfull.intel.models import Advisory, Component, product_matches
from cyberpowerfull.intel.store import AdvisoryStore
from cyberpowerfull.models import Finding, Phase, Severity

MAX_CANDIDATES_PER_COMPONENT = 5


@dataclass(frozen=True)
class Match:
    """One component/advisory match with its rationale."""

    component: Component
    advisory: Advisory
    confidence: float
    severity: Severity
    rationale: str

    @property
    def key(self) -> str:
        return f"{self.advisory.id}:{self.component.key()}"


class CveCorrelator:
    """Deterministic matcher between observed components and the advisory corpus."""

    def __init__(
        self,
        store: AdvisoryStore,
        *,
        min_cvss: float = 0.0,
        max_per_component: int = MAX_CANDIDATES_PER_COMPONENT,
    ) -> None:
        self.store = store
        self.min_cvss = min_cvss
        self.max_per_component = max_per_component

    def match_component(self, component: Component) -> list[Match]:
        matches: list[Match] = []
        for advisory in self.store.all():
            if advisory.cvss is not None and advisory.cvss < self.min_cvss:
                continue
            if not advisory.product:
                continue
            if not product_matches(component.product, advisory.product):
                continue
            if not advisory.affects(component.product, component.version):
                continue
            matches.append(self._build(component, advisory))
        matches.sort(key=lambda match: (match.severity.rank, match.confidence), reverse=True)
        return matches[: self.max_per_component]

    def correlate(self, components: list[Component]) -> list[Match]:
        seen: set[str] = set()
        results: list[Match] = []
        for component in components:
            for match in self.match_component(component):
                if match.key in seen:
                    continue
                seen.add(match.key)
                results.append(match)
        return results

    # -- scoring -----------------------------------------------------------
    @staticmethod
    def _build(component: Component, advisory: Advisory) -> Match:
        confidence = 0.40
        reasons: list[str] = []
        if component.version:
            confidence += 0.15
            reasons.append(f"version {component.version} inside affected range")
        else:
            reasons.append("version not observed; range cannot be excluded")
        if advisory.ranges:
            ranges = ", ".join(item.describe() for item in advisory.ranges[:3])
            reasons.append(f"affected={ranges}")
        else:
            confidence -= 0.10
            reasons.append("product-level advisory only")
        if advisory.kev:
            confidence += 0.15
            reasons.append("CISA KEV: exploited in the wild")
        severity = advisory.severity
        if component.version is None and severity.rank > Severity.MEDIUM.rank:
            severity = Severity.MEDIUM
            reasons.append("severity capped: unversioned component")
        confidence = round(max(0.15, min(confidence, 0.8)), 2)
        return Match(
            component=component,
            advisory=advisory,
            confidence=confidence,
            severity=severity,
            rationale="; ".join(reasons),
        )


def match_to_finding(match: Match, *, reference_target: str) -> Finding:
    """Convert a match into an unverified candidate finding."""
    component = match.component
    advisory = match.advisory
    endpoint = component.endpoint or reference_target
    fixed = advisory.fixed_versions()
    remediation = (
        f"Upgrade {component.product} to a version outside the affected range"
        + (f" (fixed in {', '.join(fixed[:3])})" if fixed else "")
        + "; confirm against the vendor advisory."
    )
    return Finding(
        title=f"CVE candidate: {advisory.id} may affect {component.label()}",
        severity=match.severity,
        confidence=match.confidence,
        target=reference_target,
        endpoint=endpoint,
        evidence=(
            f"component={component.label()} source={component.source} "
            f"advisory={advisory.id} ({advisory.source}) cvss={advisory.cvss} "
            f"kev={advisory.kev} | {match.rationale}"
        ),
        tool="cve_correlate",
        skill="exploit_availability",
        cwe=advisory.cwe,
        cve=advisory.id,
        cvss=advisory.cvss,
        remediation=remediation,
        verified=False,
        phase=Phase.VALIDATION,
    )


def correlate_components(
    components: list[Component],
    correlator: CveCorrelator,
    *,
    target: str,
    seen: set[str] | None = None,
) -> tuple[list[Finding], list[Match]]:
    """Produce deduplicated candidate findings for a set of components."""
    seen = seen if seen is not None else set()
    findings: list[Finding] = []
    matches: list[Match] = []
    for match in correlator.correlate(components):
        if match.key in seen:
            continue
        seen.add(match.key)
        matches.append(match)
        findings.append(match_to_finding(match, reference_target=target))
    return findings, matches


__all__ = [
    "MAX_CANDIDATES_PER_COMPONENT",
    "CveCorrelator",
    "Match",
    "correlate_components",
    "match_to_finding",
]
