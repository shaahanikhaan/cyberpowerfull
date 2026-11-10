"""Advisory and component data models for offline CVE correlation."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cyberpowerfull.intel.versioning import normalize_product, version_in_range
from cyberpowerfull.models import Severity


class Component(BaseModel):
    """A product/version pair observed on a target (service, banner, technology).

    Components are facts extracted from tool output, never claims: a component
    alone is not a vulnerability.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    product: str = Field(min_length=1, max_length=120)
    vendor: str | None = Field(default=None, max_length=120)
    version: str | None = Field(default=None, max_length=80)
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = Field(default="tcp", max_length=16)
    endpoint: str | None = Field(default=None, max_length=400)
    source: str = Field(default="", max_length=40)
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)

    def key(self) -> str:
        """Stable identity used for de-duplication."""
        vendor = (self.vendor or "unknown").strip().lower().replace(" ", "_")
        product = self.product.strip().lower().replace(" ", "_")
        version = (self.version or "unknown").strip().lower()
        port = "" if self.port is None else str(self.port)
        return f"{vendor}:{product}:{version}:{port}"

    def label(self) -> str:
        parts = [part for part in (self.vendor, self.product, self.version) if part]
        text = " ".join(parts)
        return f"{text} (port {self.port})" if self.port is not None else text


class VersionRange(BaseModel):
    """An affected-version interval for one vendor/product pair."""

    model_config = ConfigDict(extra="forbid")

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    exact: str | None = None

    def contains(self, version: str | None) -> bool:
        return version_in_range(
            version,
            introduced=self.introduced,
            fixed=self.fixed,
            last_affected=self.last_affected,
            exact=self.exact,
        )

    def describe(self) -> str:
        if self.exact:
            return f"== {self.exact}"
        lower = f">= {self.introduced}" if self.introduced else "any"
        if self.fixed:
            return f"{lower}, < {self.fixed}"
        if self.last_affected:
            return f"{lower}, <= {self.last_affected}"
        return lower

    def is_empty(self) -> bool:
        return not any((self.introduced, self.fixed, self.last_affected, self.exact))


class Advisory(BaseModel):
    """A vulnerability advisory as stored in the local corpus."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=4, max_length=64, pattern=r"^[A-Za-z0-9:\-_.]+$")
    source: str = Field(default="bundled", max_length=32)
    title: str = Field(default="", max_length=400)
    description: str = Field(default="", max_length=4000)
    severity: Severity = Severity.MEDIUM
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=200)
    published: str | None = Field(default=None, max_length=32)
    cwe: str | None = Field(default=None, max_length=32)
    vendor: str | None = Field(default=None, max_length=120)
    product: str | None = Field(default=None, max_length=120)
    ranges: list[VersionRange] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    kev: bool = False
    kev_due: str | None = Field(default=None, max_length=32)
    exploited_in_wild: bool = False
    note: str | None = Field(default=None, max_length=600)

    @field_validator("id", mode="before")
    @classmethod
    def _upper_id(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) and "-" in value else value

    @field_validator("id")
    @classmethod
    def _check_id_shape(cls, value: str) -> str:
        """Accept only recognisable advisory identifiers."""
        prefix = value.split("-", 1)[0].upper()
        if prefix not in ADVISORY_ID_PREFIXES:
            raise ValueError(f"{value!r} is not a recognised advisory identifier")
        if prefix == "CVE" and not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
            raise ValueError(f"{value!r} is not a valid CVE identifier")
        return value

    def affects(self, product: str | None, version: str | None) -> bool:
        """Return True when this advisory plausibly covers the component."""
        if not product:
            return False
        if self.product and not product_matches(product, self.product):
            return False
        if not self.ranges:
            return True  # product-level advisory; the caller lowers confidence
        if version is None:
            return True  # cannot rule out without a version
        return any(version_range.contains(version) for version_range in self.ranges)

    def fixed_versions(self) -> list[str]:
        return [version_range.fixed for version_range in self.ranges if version_range.fixed]


#: Advisory identifier families the corpus accepts (CVE plus vendor/OS trackers).
ADVISORY_ID_PREFIXES: frozenset[str] = frozenset(
    {"CVE", "GHSA", "RHSA", "USN", "DSA", "MSRC", "ZDI", "CNVD", "BDU"}
)

#: Product-name reconciliation between scanner banners and advisory data.
PRODUCT_ALIASES: dict[str, set[str]] = {
    "http_server": {"httpd", "apache", "apache2", "http_server", "httpserver"},
    "openssh": {"openssh", "ssh", "openssh_server", "sshd", "openssh-server"},
    "log4j": {"log4j", "log4j2", "log4j_core", "log4jcore"},
    "spring_framework": {"spring", "spring_framework", "springframework", "spring_core"},
    "tomcat": {"tomcat", "apache_tomcat", "catalina"},
    "php": {"php", "php_cgi", "php_fpm", "php-fpm"},
    "postgresql": {"postgresql", "postgres", "pgsql"},
    "openssl": {"openssl", "libssl"},
    "nginx": {"nginx"},
    "mysql": {"mysql", "mariadb"},
    "big_ip": {"big_ip", "bigip", "f5_big_ip", "big-ip"},
    "pan_os": {"pan_os", "panos", "globalprotect"},
    "moveit_transfer": {"moveit", "moveit_transfer", "moveittransfer"},
    "xz_utils": {"xz", "xz_utils", "liblzma"},
    "wordpress": {"wordpress", "wp", "wp_core"},
}


def _words(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", (value or "").lower()) if token}


def product_matches(left: str, right: str) -> bool:
    """Fuzzy-but-bounded product comparison used only for candidate generation.

    Matches on normalised product strings, on words (``Apache httpd`` vs
    ``http_server``), or on a conservative substring rule.
    """
    a = normalize_product(left)
    b = normalize_product(right)
    if not a or not b:
        return False
    if a == b:
        return True
    words_a = _words(left)
    words_b = _words(right)
    for canonical, aliases in PRODUCT_ALIASES.items():
        group = aliases | {canonical}
        normalised = {normalize_product(alias) for alias in group}
        group_words: set[str] = set()
        for alias in group:
            group_words |= _words(alias)
        if (a in normalised or bool(words_a & group_words)) and (
            b in normalised or bool(words_b & group_words)
        ):
            return True
    return bool(min(len(a), len(b)) >= 5 and (a in b or b in a))


class ImportSummary(BaseModel):
    """Outcome of importing an advisory feed."""

    source: str = "custom"
    path: str | None = None
    imported: int = 0
    updated: int = 0
    skipped: int = 0
    errors: int = 0
    messages: list[str] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return self.imported + self.updated

    def summary_line(self) -> str:
        return (
            f"{self.source}: imported={self.imported} updated={self.updated} "
            f"skipped={self.skipped} errors={self.errors}"
        )


__all__ = [
    "ADVISORY_ID_PREFIXES",
    "PRODUCT_ALIASES",
    "Advisory",
    "Component",
    "ImportSummary",
    "VersionRange",
    "product_matches",
]
