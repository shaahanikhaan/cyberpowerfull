"""Live toolchain inventory tests: detection, wordlists, and honest reporting."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from cyberpowerfull import inventory
from cyberpowerfull.inventory import (
    BINARY_CATALOG,
    BinaryInfo,
    Toolchain,
    Wordlist,
    build_toolchain,
    clear_cache,
    discover_wordlists,
    family_members,
    install_hint,
    pick_wordlist,
    probe_binaries,
)
from tests.conftest import completed


@pytest.fixture(autouse=True)
def _reset_cache():
    clear_cache()
    yield
    clear_cache()


def _which_map(mapping: dict[str, str]):
    return mock.patch(
        "cyberpowerfull.inventory.shutil.which",
        side_effect=lambda name: mapping.get(name),
    )


class TestProbeBinaries:
    def test_detects_alternate_binary_names(self) -> None:
        mapping = {"nmap": "/usr/bin/nmap", "httpx-toolkit": "/usr/bin/httpx-toolkit"}
        with (
            _which_map(mapping),
            mock.patch(
                "cyberpowerfull.inventory.subprocess.run",
                return_value=completed("nmap version 7.94\n"),
            ),
        ):
            results = probe_binaries(versions=True)
        assert results["nmap"].installed
        assert results["nmap"].version == "nmap version 7.94"
        assert results["httpx"].installed
        assert results["httpx"].alternative_used == "httpx-toolkit"
        assert not results["nuclei"].installed
        assert results["nuclei"].as_dict()["installed"] is False

    def test_missing_binary_is_not_fabricated(self) -> None:
        with _which_map({}):
            results = probe_binaries(versions=False)
        assert all(not info.installed for info in results.values())
        assert results["masscan"].path is None

    def test_version_probe_failure_is_tolerated(self) -> None:
        with (
            _which_map({"nmap": "/usr/bin/nmap"}),
            mock.patch(
                "cyberpowerfull.inventory.subprocess.run",
                side_effect=OSError("boom"),
            ),
        ):
            results = probe_binaries(versions=True)
        assert results["nmap"].installed
        assert results["nmap"].version is None

    def test_catalog_covers_kali_families(self) -> None:
        for name in ("nmap", "nuclei", "nikto", "hydra", "searchsploit", "strix"):
            assert name in BINARY_CATALOG
        assert "web" in {family for _alts, family in BINARY_CATALOG.values()}
        assert "hydra" in family_members("credentials")


class TestWordlistDiscovery:
    def test_classifies_and_flags_compressed(self, tmp_path: Path) -> None:
        discovery = tmp_path / "discovery"
        discovery.mkdir()
        (discovery / "common.txt").write_text("admin\n" * 200, encoding="utf-8")
        passwords = tmp_path / "passwords"
        passwords.mkdir()
        (passwords / "rockyou.txt").write_text("hunter2\n" * 300, encoding="utf-8")
        (passwords / "rockyou.txt.gz").write_text("x" * 2000, encoding="utf-8")
        (passwords / "tiny.txt").write_text("x", encoding="utf-8")

        found = discover_wordlists([str(tmp_path)], min_size=16)
        paths = {item.path for item in found}
        assert str(discovery / "common.txt") in paths
        assert str(passwords / "rockyou.txt") in paths
        assert str(passwords / "tiny.txt") not in paths, "tiny files are filtered"
        kinds = {item.path: item.kind for item in found}
        assert kinds[str(discovery / "common.txt")] == "discovery"
        assert kinds[str(passwords / "rockyou.txt")] == "passwords"
        compressed = [item for item in found if item.path.endswith(".gz")]
        assert compressed and compressed[0].compressed

    def test_ignores_missing_roots(self, tmp_path: Path) -> None:
        assert discover_wordlists([str(tmp_path / "nope")]) == []

    def test_limit_is_respected(self, tmp_path: Path) -> None:
        for index in range(6):
            (tmp_path / f"list-{index}.txt").write_text("a\n" * 300, encoding="utf-8")
        assert len(discover_wordlists([str(tmp_path)], limit=3)) == 3

    def test_pick_wordlist_prefers_known_names(self) -> None:
        items = [
            Wordlist("/x/huge-passes.txt", 10_000, "passwords", False),
            Wordlist("/usr/share/seclists/rockyou.txt", 900, "passwords", False),
        ]
        toolchain = Toolchain(wordlists=items)
        assert pick_wordlist("passwords", toolchain=toolchain).endswith("rockyou.txt")

    def test_pick_wordlist_falls_back_to_largest(self) -> None:
        items = [
            Wordlist("/x/small.txt", 100, "fuzzing", False),
            Wordlist("/x/large.txt", 9000, "fuzzing", False),
        ]
        assert pick_wordlist("fuzzing", toolchain=Toolchain(wordlists=items)) == "/x/large.txt"

    def test_pick_wordlist_returns_none_when_absent(self) -> None:
        assert pick_wordlist("dns", toolchain=Toolchain()) is None

    def test_pick_wordlist_skips_compressed(self) -> None:
        items = [Wordlist("/x/rockyou.txt.gz", 1000, "passwords", True)]
        assert pick_wordlist("passwords", toolchain=Toolchain(wordlists=items)) is None


class TestBuildToolchain:
    def test_reports_real_directories(self, tmp_path: Path, monkeypatch) -> None:
        share = tmp_path / "share"
        (share / "seclists").mkdir(parents=True)
        (share / "exploitdb").mkdir()
        scripts = share / "nmap" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "http-title.nse").write_text("-- nse", encoding="utf-8")
        templates = tmp_path / "nuclei-templates"
        templates.mkdir()
        (templates / "cves").mkdir()
        (templates / "cves" / "CVE-2021-41773.yaml").write_text("id: x", encoding="utf-8")
        wordlists = tmp_path / "wordlists"
        wordlists.mkdir()
        (wordlists / "directory-list-2.3-medium.txt").write_text("admin\n" * 200, encoding="utf-8")
        monkeypatch.setattr(inventory, "NUCLEI_TEMPLATE_ROOTS", (str(templates),))

        with _which_map({"nmap": "/usr/bin/nmap"}):
            toolchain = build_toolchain(
                versions=False,
                wordlist_roots=[str(wordlists)],
                share_dirs={
                    "seclists": str(share / "seclists"),
                    "exploitdb": str(share / "exploitdb"),
                    "nmap_scripts": str(scripts),
                    "metasploit": str(tmp_path / "absent"),
                },
            )
        assert toolchain.nmap_scripts == 1
        assert toolchain.seclists_present is True
        assert toolchain.exploitdb_present is True
        assert toolchain.metasploit_present is False
        assert toolchain.nuclei_templates["count"] == 1
        assert toolchain.has("nmap")
        assert toolchain.binary("nmap") == "nmap"
        assert toolchain.version("nmap") is None
        assert toolchain.wordlists, "wordlist scan should find the file"

    def test_as_dict_is_json_serialisable(self, tmp_path: Path) -> None:
        toolchain = build_toolchain(
            versions=False,
            include_wordlists=False,
            wordlist_roots=[],
            share_dirs={},
        )
        payload = toolchain.as_dict(include_wordlists=False)
        assert json.loads(json.dumps(payload, default=str))
        assert payload["installed_count"] + payload["missing_count"] == len(BINARY_CATALOG)
        assert "wordlists" not in payload

    def test_summary_lines_are_honest_about_absence(self) -> None:
        toolchain = Toolchain(
            binaries={"nmap": BinaryInfo("nmap", "network", None)},
            operating_system={"name": "Test OS", "version": "1"},
        )
        text = "\n".join(toolchain.summary_lines())
        assert "missing_binaries (1): nmap" in text
        assert "nuclei_templates: not installed" in text
        assert "wordlists_available: none found" in text

    def test_wordlists_of_kind_filters_compressed(self) -> None:
        toolchain = Toolchain(
            wordlists=[
                Wordlist("/a.txt", 10, "dns", False),
                Wordlist("/b.txt.gz", 10, "dns", True),
            ]
        )
        assert [item.path for item in toolchain.wordlists_of_kind("dns")] == ["/a.txt"]

    def test_install_hints_exist_for_major_tools(self) -> None:
        for name in ("nmap", "nuclei", "strix", "pentagi", "searchsploit"):
            assert install_hint(name)
        assert install_hint("does-not-exist") is None

    def test_external_agents_are_detected_from_environment(self, monkeypatch) -> None:
        monkeypatch.setenv("PENTAGI_URL", "https://127.0.0.1:8443")
        monkeypatch.delenv("PENTAGI_API_TOKEN", raising=False)
        with _which_map({"strix": "/usr/local/bin/strix"}):
            toolchain = build_toolchain(
                versions=False,
                include_wordlists=False,
                wordlist_roots=[],
                share_dirs={},
            )
        assert toolchain.external_agents["pentagi"]["available"] is True
        assert toolchain.external_agents["pentagi"]["token_configured"] is False
        assert toolchain.external_agents["strix"]["available"] is True
        assert toolchain.external_agents["sn1per"]["available"] is False
