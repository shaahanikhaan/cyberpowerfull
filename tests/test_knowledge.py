"""Local knowledge base readers: Exploit-DB, nuclei templates, NSE scripts."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from cyberpowerfull import inventory, knowledge
from cyberpowerfull.knowledge import (
    KnowledgeUnavailable,
    nmap_script_paths,
    nuclei_template_paths,
    recommended_wordlist,
    search_exploit_db,
    wordlist_summary,
)
from tests.conftest import completed

SEARCHSPLOIT_JSON = json.dumps(
    {
        "SEARCH": "apache",
        "RESULTS_EXPLOIT": [
            {
                "Title": "Apache 2.4.49 - Path Traversal (RCE)",
                "EDB-ID": "50383",
                "Path": "/usr/share/exploitdb/exploits/multiple/remote/50383.py",
                "Date": "2021-10-05",
                "Type": "remote",
                "Platform": "multiple",
            },
            {
                "Title": "Apache 2.4 - Local Privilege Escalation",
                "EDB-ID": "12345",
                "Date": "2019-01-01",
                "Type": "local",
                "Platform": "linux",
            },
        ],
        "RESULTS_SHELLCODE": [],
    }
)


class TestExploitDb:
    def test_parses_real_records(self) -> None:
        with (
            mock.patch(
                "cyberpowerfull.knowledge.shutil.which", return_value="/usr/bin/searchsploit"
            ),
            mock.patch(
                "cyberpowerfull.knowledge.subprocess.run",
                return_value=completed(SEARCHSPLOIT_JSON),
            ),
        ):
            records = search_exploit_db("apache")
        assert len(records) == 2
        assert records[0].edb_id == "50383"
        assert records[0].exploit_type == "remote"
        assert records[1].as_dict()["title"].startswith("Apache 2.4")

    def test_limit_is_applied(self) -> None:
        with (
            mock.patch(
                "cyberpowerfull.knowledge.shutil.which", return_value="/usr/bin/searchsploit"
            ),
            mock.patch(
                "cyberpowerfull.knowledge.subprocess.run",
                return_value=completed(SEARCHSPLOIT_JSON),
            ),
        ):
            assert len(search_exploit_db("apache", limit=1)) == 1

    def test_missing_binary_raises(self) -> None:
        with (
            mock.patch("cyberpowerfull.knowledge.shutil.which", return_value=None),
            pytest.raises(KnowledgeUnavailable, match="not installed"),
        ):
            search_exploit_db("apache")

    def test_garbage_output_returns_empty(self) -> None:
        with (
            mock.patch(
                "cyberpowerfull.knowledge.shutil.which", return_value="/usr/bin/searchsploit"
            ),
            mock.patch(
                "cyberpowerfull.knowledge.subprocess.run",
                return_value=completed("not json at all"),
            ),
        ):
            assert search_exploit_db("apache") == []

    def test_subprocess_failure_raises(self) -> None:
        with (
            mock.patch(
                "cyberpowerfull.knowledge.shutil.which", return_value="/usr/bin/searchsploit"
            ),
            mock.patch("cyberpowerfull.knowledge.subprocess.run", side_effect=OSError("denied")),
            pytest.raises(KnowledgeUnavailable, match="failed to start"),
        ):
            search_exploit_db("apache")


class TestNucleiTemplates:
    def test_lists_and_filters_templates(self, tmp_path: Path, monkeypatch) -> None:
        root = tmp_path / "nuclei-templates"
        (root / "cves").mkdir(parents=True)
        (root / "cves" / "CVE-2021-41773.yaml").write_text("id: x", encoding="utf-8")
        (root / "exposures").mkdir()
        (root / "exposures" / "git-config.yaml").write_text("id: y", encoding="utf-8")
        (root / "readme.md").write_text("not a template", encoding="utf-8")
        monkeypatch.setattr(inventory, "NUCLEI_TEMPLATE_ROOTS", (str(root),))

        assert len(nuclei_template_paths(limit=50)) == 2
        filtered = nuclei_template_paths("cve")
        assert filtered == ["cves/CVE-2021-41773.yaml"]

    def test_missing_repository_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(inventory, "NUCLEI_TEMPLATE_ROOTS", (str(tmp_path / "none"),))
        with pytest.raises(KnowledgeUnavailable, match="nuclei-templates"):
            nuclei_template_paths()


class TestNseScripts:
    def test_missing_directory_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(knowledge, "Path", lambda value: tmp_path / value.lstrip("/"))
        with pytest.raises(KnowledgeUnavailable):
            nmap_script_paths()

    def test_reads_real_script_directory(self, tmp_path: Path, monkeypatch) -> None:
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "http-title.nse").write_text("-- nse", encoding="utf-8")
        (scripts / "ssl-cert.nse").write_text("-- nse", encoding="utf-8")
        real_path = knowledge.Path

        def fake_path(value: str):
            if value == "/usr/share/nmap/scripts":
                return scripts
            return real_path(value)

        monkeypatch.setattr(knowledge, "Path", fake_path)
        assert nmap_script_paths() == ["http-title.nse", "ssl-cert.nse"]
        assert nmap_script_paths("ssl") == ["ssl-cert.nse"]


class TestWordlists:
    def test_summary_and_recommendation(self) -> None:
        items = [
            {"path": "/x/common.txt", "kind": "discovery", "size_bytes": 10, "compressed": False}
        ]
        assert wordlist_summary("discovery", toolchain=mock.Mock(wordlists=[])) == []
        with mock.patch("cyberpowerfull.knowledge.pick_wordlist", return_value="/x/common.txt"):
            assert recommended_wordlist("discovery") == "/x/common.txt"
        assert items  # keeps the shape explicit for readers
