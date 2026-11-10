"""Memory layer tests: append-only invariants, negative cache, TDA inputs."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from cyberpowerfull.memory.store import MemoryStore, MemoryView, args_hash
from cyberpowerfull.models import Finding, Phase, Severity


@pytest.fixture
def store() -> MemoryStore:
    store = MemoryStore(":memory:", run_id="test-run")
    yield store
    store.close()


def make_finding(severity: Severity = Severity.HIGH, verified: bool = True) -> Finding:
    return Finding(
        title=f"{severity.value} finding",
        severity=severity,
        confidence=0.9,
        target="127.0.0.1",
        endpoint="127.0.0.1:80",
        tool="nuclei",
        skill="information_disclosure",
        verified=verified,
    )


class TestAppendOnly:
    def test_findings_roundtrip(self, store: MemoryStore) -> None:
        finding = make_finding()
        store.append_finding(finding)
        stored = store.findings()
        assert len(stored) == 1
        assert stored[0].id == finding.id
        assert stored[0].severity is Severity.HIGH

    def test_step_roundtrip(self, store: MemoryStore) -> None:
        store.append_step(
            step=1, phase=Phase.RECON, tool="nmap", args={"target": "127.0.0.1"}, ok=True
        )
        steps = store.steps()
        assert steps[0]["tool"] == "nmap"
        assert steps[0]["ok"] == 1

    @pytest.mark.parametrize("table", ["steps", "findings", "attempts"])
    def test_update_is_rejected(self, store: MemoryStore, table: str) -> None:
        store.append_step(step=1, phase=Phase.RECON, tool="nmap")
        store.append_finding(make_finding())
        store.record_attempt(tool="nmap", args={}, target="127.0.0.1", ok=True)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(f"UPDATE {table} SET run_id = 'tampered'")

    @pytest.mark.parametrize("table", ["steps", "findings", "attempts"])
    def test_delete_is_rejected(self, store: MemoryStore, table: str) -> None:
        store.append_step(step=1, phase=Phase.RECON, tool="nmap")
        store.append_finding(make_finding())
        store.record_attempt(tool="nmap", args={}, target="127.0.0.1", ok=True)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(f"DELETE FROM {table}")

    def test_persists_to_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "memory.sqlite3"
        with MemoryStore(path, run_id="disk") as store:
            store.append_finding(make_finding())
        with MemoryStore(path, run_id="disk") as reopened:
            assert len(reopened.findings()) == 1


class TestNegativeCache:
    def test_hit_after_failure(self, store: MemoryStore) -> None:
        args = {"target": "127.0.0.1", "ports": "22"}
        store.record_attempt(tool="nmap", args=args, target="127.0.0.1", ok=False, error="timeout")
        assert store.negative_cache_hit("nmap", args) == "timeout"

    def test_latest_attempt_wins(self, store: MemoryStore) -> None:
        args = {"target": "127.0.0.1"}
        store.record_attempt(tool="nmap", args=args, target="127.0.0.1", ok=False, error="boom")
        store.record_attempt(tool="nmap", args=args, target="127.0.0.1", ok=True)
        assert store.negative_cache_hit("nmap", args) is None

    def test_unknown_invocation(self, store: MemoryStore) -> None:
        assert store.negative_cache_hit("nmap", {"target": "x"}) is None

    def test_args_hash_is_stable(self) -> None:
        assert args_hash("nmap", {"a": 1, "b": 2}) == args_hash("nmap", {"b": 2, "a": 1})
        assert args_hash("nmap", {"a": 1}) != args_hash("nmap", {"a": 2})


class TestAggregates:
    def test_success_rate(self, store: MemoryStore) -> None:
        assert store.success_rate() == 0.0
        store.record_attempt(tool="nmap", args={}, target="t", ok=True)
        store.record_attempt(tool="nmap", args={"x": 1}, target="t", ok=False, error="e")
        assert store.success_rate() == 0.5
        assert store.success_rate("nmap") == 0.5
        assert store.success_rate("nuclei") == 0.0

    def test_evidence_confidence_grows(self, store: MemoryStore) -> None:
        assert store.evidence_confidence() == 0.0
        store.append_finding(make_finding(Severity.INFO))
        low = store.evidence_confidence()
        store.append_finding(make_finding(Severity.CRITICAL))
        assert store.evidence_confidence() > low

    def test_highest_severity(self, store: MemoryStore) -> None:
        assert store.highest_severity() is Severity.INFO
        store.append_finding(make_finding(Severity.MEDIUM))
        store.append_finding(make_finding(Severity.CRITICAL))
        assert store.highest_severity() is Severity.CRITICAL

    def test_digest_mentions_state(self, store: MemoryStore) -> None:
        store.append_finding(make_finding())
        store.record_attempt(tool="nmap", args={}, target="t", ok=False, error="timeout")
        digest = store.digest()
        assert "findings_total: 1" in digest
        assert "highest_severity: high" in digest
        assert "failed_attempts_by_tool" in digest

    def test_stats(self, store: MemoryStore) -> None:
        store.append_finding(make_finding())
        stats = store.stats()
        assert stats["findings"] == 1
        assert stats["run_id"] == "test-run"


class TestMemoryView:
    def test_reads_work(self, store: MemoryStore) -> None:
        store.append_finding(make_finding())
        view = store.view()
        assert len(view.findings()) == 1
        assert "findings_total" in view.digest()
        assert view.evidence_confidence() > 0
        assert view.stats()["findings"] == 1
        assert view.highest_severity() is Severity.HIGH
        assert view.success_rate() == 0.0
        assert view.negative_cache_hit("nmap", {}) is None

    def test_writes_are_impossible(self, store: MemoryStore) -> None:
        view = store.view()
        assert isinstance(view, MemoryView)
        assert not hasattr(view, "append_finding")
        assert not hasattr(view, "record_attempt")
