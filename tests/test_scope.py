"""Scope enforcement tests: the gate that stops the agent leaving its engagement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberpowerfull.errors import ScopeError, ScopeViolation
from cyberpowerfull.models import Phase
from cyberpowerfull.scope import Scope, load_scope, normalize_host
from tests.conftest import SCOPE_PAYLOAD


class TestNormalizeHost:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("127.0.0.1", "127.0.0.1"),
            ("https://app.lab.test/path?q=1", "app.lab.test"),
            ("http://127.0.0.1:8080/admin", "127.0.0.1"),
            ("LAB.TEST.", "lab.test"),
            ("[::1]", "::1"),
            ("user:pass@host.lab.test/x", "host.lab.test"),
        ],
    )
    def test_normalises(self, raw: str, expected: str) -> None:
        assert normalize_host(raw) == expected

    def test_rejects_empty(self) -> None:
        with pytest.raises(ScopeError):
            normalize_host("   ")

    def test_rejects_suspicious_characters(self) -> None:
        with pytest.raises(ScopeError):
            normalize_host("127.0.0.1; rm -rf /")


class TestScopeAuthorisation:
    def test_exact_ip(self, scope: Scope) -> None:
        assert scope.authorizes("127.0.0.1")
        assert scope.authorizes("http://127.0.0.1:8080/login")

    def test_domain_and_subdomain(self, scope: Scope) -> None:
        assert scope.authorizes("lab.test")
        assert scope.authorizes("api.lab.test")
        assert not scope.authorizes("evil.com")

    def test_excluded_target_is_refused(self, scope: Scope) -> None:
        assert not scope.authorizes("169.254.169.254")

    def test_cidr_membership(self, scope_payload: dict) -> None:
        scope_payload["targets"] = ["10.10.0.0/24"]
        scope = Scope.model_validate(scope_payload)
        assert scope.authorizes("10.10.0.55")
        assert not scope.authorizes("10.10.1.55")

    def test_wildcard_domain(self, scope_payload: dict) -> None:
        scope_payload["domains"] = ["*.lab.test"]
        scope = Scope.model_validate(scope_payload)
        assert scope.authorizes("deep.api.lab.test")

    def test_unauthorized_scope_authorizes_nothing(self, scope_payload: dict) -> None:
        scope_payload["authorized"] = False
        scope = Scope.model_validate(scope_payload)
        assert not scope.authorizes("127.0.0.1")

    def test_require_raises(self, scope: Scope) -> None:
        assert scope.require("127.0.0.1") == "127.0.0.1"
        with pytest.raises(ScopeViolation):
            scope.require("attacker.example.com")
        assert ScopeViolation.exit_code == 4

    def test_garbage_target(self, scope: Scope) -> None:
        assert not scope.authorizes("!!!!")

    def test_phase_allowed(self, scope: Scope) -> None:
        assert scope.phase_allowed(Phase.SCANNING)
        scope_payload = SCOPE_PAYLOAD | {"allowed_phases": ["recon"]}
        restricted = Scope.model_validate(scope_payload)
        assert not restricted.phase_allowed(Phase.VALIDATION)


class TestScopeValidation:
    def test_missing_scope_file(self, tmp_path: Path) -> None:
        with pytest.raises(ScopeError, match="refuses to run"):
            load_scope(tmp_path / "nope.json")
        assert ScopeError.exit_code == 3

    def test_not_authorized(self, tmp_path: Path, scope_payload: dict) -> None:
        scope_payload["authorized"] = False
        path = tmp_path / "scope.json"
        path.write_text(json.dumps(scope_payload), encoding="utf-8")
        with pytest.raises(ScopeError, match="not marked authorized"):
            load_scope(path)

    def test_no_targets(self, tmp_path: Path, scope_payload: dict) -> None:
        scope_payload["targets"] = []
        scope_payload["domains"] = []
        path = tmp_path / "scope.json"
        path.write_text(json.dumps(scope_payload), encoding="utf-8")
        with pytest.raises(ScopeError, match="at least one target"):
            load_scope(path)

    def test_expired(self, tmp_path: Path, scope_payload: dict) -> None:
        scope_payload["expires"] = "2020-01-01"
        path = tmp_path / "scope.json"
        path.write_text(json.dumps(scope_payload), encoding="utf-8")
        with pytest.raises(ScopeError, match="expired"):
            load_scope(path)

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ScopeError, match="not valid JSON"):
            load_scope(path)

    def test_non_object_json(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.json"
        path.write_text("[]", encoding="utf-8")
        with pytest.raises(ScopeError, match="JSON object"):
            load_scope(path)

    def test_schema_failure(self, tmp_path: Path, scope_payload: dict) -> None:
        scope_payload["unexpected_key"] = True
        path = tmp_path / "scope.json"
        path.write_text(json.dumps(scope_payload), encoding="utf-8")
        with pytest.raises(ScopeError, match="failed validation"):
            load_scope(path)

    def test_empty_phase_list_rejected(self, tmp_path: Path, scope_payload: dict) -> None:
        scope_payload["allowed_phases"] = []
        path = tmp_path / "scope.json"
        path.write_text(json.dumps(scope_payload), encoding="utf-8")
        with pytest.raises(ScopeError, match="allowed phase"):
            load_scope(path)

    def test_repository_scope_is_loadable(self) -> None:
        scope = load_scope(Path(__file__).resolve().parents[1] / "scope.json")
        assert scope.engagement == "localhost-lab"
        assert scope.authorizes("127.0.0.1")


class TestScopeFingerprintAndPrompt:
    def test_fingerprint_is_stable_and_sensitive(self, scope: Scope, scope_payload: dict) -> None:
        other = Scope.model_validate(scope_payload | {"max_rps": 1})
        assert scope.fingerprint() == Scope.model_validate(scope_payload).fingerprint()
        assert scope.fingerprint() != other.fingerprint()

    def test_prompt_block_content(self, scope: Scope) -> None:
        block = scope.prompt_block()
        assert "scope_fingerprint:" in block
        assert "127.0.0.1" in block
        assert "max_requests_per_second: 5.0" in block
