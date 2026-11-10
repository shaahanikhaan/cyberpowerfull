"""Regression tests for the scope, tool-policy, and evidence boundaries."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from unittest import mock

import pytest
from pydantic import ValidationError

from cyberpowerfull.brain.attack_tree import AttackTree, ExpansionProposal, NodeStatus
from cyberpowerfull.brain.orchestrator import DelegationRequest, WorkerAgent
from cyberpowerfull.config import ToolPolicy
from cyberpowerfull.errors import InvalidToolArguments, ScopeError
from cyberpowerfull.models import Severity
from cyberpowerfull.scope import Scope, normalize_host
from cyberpowerfull.tools.base import ToolStatus
from cyberpowerfull.tools.nmap import NmapTool
from cyberpowerfull.tools.nuclei import NucleiTool
from cyberpowerfull.tools.sqlmap import SqlmapTool
from cyberpowerfull.tools.tcp_probe import TcpProbeTool


def request(tool: str, args: dict, agent: str = "scan") -> DelegationRequest:
    return DelegationRequest(agent=agent, tool=tool, args=args)


@pytest.mark.parametrize(
    "target",
    [
        "http://user:secret@127.0.0.1/",
        "http://127.0.0.1:99999/",
        "http://127.0.0.1\\@evil.test/",
        "http://127.0.0.1/line\nbreak",
        "127.1",
        "0177.0.0.1",
        "0x7f000001",
        "127.0.0x0.1",
        "0x7f.0.0.1",
        "-sV",
    ],
)
def test_ambiguous_target_rejected(target: str, scope: Scope) -> None:
    with pytest.raises(ScopeError):
        normalize_host(target)
    assert not scope.authorizes(target)


def test_exact_target_does_not_authorize_subdomains(scope_payload: dict) -> None:
    scope_payload.update(targets=["app.lab.test"], domains=[], exclude=[])
    scope = Scope.model_validate(scope_payload)
    assert scope.authorizes("app.lab.test")
    assert not scope.authorizes("evil.app.lab.test")


def test_wildcard_excludes_apex_but_bare_domain_includes_it(scope_payload: dict) -> None:
    scope_payload.update(targets=[], domains=["*.lab.test"], exclude=[])
    scope = Scope.model_validate(scope_payload)
    assert not scope.authorizes("lab.test")
    assert scope.authorizes("app.lab.test")
    scope_payload["domains"] = ["lab.test"]
    assert Scope.model_validate(scope_payload).authorizes("lab.test")


def test_mapped_ipv6_cannot_bypass_ipv4_exclusion(scope_payload: dict) -> None:
    scope_payload.update(targets=["0.0.0.0/0", "::/0"], domains=[], exclude=["10.0.0.0/8"])
    scope = Scope.model_validate(scope_payload)
    assert normalize_host("::ffff:10.0.0.1") == "10.0.0.1"
    assert not scope.authorizes("http://[::ffff:10.0.0.1]/")


@pytest.mark.parametrize("authorized", ["true", 1, "yes"])
def test_authorization_requires_a_json_boolean(scope_payload: dict, authorized: object) -> None:
    scope_payload["authorized"] = authorized
    with pytest.raises(ValidationError):
        Scope.model_validate(scope_payload)


@pytest.mark.parametrize("entry", ["https://lab.test/path", "lab.test:443", "lab.test/path"])
def test_scope_entries_cannot_imply_unenforced_url_or_port_restrictions(
    scope_payload: dict, entry: str
) -> None:
    scope_payload.update(targets=[entry], domains=[])
    with pytest.raises(ValidationError):
        Scope.model_validate(scope_payload)


def test_expired_scope_is_rechecked_by_worker(scope_payload: dict) -> None:
    scope_payload["expires"] = "2000-01-01"
    worker = WorkerAgent("recon", scope=Scope.model_validate(scope_payload))
    result = worker.execute(request("tcp_probe", {"target": "127.0.0.1"}, "recon"), dry_run=True)
    assert result.status is ToolStatus.BLOCKED
    assert "expired" in result.error


def test_ffuf_requires_operator_allowlisted_wordlist(scope: Scope, tmp_path: Path) -> None:
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    args = {"target": "http://127.0.0.1/FUZZ", "wordlist": str(words)}
    blocked = WorkerAgent("scan", scope=scope).execute(request("ffuf", args), dry_run=True)
    assert blocked.status is ToolStatus.BLOCKED
    allowed_scope = scope.model_copy(update={"allowed_wordlists": [str(words)]})
    allowed = WorkerAgent("scan", scope=allowed_scope).execute(request("ffuf", args), dry_run=True)
    assert allowed.status is ToolStatus.SKIPPED
    assert allowed.argv[allowed.argv.index("-rate") + 1] == "5"
    assert "-r=false" in allowed.argv


def test_ffuf_never_fuzzes_authority(scope: Scope, tmp_path: Path) -> None:
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    scope = scope.model_copy(update={"allowed_wordlists": [str(words)]})
    args = {"target": "http://FUZZ.lab.test/FUZZ", "wordlist": str(words)}
    result = WorkerAgent("scan", scope=scope).execute(request("ffuf", args), dry_run=True)
    assert result.status is ToolStatus.ERROR
    assert "never in its host" in result.error


def test_nuclei_requires_explicit_allowlisted_templates(scope: Scope, tmp_path: Path) -> None:
    template = tmp_path / "safe.yaml"
    template.write_text("id: test\n", encoding="utf-8")
    args = {"target": "http://127.0.0.1", "templates": [str(template)], "rate_limit": 50}
    worker = WorkerAgent("validate", scope=scope)
    assert (
        worker.execute(request("nuclei", args, "validate"), dry_run=True).status
        is ToolStatus.BLOCKED
    )
    scope = scope.model_copy(update={"allowed_nuclei_templates": [str(template)]})
    result = WorkerAgent("validate", scope=scope).execute(
        request("nuclei", args, "validate"), dry_run=True
    )
    assert result.status is ToolStatus.SKIPPED
    assert result.argv[result.argv.index("-rl") + 1] == "5"
    assert {"-no-interactsh", "-disable-redirects", "-disable-update-check"} <= set(result.argv)
    assert (
        WorkerAgent("validate", scope=scope)
        .execute(request("nuclei", {"target": "127.0.0.1"}, "validate"), dry_run=True)
        .status
        is ToolStatus.BLOCKED
    )


def test_subfinder_requires_explicit_external_source_opt_in(scope: Scope) -> None:
    args = {"target": "lab.test"}
    blocked = WorkerAgent("recon", scope=scope).execute(request("subfinder", args, "recon"))
    assert blocked.status is ToolStatus.BLOCKED
    scope = scope.model_copy(update={"allow_passive_sources": True})
    result = WorkerAgent("recon", scope=scope).execute(
        request("subfinder", args, "recon"), dry_run=True
    )
    assert result.status is ToolStatus.SKIPPED
    assert result.argv[result.argv.index("-rl") + 1] == "5"


def test_httpx_limits_rate_and_only_follows_same_host(scope: Scope) -> None:
    args = {"target": "http://127.0.0.1", "follow_redirects": True}
    result = WorkerAgent("recon", scope=scope).execute(
        request("httpx", args, "recon"), dry_run=True
    )
    assert result.status is ToolStatus.SKIPPED
    assert "-follow-host-redirects" in result.argv
    assert "-follow-redirects" not in result.argv
    assert result.argv[result.argv.index("-rl") + 1] == "5"
    assert "-disable-update-check" in result.argv


def test_integer_rate_tool_refuses_a_fractional_limit(scope: Scope) -> None:
    scope = scope.model_copy(update={"max_rps": 0.5})
    result = WorkerAgent("recon", scope=scope).execute(
        request("httpx", {"target": "127.0.0.1"}, "recon"), dry_run=True
    )
    assert result.status is ToolStatus.ERROR
    assert "below 1" in result.error


@pytest.mark.parametrize(
    ("tool", "agent", "args", "flags"),
    [
        ("nmap", "scan", {"target": "127.0.0.1"}, ["--max-rate", "5"]),
        ("nikto", "scan", {"target": "127.0.0.1"}, ["-Pause", "0.200"]),
        (
            "sqlmap",
            "validate",
            {"target": "http://127.0.0.1/?id=1"},
            ["--delay=0.200", "--threads=1", "--ignore-redirects"],
        ),
        (
            "dalfox",
            "validate",
            {"target": "http://127.0.0.1/?q=1", "workers": 30},
            ["--worker", "1", "--delay", "200"],
        ),
    ],
)
def test_worker_adds_scanner_rate_options(scope: Scope, tool, agent, args, flags) -> None:
    result = WorkerAgent(agent, scope=scope).execute(request(tool, args, agent), dry_run=True)
    assert result.status is ToolStatus.SKIPPED
    for flag in flags:
        assert flag in result.argv
    if tool == "dalfox":
        assert result.argv[result.argv.index("--worker") + 1] == "1"


def test_nmap_unrestricted_default_scripts_are_rejected() -> None:
    with pytest.raises(InvalidToolArguments):
        NmapTool().validate({"target": "127.0.0.1", "default_scripts": True})


def test_native_probe_paces_each_connection() -> None:
    clock = [10.0]
    attempted: list[float] = []
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    def connect(address, timeout):
        attempted.append(clock[0])
        return Connection()

    def sleep(seconds):
        clock[0] += seconds

    with (
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.getaddrinfo", return_value=addresses),
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.create_connection", side_effect=connect),
        mock.patch(
            "cyberpowerfull.tools.tcp_probe.time.perf_counter", side_effect=lambda: clock[0]
        ),
        mock.patch("cyberpowerfull.tools.tcp_probe.time.sleep", side_effect=sleep),
    ):
        result = TcpProbeTool().run(
            {"target": "127.0.0.1", "ports": [80, 81, 82]},
            policy=ToolPolicy(max_rps=5, timeout_s=10),
        )
    assert result.status is ToolStatus.OK
    assert attempted == pytest.approx([10.0, 10.2, 10.4])


def test_native_probe_blocks_dns_addresses_in_excluded_network() -> None:
    addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:10.0.0.1", 0, 0, 0)),
    ]
    with (
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.getaddrinfo", return_value=addresses),
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.create_connection") as connect,
    ):
        result = TcpProbeTool().run(
            {"target": "lab.test", "ports": [80]},
            policy=ToolPolicy(excluded_networks=("10.0.0.0/8",)),
        )
    assert result.status is ToolStatus.BLOCKED
    connect.assert_not_called()


def test_subprocess_output_truncation_is_an_error() -> None:
    def execute(argv, **kwargs):
        kwargs["stdout"].write(b"x" * 51)
        return mock.Mock(returncode=0)

    with (
        mock.patch("cyberpowerfull.tools.base.shutil.which", return_value="/usr/bin/nmap"),
        mock.patch("cyberpowerfull.tools.base.subprocess.run", side_effect=execute) as run,
    ):
        result = NmapTool().run(
            {"target": "127.0.0.1"}, policy=ToolPolicy(max_output_bytes=50, timeout_s=2)
        )
    assert result.status is ToolStatus.ERROR
    assert "incomplete" in result.error
    assert run.call_args.kwargs["timeout"] == 2


def test_sqlmap_heuristic_and_false_positive_are_not_confirmed() -> None:
    tool = SqlmapTool()
    args = tool.validate({"target": "http://127.0.0.1/?id=1"})
    heuristic = "GET parameter 'id' appears to be 'boolean-based' injectable"
    finding = tool.parse(args, heuristic)[0]
    assert finding.verified is False
    assert finding.severity is Severity.LOW
    assert (
        tool.parse(
            args, heuristic + "\n[WARNING] false positive or unexploitable injection point detected"
        )
        == []
    )


def test_nuclei_match_and_identifiers_are_not_misreported() -> None:
    tool = NucleiTool()
    args = tool.validate({"target": "http://127.0.0.1"})
    record = {
        "template-id": "example",
        "matcher-name": "word",
        "info": {
            "severity": "critical",
            "classification": {"cwe-id": "CWE-22", "cve-id": "CVE-2021-41773", "cvss-score": "7.5"},
        },
    }
    finding = tool.parse(args, json.dumps(record))[0]
    assert (finding.cwe, finding.cve, finding.cvss) == ("CWE-22", "CVE-2021-41773", 7.5)
    assert finding.verified is False


def test_failed_tree_expansion_does_not_discard_open_node() -> None:
    tree = AttackTree(target="127.0.0.1")
    assert not tree.expand(tree.root_id, [ExpansionProposal(hypothesis="too deep")], max_depth=0)
    assert tree.get(tree.root_id).status is NodeStatus.OPEN


def test_external_scanner_dns_preflight_blocks_excluded_addresses(scope: Scope) -> None:
    scope = scope.model_copy(update={"exclude": ["10.0.0.0/8"]})
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 0))]
    with (
        mock.patch("cyberpowerfull.brain.orchestrator.socket.getaddrinfo", return_value=answers),
        mock.patch("cyberpowerfull.tools.httpx_probe.HttpxTool.run") as run,
    ):
        result = WorkerAgent("recon", scope=scope).execute(
            request("httpx", {"target": "http://lab.test"}, "recon")
        )
    assert result.status is ToolStatus.BLOCKED
    assert "excluded" in result.error
    run.assert_not_called()


def test_worker_suppresses_out_of_scope_scanner_findings(scope_payload: dict) -> None:
    from cyberpowerfull.models import Finding
    from cyberpowerfull.tools.base import ToolResult
    from cyberpowerfull.tools.subfinder import SubfinderTool

    scope_payload.update(targets=["lab.test"], domains=[], exclude=[], allow_passive_sources=True)
    scope = Scope.model_validate(scope_payload)
    result = ToolResult(
        tool="subfinder",
        status=ToolStatus.OK,
        findings=[
            Finding(title="Subdomain discovered", target="lab.test", endpoint="sub.lab.test")
        ],
    )
    with mock.patch.object(SubfinderTool, "run", return_value=result):
        actual = WorkerAgent("recon", scope=scope).execute(
            request("subfinder", {"target": "lab.test"}, "recon")
        )
    assert actual.findings == []
    assert "suppressed 1" in actual.observations[-1]


def test_ipv6_findings_have_unambiguous_in_scope_endpoints(scope_payload: dict) -> None:
    scope_payload.update(targets=["::1"], domains=[], exclude=[])
    scope = Scope.model_validate(scope_payload)
    tool = TcpProbeTool()
    args = tool.validate({"target": "::1", "ports": [8000]})
    finding = tool.parse(args, '{"open": [8000], "errors": {}}')[0]
    assert finding.endpoint == "[::1]:8000"
    assert scope.authorizes(finding.endpoint)


def test_native_probe_rejects_localhost_resolving_off_loopback() -> None:
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 0))]
    with (
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.getaddrinfo", return_value=answers),
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.create_connection") as connect,
    ):
        result = TcpProbeTool().run({"target": "localhost", "ports": [80]})
    assert result.status is ToolStatus.BLOCKED
    assert "outside loopback" in result.error
    connect.assert_not_called()


def test_ipv4_mapped_ipv6_cidr_respects_scope_exclusions() -> None:
    scope = Scope(
        engagement="mapped",
        authorized=True,
        targets=["10.0.0.0/8"],
        exclude=["::ffff:10.0.0.0/104"],
    )
    assert not scope.authorizes("10.0.0.8")
    assert not scope.authorizes("::ffff:10.0.0.8")
    mapped_only = Scope(engagement="mapped", authorized=True, targets=["::ffff:10.0.0.0/104"])
    assert mapped_only.authorizes("10.0.0.8")
    assert mapped_only.authorizes("::ffff:10.0.0.8")
    ipv6_only = Scope(engagement="v6", authorized=True, targets=["::/0"])
    assert not ipv6_only.authorizes("10.0.0.8")


def test_native_probe_blocks_ipv4_address_excluded_as_mapped_cidr() -> None:
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 0))]
    with (
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.getaddrinfo", return_value=addresses),
        mock.patch("cyberpowerfull.tools.tcp_probe.socket.create_connection") as connect,
    ):
        result = TcpProbeTool().run(
            {"target": "lab.test", "ports": [80]},
            policy=ToolPolicy(excluded_networks=("::ffff:10.0.0.0/104",)),
        )
    assert result.status is ToolStatus.BLOCKED
    connect.assert_not_called()


def test_external_scanner_dns_blocks_mapped_cidr(scope: Scope) -> None:
    scope = scope.model_copy(update={"exclude": ["::ffff:10.0.0.0/104"]})
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 0))]
    with (
        mock.patch("cyberpowerfull.brain.orchestrator.socket.getaddrinfo", return_value=answers),
        mock.patch("cyberpowerfull.tools.httpx_probe.HttpxTool.run") as run,
    ):
        result = WorkerAgent("recon", scope=scope).execute(
            request("httpx", {"target": "http://lab.test"}, "recon")
        )
    assert result.status is ToolStatus.BLOCKED
    run.assert_not_called()


@pytest.mark.parametrize(
    ("tool", "agent", "args", "expected"),
    [
        ("sqlmap", "validate", {"target": "http://127.0.0.1/?id=1"}, "--delay=0.334"),
        ("nikto", "scan", {"target": "127.0.0.1"}, "0.334"),
        ("dalfox", "validate", {"target": "http://127.0.0.1/?q=1"}, "334"),
    ],
)
def test_fractional_request_delays_round_up(scope: Scope, tool, agent, args, expected) -> None:
    scope = scope.model_copy(update={"max_rps": 3.0})
    result = WorkerAgent(agent, scope=scope).execute(request(tool, args, agent), dry_run=True)
    assert result.status is ToolStatus.SKIPPED
    assert expected in result.argv


def test_unrepresentably_low_request_rate_is_reported_not_crashed(scope: Scope) -> None:
    scope = scope.model_copy(update={"max_rps": 5e-324})
    result = WorkerAgent("validate", scope=scope).execute(
        request("sqlmap", {"target": "http://127.0.0.1/?id=1"}, "validate"), dry_run=True
    )
    assert result.status is ToolStatus.ERROR
    assert "too small" in result.error


def test_ffuf_expands_a_permitted_home_relative_wordlist(
    scope: Scope, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    scope = scope.model_copy(update={"allowed_wordlists": [str(words)]})
    result = WorkerAgent("scan", scope=scope).execute(
        request("ffuf", {"target": "http://127.0.0.1/FUZZ", "wordlist": "~/words.txt"}),
        dry_run=True,
    )
    assert result.status is ToolStatus.SKIPPED
    assert result.argv[result.argv.index("-w") + 1] == str(words)


def test_dalfox_does_not_invent_cvss_score() -> None:
    from cyberpowerfull.tools.dalfox import DalfoxTool

    tool = DalfoxTool()
    args = tool.validate({"target": "http://127.0.0.1/?q=1"})
    findings = tool.parse(args, '[{"type":"V","param":"q"}]')
    assert findings[0].verified is True
    assert findings[0].cvss is None


@pytest.mark.parametrize(
    ("output", "status"),
    [
        ("[CRITICAL] unable to connect to the target URL ('Connection refused')", ToolStatus.ERROR),
        ("[INFO] starting, but no conclusive result", ToolStatus.ERROR),
        ("[CRITICAL] all tested parameters do not appear to be injectable", ToolStatus.OK),
        (
            "[CRITICAL] unable to connect\n"
            "[CRITICAL] all tested parameters do not appear to be injectable",
            ToolStatus.ERROR,
        ),
    ],
)
def test_sqlmap_zero_exit_requires_a_complete_nonfatal_result(output, status) -> None:
    def execute(argv, **kwargs):
        kwargs["stdout"].write(output.encode())
        return mock.Mock(returncode=0)

    with (
        mock.patch("cyberpowerfull.tools.base.shutil.which", return_value="/usr/bin/sqlmap"),
        mock.patch("cyberpowerfull.tools.base.subprocess.run", side_effect=execute),
    ):
        result = SqlmapTool().run({"target": "http://127.0.0.1/?id=1"})
    assert result.status is status
    if status is ToolStatus.ERROR:
        assert "despite exit code 0" in result.error
