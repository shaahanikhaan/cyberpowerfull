"""One-command mode: ``cpf TARGET`` does the whole first engagement.

The rest of the CLI expects an operator who has already written a scope file, chosen a
playbook, and picked budgets. That is the right contract for a real engagement and the wrong
first experience: somebody who just cloned the repository wants to point it at a host.

This module is the bridge. It derives the scope file, the playbook and the budgets from the
target and one profile name, refuses to invent authorization, and turns the run into plain
language. Every step it takes is still the same guardrailed step the explicit CLI takes:

* the scope file is written only after the operator attests authorization, and the attestation
  is recorded verbatim (the tool cannot verify permission, so it records who claimed it);
* an existing scope file is never widened -- a target outside it is an error, not a merge;
* missing binaries, ungranted capabilities and out-of-scope steps are reported, never simulated.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

from cyberpowerfull.errors import ScopeError
from cyberpowerfull.models import Capability
from cyberpowerfull.playbook import get_playbook
from cyberpowerfull.scope import Scope, bootstrap_scope, load_scope, write_scope
from cyberpowerfull.tools.registry import all_tools

#: Where auto-created scope files go when the operator does not choose a location.
DEFAULT_SCOPE_DIR = "engagements"

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$")
_SLUG_RE = re.compile(r"[^a-z0-9.\-]+")


@dataclass(frozen=True)
class Profile:
    """A named difficulty/speed trade-off, resolved to a real playbook and budgets."""

    name: str
    playbook: str
    max_seconds: int
    parallel: int
    summary: str


PROFILES: dict[str, Profile] = {
    "quick": Profile(
        name="quick",
        playbook="recon",
        max_seconds=600,
        parallel=4,
        summary="surface map only: ports, HTTP, WAF, a first template pass (~5 minutes)",
    ),
    "standard": Profile(
        name="standard",
        playbook="full",
        max_seconds=1800,
        parallel=8,
        summary="recon + web + network in one ordered pass (~15-30 minutes on a live host)",
    ),
    "deep": Profile(
        name="deep",
        playbook="full",
        max_seconds=7200,
        parallel=12,
        summary="the standard pass with a two-hour budget and the widest parallelism",
    ),
}

DEFAULT_PROFILE = "standard"


def target_host(raw: str) -> str:
    """Turn ``https://user@app.example.test:8443/x?y`` into ``app.example.test``.

    The scope engine matches hosts, not URLs, so the one-command mode has to reduce the
    operator's input to the thing that can actually be authorized.
    """
    text = (raw or "").strip()
    if not text:
        raise ScopeError("a target is required: pass a host or URL, e.g. 'cpf example.com'")
    if any(ch.isspace() for ch in text):
        raise ScopeError(f"target must not contain whitespace: {text!r}")
    if "://" in text:
        parts = urlsplit(text)
        host = parts.hostname or ""
    else:
        candidate = text.split("/", 1)[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[1]
        # A bare IPv6 literal arrives in brackets; urlsplit understands that form.
        if candidate.startswith("["):
            host = urlsplit(f"//{candidate}").hostname or ""
        else:
            host = candidate.split(":", 1)[0]
    host = host.strip().strip(".").lower()
    if not host:
        raise ScopeError(f"could not read a host from {raw!r}")
    if not (_HOST_RE.match(host) or ":" in host):
        raise ScopeError(
            f"{host!r} is not a host name or IP address; pass the host, not a URL path or pattern"
        )
    return host


def engagement_name(host: str) -> str:
    """A stable engagement name for an auto-created scope."""
    slug = _SLUG_RE.sub("-", host).strip("-") or "target"
    return f"one-pass-{slug}"[:120]


def default_scope_path(host: str, scope_dir: str | Path = DEFAULT_SCOPE_DIR) -> Path:
    """``engagements/<host>.json`` -- one file per host, easy to find and to edit."""
    slug = _SLUG_RE.sub("-", host).strip("-") or "target"
    return Path(scope_dir) / f"{slug}.json"


def profile_for(name: str | None) -> Profile:
    profile = PROFILES.get((name or DEFAULT_PROFILE).strip().lower())
    if profile is None:
        allowed = ", ".join(sorted(PROFILES))
        raise ScopeError(f"unknown profile {name!r}; choose one of: {allowed}")
    return profile


def attestation_reference(explicit: str | None, *, today: date | None = None) -> str:
    """The reference recorded on an operator-attested scope.

    It is deliberately self-describing: an auditor reading the file must be able to see that
    this scope was created from a claim made at a terminal, not from a stored document.
    """
    reference = (explicit or "").strip()
    if reference:
        return reference
    stamp = (today or date.today()).isoformat()
    return f"operator-attested:{stamp}"


def ensure_scope(
    *,
    target: str,
    scope_path: str | Path,
    attest: Callable[[str], bool],
    authorization_ref: str | None = None,
    aggressive: bool = True,
    credentials: bool = False,
    today: date | None = None,
) -> tuple[Scope, Path, bool]:
    """Load the scope that authorizes ``target``, creating it only with an attestation.

    Returns ``(scope, path, created)``. ``attest`` is called with the host and must return
    ``True`` before anything is written; when it returns ``False`` no file is created and the
    operator is told exactly what to do next.
    """
    path = Path(scope_path)
    host = target_host(target)

    if path.exists():
        scope = load_scope(path)
        try:
            scope.require(target)
        except ScopeError as exc:
            raise ScopeError(
                f"{exc}\n  the existing scope file {path} was not modified: widening a live "
                f'engagement is an operator decision.\n  add {host!r} to its "targets" list, '
                "or point --scope at a different file"
            ) from exc
        return scope, path, False

    if not attest(host):
        raise ScopeError(
            "no scope file exists for this target and authorization was not attested.\n"
            "  only test systems you own or have written permission to test.\n"
            "  to record your attestation non-interactively:\n"
            f"    cpf {target} --i-am-authorized --authorization-ref REF\n"
            "  or write the scope yourself:\n"
            f"    cpf --init-scope {path} --engagement {engagement_name(host)} "
            f"--targets {host} --authorize --authorization-ref REF"
        )

    capabilities = [Capability.AGGRESSIVE] if aggressive else []
    if credentials:
        capabilities.append(Capability.CREDENTIAL_TESTING)
    scope = bootstrap_scope(
        engagement=engagement_name(host),
        targets=[host],
        capabilities=capabilities,
        authorization_ref=attestation_reference(authorization_ref, today=today),
        authorized=True,
        notes=(
            "created by one-command mode after the operator attested authorization at the "
            "terminal; this file is the record of that claim"
        ),
    )
    scope.assert_runnable()
    written = write_scope(path, scope)
    return scope, written, True


def phase_breakdown(steps) -> str:
    """``8 recon, 19 scanning, 7 validation`` — read from the real tool registry.

    A playbook step may declare no phase of its own; the phase then comes from the tool it
    calls, which is what the runner enforces.
    """
    tools = all_tools()
    counts: dict[str, int] = {}
    for step in steps:
        phase = step.phase
        if phase is None:
            tool = tools.get(step.tool)
            phase = getattr(tool, "phase", None)
        label = phase.value if phase is not None else "unclassified"
        counts[label] = counts.get(label, 0) + 1
    order = ["recon", "scanning", "validation", "unclassified"]
    return ", ".join(f"{counts[name]} {name}" for name in order if counts.get(name)) or "no steps"


def render_plan(
    *,
    target: str,
    host: str,
    profile: Profile,
    scope: Scope,
    scope_path: Path,
    created: bool,
    out_dir: Path,
    aggressive: bool,
) -> list[str]:
    """The short, plain-language description printed before the first request goes out."""
    playbook = get_playbook(profile.playbook)
    steps = list(playbook.steps)
    phase_line = phase_breakdown(steps)

    lines = [
        f"target      {target}",
        f"engagement  {scope.engagement} (scope: {scope_path}"
        f"{', just created' if created else ''})",
        f"profile     {profile.name} -- {profile.summary}",
        f"plan        playbook '{profile.playbook}': {len(steps)} steps ({phase_line}), "
        f"{profile.parallel} at a time, {profile.max_seconds // 60} min budget",
        "capabilities "
        + (", ".join(capability.value for capability in scope.capabilities) or "none granted")
        + " (credential testing stays off unless you ask for it)",
        f"reports     {out_dir}",
        "start       " + ("records your attestation" if created else "using the existing scope"),
    ]
    return lines


def step_line(record, *, index: int, total: int) -> str:
    """One progress line a non-expert can read."""
    status = (record.result or {}).get("status", "-")
    words = {
        "ok": "done",
        "missing": "skipped: tool not installed",
        "blocked": "blocked by scope",
        "error": "failed",
        "timeout": "timed out",
        "dry_run": "rehearsed",
    }
    label = words.get(status, status)
    findings = len(record.finding_ids)
    suffix = f" ({findings} finding{'s' if findings != 1 else ''})" if findings else ""
    return f"[{index:02d}/{total:02d}] {record.tool or '-':<12} {label}{suffix}"


def missing_binaries(skipped: list[str]) -> list[str]:
    """Binaries named in the playbook's skip reasons, in stable order."""
    found: list[str] = []
    for line in skipped:
        marker = "binary not installed: "
        if marker not in line:
            continue
        name = line.split(marker, 1)[1].strip()
        if name and name not in found:
            found.append(name)
    return sorted(found)


def next_steps(
    *,
    trace,
    report_path: Path | None,
    skipped: list[str],
    install_hint_cmd: str = "./run.sh --install-tools",
) -> list[str]:
    """Plain-language follow-ups derived from what actually happened."""
    steps: list[str] = []
    if report_path is not None:
        steps.append(f"read the report: {report_path}")
    findings = trace.sorted_findings()
    if findings:
        top = findings[0]
        steps.append(
            f"confirm the top finding before reporting it: {top.title[:90]} "
            f"({top.severity.value}, confidence {top.confidence:.2f}, verified="
            f"{'yes' if top.verified else 'no'})"
        )
        cves = sorted({finding.cve for finding in findings if finding.cve})
        if cves:
            steps.append(
                "correlate the version you saw against the offline corpus: "
                f"cpf --correlate '<product>=<version>' --target {trace.target}"
            )
    else:
        steps.append(
            "no findings in this pass: treat that as 'this tool set saw nothing', not as a "
            "clean bill of health"
        )
    binaries = missing_binaries(skipped)
    if binaries:
        preview = ", ".join(binaries[:8])
        steps.append(f"install the {len(binaries)} missing scanner(s) to widen coverage: {preview}")
        steps.append(f"one command on Kali/Debian: {install_hint_cmd}")
    steps.append(f"go deeper: cpf {trace.target} --profile deep")
    return steps


__all__ = [
    "DEFAULT_PROFILE",
    "DEFAULT_SCOPE_DIR",
    "PROFILES",
    "Profile",
    "attestation_reference",
    "default_scope_path",
    "engagement_name",
    "ensure_scope",
    "missing_binaries",
    "next_steps",
    "phase_breakdown",
    "profile_for",
    "render_plan",
    "step_line",
    "target_host",
]
