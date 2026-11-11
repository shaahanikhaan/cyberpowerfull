"""assetfinder wrapper: passive subdomain discovery from third-party sources.

Flags verified against tomnomnom/assetfinder (``main.go`` on main,
2026-11-11): the domain is positional (stdin is read only when no
positional arg is given), ``--subs-only`` keeps names carrying the domain
as a suffix, and stdout is one lowercased deduplicated domain per line
with ``*.``/``%.``/``.`` prefixes stripped. Errors are swallowed silently
and the exit code is always 0, so empty output simply means no source
returned names. All sources are third-party (crt.sh, certspotter,
hackertarget, threatcrowd, virustotal, urlscan, bufferover.run, ...):
the worker requires ``allow_passive_sources`` for this tool.
"""

from __future__ import annotations

from pydantic import Field

from cyberpowerfull.models import Finding, Phase, Severity
from cyberpowerfull.tools.base import BaseTool, DomainInput, truncate


class AssetfinderArgs(DomainInput):
    """Validated assetfinder invocation arguments."""

    subs_only: bool = True
    max_findings: int = Field(default=100, ge=1, le=500)


class AssetfinderTool(BaseTool):
    name = "assetfinder"
    phase = Phase.RECON
    skill = "subdomain_enum"
    binary = "assetfinder"
    description = (
        "Passive subdomain discovery via crt.sh, certspotter and other archives. "
        "Third-party sources: needs allow_passive_sources."
    )
    input_model = AssetfinderArgs

    def build_argv(self, args: AssetfinderArgs, out_file: str | None = None) -> list[str]:
        argv = ["assetfinder"]
        if args.subs_only:
            argv.append("--subs-only")
        argv.append(args.target)
        return argv

    def parse(
        self, args: AssetfinderArgs, output: str, out_file: str | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        for name in _in_scope_names(output, args.target):
            findings.append(
                self.finding(
                    title=f"Subdomain discovered: {name}",
                    severity=Severity.INFO,
                    confidence=0.7,
                    target=args.target,
                    endpoint=name,
                    evidence=truncate(f"assetfinder name={name}"),
                )
            )
            if len(findings) >= args.max_findings:
                break
        return findings

    def observations(self, args: AssetfinderArgs, output: str) -> list[str]:
        names = [line.strip().lower() for line in output.splitlines() if line.strip()]
        in_scope = len(_in_scope_names(output, args.target))
        skipped = len(names) - in_scope
        note = f"assetfinder: {in_scope} in-scope subdomain(s)"
        if skipped:
            note += f" ({skipped} duplicate/out-of-scope name(s) skipped)"
        return [note]


def _in_scope_names(output: str, target: str) -> list[str]:
    """Return deduplicated names at or below ``target``.

    Upstream ``--subs-only`` is a plain suffix match, so ``evillab.test``
    would pass for ``lab.test``; enforce a dot boundary here to stay in
    scope. The bare target itself is the input, not a discovery.
    """
    seen: set[str] = set()
    names: list[str] = []
    suffix = "." + target.lower()
    for line in output.splitlines():
        name = line.strip().lower().rstrip(".")
        if not name or name in seen:
            continue
        seen.add(name)
        if name != target.lower() and name.endswith(suffix):
            names.append(name)
    return names


__all__ = ["AssetfinderArgs", "AssetfinderTool"]
