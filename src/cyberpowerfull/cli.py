"""Command line interface.

One job: run (or replay) an authorized penetration-testing engagement. There is
no chat mode, no prompt box, and no interactive assistant.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

from cyberpowerfull import DEFAULT_MODEL, __version__
from cyberpowerfull.brain.attack_tree import AttackTree
from cyberpowerfull.brain.orchestrator import Orchestrator
from cyberpowerfull.brain.prompt import PromptContext, build_system_prompt
from cyberpowerfull.brain.tda import TaskDifficultyAssessor, TDAInput
from cyberpowerfull.config import RunConfig
from cyberpowerfull.errors import CyberpowerfullError, LLMError
from cyberpowerfull.inventory import build_toolchain, install_hint
from cyberpowerfull.knowledge import (
    nmap_script_paths,
    nuclei_template_paths,
    search_exploit_db,
    wordlist_summary,
)
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.models import new_id
from cyberpowerfull.playbook import PlaybookRunner, describe_playbooks, get_playbook
from cyberpowerfull.reporting import severity_breakdown, write_reports
from cyberpowerfull.scope import load_scope
from cyberpowerfull.skills import skill_index
from cyberpowerfull.tools.registry import catalog, external_agent_catalog
from cyberpowerfull.trace import StepRecord, load_trace, save_trace, summarize_trace

DESCRIPTION = (
    "cyberpowerfull - local-only autonomous penetration-testing agent.\n"
    "Runs recon -> scanning -> validation -> reporting against an authorized target "
    "using a local open-weight model (Ollama / llama.cpp), or a deterministic "
    "multi-tool playbook when no model is available. No chat mode. No cloud inference."
)

EPILOG = """\
examples:
  cyberpowerfull --scope scope.json --target 127.0.0.1
  cyberpowerfull --scope scope.json --target lab.internal --llm ollama:qwen3:4b --max-iterations 20
  cyberpowerfull --scope scope.json --target lab.internal --playbook full --parallel 4
  cyberpowerfull --scope scope.json --target app.example.test --playbook web
  cyberpowerfull --toolchain                    # live inventory of this host
  cyberpowerfull --doctor --scope scope.json    # pre-engagement readiness check
  cyberpowerfull --list-playbooks
  cyberpowerfull --agents
  cyberpowerfull --search-exploits "apache 2.4"
  cyberpowerfull --replay traces/latest.json

exit codes:
  0  run completed without a failed or blocked action
  2  usage error
  3  scope.json missing, invalid, unauthorized, or expired
  4  target outside the authorized scope
  5  local inference unavailable
  6  tool argument or execution error, or a missing local knowledge source
  7  policy violation or blocked delegation by the reasoning model
  8  unknown playbook name
"""


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberpowerfull",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    defaults = RunConfig()
    # Environment values are resolved after parsing so that --help/--version and
    # explicit CLI overrides keep working even when an environment value is bad.
    parser.add_argument(
        "--scope",
        default=None,
        metavar="PATH",
        help="engagement scope file (default: $CYBERPOWERFULL_SCOPE or scope.json)",
    )
    parser.add_argument("--target", metavar="HOST", help="authorized target host or URL")
    parser.add_argument(
        "--llm",
        default=None,
        metavar="SPEC",
        help=f"local inference backend: ollama[:MODEL], llamacpp[:MODEL], replay:PATH "
        f"(default: $CYBERPOWERFULL_LLM or ollama:{DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--replay", metavar="TRACE", help="replay a recorded trace instead of running the agent"
    )
    parser.add_argument(
        "--check", action="store_true", help="validate scope, tool availability, and model endpoint"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build tool command lines but execute nothing (safe rehearsal)",
    )
    parser.add_argument(
        "--max-iterations",
        type=_positive_int,
        default=None,
        metavar="N",
        help=f"reasoning iteration budget (default: $CYBERPOWERFULL_MAX_ITERATIONS or "
        f"{defaults.max_iterations})",
    )
    parser.add_argument(
        "--max-tokens",
        type=_positive_int,
        default=None,
        metavar="N",
        help=f"estimated token budget (default: $CYBERPOWERFULL_MAX_TOKENS or "
        f"{defaults.max_tokens})",
    )
    parser.add_argument(
        "--max-seconds",
        type=_positive_int,
        default=None,
        metavar="N",
        help=f"wall-clock budget in seconds (default: $CYBERPOWERFULL_MAX_SECONDS or "
        f"{defaults.max_seconds})",
    )
    parser.add_argument("--out", default="artifacts", metavar="DIR", help="report output directory")
    parser.add_argument(
        "--trace", default="traces/latest.json", metavar="PATH", help="where to write the run trace"
    )
    parser.add_argument(
        "--memory", default="artifacts/memory.sqlite3", metavar="PATH", help="SQLite memory path"
    )
    parser.add_argument(
        "--render-prompt", action="store_true", help="print the rendered system prompt"
    )
    parser.add_argument("--list-tools", action="store_true", help="list typed tool wrappers")
    parser.add_argument("--list-skills", action="store_true", help="list skill packs")
    parser.add_argument(
        "--toolchain",
        action="store_true",
        help="probe this host and print the live pentest toolchain inventory",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="readiness check: scope, binaries, wordlists, templates, external agents, model",
    )
    parser.add_argument("--list-playbooks", action="store_true", help="list playbooks")
    parser.add_argument(
        "--playbook",
        metavar="NAME",
        help="run a deterministic multi-tool playbook instead of the reasoning loop",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=0,
        metavar="N",
        help="parallel steps inside a playbook group (default: playbook specific)",
    )
    parser.add_argument("--max-steps", type=int, default=80, metavar="N")
    parser.add_argument(
        "--agents", action="store_true", help="list external autonomous agent integrations"
    )
    parser.add_argument(
        "--search-exploits",
        dest="search_exploits",
        metavar="QUERY",
        help="query the local Exploit-DB mirror (no network access)",
    )
    parser.add_argument(
        "--templates",
        nargs="?",
        const="",
        metavar="PATTERN",
        help="list installed nuclei templates, optionally filtered",
    )
    parser.add_argument(
        "--nse",
        nargs="?",
        const="",
        metavar="PATTERN",
        help="list installed nmap NSE scripts, optionally filtered",
    )
    parser.add_argument(
        "--wordlists",
        nargs="?",
        const="",
        metavar="KIND",
        help="list discovered wordlists (kind: discovery|passwords|dns|fuzzing)",
    )
    parser.add_argument("--json", action="store_true", help="emit the trace JSON on stdout")
    parser.add_argument("--quiet", action="store_true", help="suppress per-step progress lines")
    parser.add_argument("--version", action="version", version=f"cyberpowerfull {__version__}")
    return parser


def _env_positive_int(parser: argparse.ArgumentParser, name: str, fallback: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return fallback
    try:
        value = int(raw)
    except ValueError:
        parser.error(f"invalid environment configuration: {name} must be an integer, got {raw!r}")
    if value < 1:
        parser.error(
            f"invalid environment configuration: {name} must be a positive integer, got {value}"
        )
    return value


def _apply_environment(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Resolve unset flags from the environment, validating only values actually used."""
    defaults = RunConfig()
    if args.scope is None:
        args.scope = os.environ.get("CYBERPOWERFULL_SCOPE", "scope.json")
    if args.llm is None:
        args.llm = os.environ.get("CYBERPOWERFULL_LLM") or (
            f"{os.environ.get('CYBERPOWERFULL_LLM_BACKEND', 'ollama')}:"
            f"{os.environ.get('CYBERPOWERFULL_MODEL', DEFAULT_MODEL)}"
        )
    if args.max_iterations is None:
        args.max_iterations = _env_positive_int(
            parser, "CYBERPOWERFULL_MAX_ITERATIONS", defaults.max_iterations
        )
    if args.max_tokens is None:
        args.max_tokens = _env_positive_int(
            parser, "CYBERPOWERFULL_MAX_TOKENS", defaults.max_tokens
        )
    if args.max_seconds is None:
        args.max_seconds = _env_positive_int(
            parser, "CYBERPOWERFULL_MAX_SECONDS", defaults.max_seconds
        )


def _progress(record: StepRecord) -> None:
    status = (record.result or {}).get("status", "-")
    level = record.tda.get("level", "-")
    print(
        f"[{record.index:02d}] {record.action:<16} {record.tool or '-':<12} "
        f"status={status:<8} findings={len(record.finding_ids)} "
        f"difficulty={level:<8} node={record.node or '-'}",
        file=sys.stderr,
    )


def _print_summary(trace, *, trace_path: Path | None, report_path: Path | None) -> None:
    summary = summarize_trace(trace)
    print("")
    print(f"run_id:      {summary['run_id']}")
    print(f"engagement:  {summary['engagement']}")
    print(f"target:      {summary['target']}")
    print(f"model:       {summary['backend']}:{summary['model']}")
    print(f"stop_reason: {summary['stop_reason']}")
    print(
        f"steps:       {summary['steps']} (tool calls: {summary['tool_calls']}, "
        f"tokens: {trace.budget.tokens_used}/{trace.budget.max_tokens})"
    )
    print(f"findings:    {summary['findings']} [{severity_breakdown(trace)}]")
    if trace_path is not None:
        print(f"trace:       {trace_path}")
    if report_path is not None:
        print(f"report:      {report_path}")


def _run(args: argparse.Namespace) -> int:
    from cyberpowerfull.brain.llm import build_client

    scope = load_scope(args.scope)
    # Preserve the operator's URL, path and port in the objective after checking the host.
    scope.require(args.target or "")
    target = (args.target or "").strip()

    cfg = RunConfig(
        scope_path=Path(args.scope),
        target=target,
        llm_spec=args.llm or f"ollama:{DEFAULT_MODEL}",
        max_iterations=args.max_iterations,
        max_tokens=args.max_tokens,
        max_seconds=args.max_seconds,
        out_dir=Path(args.out),
        memory_path=Path(args.memory),
        trace_path=Path(args.trace),
        dry_run=args.dry_run,
    )
    cfg.ensure_dirs()
    client = build_client(cfg.llm_spec)
    run_id = new_id("run-")

    with MemoryStore(cfg.memory_path, run_id=run_id) as memory:
        orchestrator = Orchestrator(
            scope=scope,
            config=cfg,
            client=client,
            memory=memory,
            target=target,
            run_id=run_id,
        )
        if not args.quiet:
            print(
                f"starting run {run_id} against {target} "
                f"(engagement={scope.engagement}, backend={client.backend}, model={client.model})",
                file=sys.stderr,
            )
        result = orchestrator.run(progress=None if args.quiet else _progress)

    trace = result.trace
    trace_path = save_trace(trace, cfg.trace_path)
    paths = write_reports(trace, cfg.out_dir)
    if args.json:
        print(trace.model_dump_json(indent=2))
    else:
        _print_summary(trace, trace_path=trace_path, report_path=paths["report"])
    return _run_exit_code(trace)


def _run_exit_code(trace) -> int:
    """Surface fatal and partial failures while retaining the trace and reports."""
    if trace.stop_reason == "inference_failed":
        return 5
    if trace.stop_reason == "policy_violation":
        return 7
    if trace.stop_reason == "prompt_render_failed":
        return 1
    statuses = {(step.result or {}).get("status") for step in trace.steps}
    if "blocked" in statuses:
        return 7
    if statuses & {"error", "missing", "timeout"} or any(
        step.action == "delegate" and step.error for step in trace.steps
    ):
        return 6
    return 0


def _replay(args: argparse.Namespace) -> int:
    trace = load_trace(args.replay)
    paths = write_reports(trace, Path(args.out))
    if args.json:
        print(trace.model_dump_json(indent=2))
    else:
        print(f"replayed trace {args.replay} (run {trace.run_id})")
        _print_summary(trace, trace_path=None, report_path=paths["report"])
        for index, step in enumerate(trace.steps, start=1):
            status = (step.result or {}).get("status", "-")
            print(
                f"  step {index:02d}: {step.action:<10} {step.tool or '-':<12} status={status:<8} "
                f"findings={len(step.finding_ids)}"
            )
    return 0


def _check(args: argparse.Namespace) -> int:
    from cyberpowerfull.brain.llm import build_client

    scope = load_scope(args.scope)
    print(f"scope: ok (engagement={scope.engagement}, fingerprint={scope.fingerprint()[:16]})")
    if args.target:
        scope.require(args.target)
        print(f"target: in scope ({args.target})")
    print(f"allowed phases: {', '.join(phase.value for phase in scope.allowed_phases)}")
    print(
        f"passive third-party sources: {'enabled' if scope.allow_passive_sources else 'disabled'}"
    )
    print(
        f"allowed wordlists: {len(scope.allowed_wordlists)}; "
        f"allowed nuclei template files: {len(scope.allowed_nuclei_templates)}"
    )

    missing: list[str] = []
    for tool in catalog():
        if tool["installed"]:
            label = (
                "ready (native)"
                if tool["binary"] == "native"
                else "found on PATH (not version-checked)"
            )
            print(f"tool: {tool['name']:<12} {label} ({tool['binary']})")
        else:
            missing.append(tool["name"])
            print(f"tool: {tool['name']:<12} MISSING binary ({tool['binary']})")
    if missing:
        print(f"note: {len(missing)} external tool(s) missing; they will report status=missing")

    client = build_client(args.llm)
    health = client.health()
    print(f"model: {health.get('backend')} {health.get('endpoint', '')} ok={health.get('ok')}")
    if health.get("error"):
        print(f"model error: {health['error']}")
        return LLMError.exit_code
    return 0 if health.get("ok") else LLMError.exit_code


def _render_prompt(args: argparse.Namespace) -> int:
    scope = load_scope(args.scope)
    scope.require(args.target or "")
    target = (args.target or "").strip()
    model = (args.llm or "").partition(":")[2] or DEFAULT_MODEL
    with MemoryStore(":memory:", run_id="prompt-preview") as memory:
        tree = AttackTree(target=target)
        tda = TaskDifficultyAssessor().assess(
            TDAInput(iteration=0, max_iterations=args.max_iterations)
        )
        context = PromptContext(
            target=target,
            engagement=scope.engagement,
            phase=tree.get(tree.root_id).phase,
            step=1,
            max_iterations=args.max_iterations,
            tokens_left=args.max_tokens,
            model=model,
            scope_block=scope.prompt_block(),
            memory_digest=memory.digest(),
            difficulty=tda,
            tree_digest=tree.digest(),
            tools=catalog(),
        )
        print(build_system_prompt(context))
    return 0


def _list_tools() -> int:
    rows = [
        (
            tool["name"],
            tool["phase"],
            tool["binary"],
            "yes" if tool["installed"] else "no",
            tool["skill"],
        )
        for tool in catalog()
    ]
    width = max(len(row[0]) for row in rows)
    print(f"{'tool'.ljust(width)}  phase      binary         installed  skill")
    for name, phase, binary, installed, skill in rows:
        print(f"{name.ljust(width)}  {phase:<10} {binary:<14} {installed:<10} {skill}")
    print(f"\n{len(rows)} typed tools registered")
    return 0


def _list_skills() -> int:
    index = skill_index()
    width = max(len(item["name"]) for item in index)
    print(f"{'skill'.ljust(width)}  category        tools")
    for item in index:
        print(f"{item['name'].ljust(width)}  {item['category']:<15} {', '.join(item['tools'])}")
    print(f"\n{len(index)} skill packs registered")
    return 0


def _print_toolchain(args: argparse.Namespace) -> int:
    toolchain = build_toolchain(versions=True, include_wordlists=True)
    if args.json:
        print(json.dumps(toolchain.as_dict(), indent=2, default=str))
        return 0
    print("host toolchain (probed live)")
    for line in toolchain.summary_lines(limit=40):
        print(f"  {line}")
    print("")
    print(f"{'family':<14} {'installed':>9} {'missing':>8}")
    for family, counts in sorted(toolchain.families().items()):
        print(f"{family:<14} {counts['installed']:>9} {counts['missing']:>8}")
    missing = toolchain.missing()
    if missing:
        print("")
        print("install hints (missing tools):")
        for name in missing[:20]:
            hint = install_hint(name)
            if hint:
                print(f"  {name:<14} {hint}")
    return 0


def _doctor(args: argparse.Namespace) -> int:
    from cyberpowerfull.brain.llm import build_client

    print("readiness check")
    scope = load_scope(args.scope)
    print(
        f"  scope:        ok (engagement={scope.engagement}, "
        f"fingerprint={scope.fingerprint()[:16]})"
    )
    if args.target:
        print(f"  target:       in scope ({scope.require(args.target)})")
    print(
        "  capabilities: "
        + (", ".join(capability.value for capability in scope.capabilities) or "none granted")
    )
    toolchain = build_toolchain(versions=True, include_wordlists=True)
    installed = toolchain.installed()
    missing = toolchain.missing()
    print(f"  binaries:     {len(installed)} installed, {len(missing)} missing")
    for name in ("nmap", "nuclei", "ffuf", "nikto", "subfinder", "httpx"):
        state = "ready" if toolchain.has(name) else "MISSING"
        version = toolchain.version(name) or ""
        print(f"    {name:<11} {state:<8} {version[:60]}")
    for kind, label in (
        ("discovery", "content discovery"),
        ("dns", "subdomain"),
        ("passwords", "password"),
        ("fuzzing", "parameter"),
    ):
        path = next((item.path for item in toolchain.wordlists_of_kind(kind)), None)
        print(f"  wordlist/{label}: {path or 'none found'}")
    print(
        "  nuclei templates: "
        + (
            f"{toolchain.nuclei_templates.get('count', 0)} in "
            f"{toolchain.nuclei_templates.get('path')}"
            if toolchain.nuclei_templates.get("path")
            else "not installed (nuclei -update-templates)"
        )
    )
    print(f"  nmap NSE scripts: {toolchain.nmap_scripts}")
    print(f"  exploitdb:        {'present' if toolchain.exploitdb_present else 'not installed'}")
    for name, info in sorted(toolchain.external_agents.items()):
        state = "ready" if info.get("available") else "unavailable"
        print(f"  agent/{name}: {state} (requires {', '.join(info.get('requires', []))})")
    client = build_client(args.llm)
    health = client.health()
    print(
        f"  model:        {health.get('backend')} {health.get('endpoint', '')} "
        f"ok={health.get('ok')}"
    )
    if health.get("error"):
        print(f"    error: {health['error']}")
    print("")
    if missing:
        urgent = [name for name in ("nmap", "nuclei", "httpx") if name in missing]
        if urgent:
            print("  next: install " + ", ".join(urgent) + " for the full tool set")
    if not toolchain.nuclei_templates.get("path"):
        print("  next: run 'nuclei -update-templates' so template validation is available")
    print("  note: playbooks run without a model; the reasoning loop needs one")
    return 0 if health.get("ok") else LLMError.exit_code


def _list_playbooks() -> int:
    rows = describe_playbooks()
    width = max(len(row["name"]) for row in rows)
    print(f"{'playbook'.ljust(width)}  steps  tools")
    for row in rows:
        print(
            f"{row['name'].ljust(width)}  {row['steps']:>5}  "
            f"{', '.join(row['tools'][:8])}{' ...' if len(row['tools']) > 8 else ''}"
        )
        print(f"{' ' * (width + 9)}{row['description']}")
    print(f"\n{len(rows)} playbooks registered")
    return 0


def _list_agents() -> int:
    rows = external_agent_catalog()
    width = max(len(row["tool"]) for row in rows)
    print(f"{'agent'.ljust(width)}  available  capability        requires")
    for row in rows:
        print(
            f"{row['tool'].ljust(width)}  {'yes' if row['available'] else 'no':<9}  "
            f"{row['capability']!s:<16}  {', '.join(row['requires']) or '-'}"
        )
    print("")
    for row in rows:
        print(f"{row['tool']}: {row['description']}")
    return 0


def _knowledge(args: argparse.Namespace) -> int:
    if args.search_exploits is not None:
        records = search_exploit_db(args.search_exploits)
        if args.json:
            print(json.dumps([record.as_dict() for record in records], indent=2))
            return 0
        if not records:
            print(f"no local Exploit-DB record matched {args.search_exploits!r}")
            return 0
        print(f"{len(records)} local Exploit-DB record(s) for {args.search_exploits!r}")
        for record in records:
            print(
                f"  EDB-{record.edb_id:<8} {record.date:<12} {record.exploit_type:<22} "
                f"{record.title[:80]}"
            )
        return 0
    if args.templates is not None:
        paths = nuclei_template_paths(args.templates, limit=500)
        print(f"{len(paths)} nuclei template(s) matched {args.templates!r}")
        for path in paths[:100]:
            print(f"  {path}")
        return 0
    if args.nse is not None:
        scripts = nmap_script_paths(args.nse, limit=500)
        print(f"{len(scripts)} NSE script(s) matched {args.nse!r}")
        for name in scripts[:100]:
            print(f"  {name}")
        return 0
    if args.wordlists is not None:
        items = wordlist_summary(args.wordlists or None)
        if args.json:
            print(json.dumps(items, indent=2))
            return 0
        print(f"{len(items)} wordlist(s) discovered")
        for item in items[:60]:
            kind = item["kind"]
            size = item["size_bytes"] / 1024
            flag = " (compressed)" if item["compressed"] else ""
            print(f"  {kind:<10} {size:>9.0f} KiB  {item['path']}{flag}")
        return 0
    return 0


def _run_playbook(args: argparse.Namespace) -> int:
    from cyberpowerfull.config import RunConfig

    scope = load_scope(args.scope)
    target = scope.require(args.target or "")
    cfg = RunConfig(
        scope_path=Path(args.scope),
        target=target,
        llm_spec=args.llm or f"ollama:{DEFAULT_MODEL}",
        max_iterations=args.max_iterations,
        max_tokens=args.max_tokens,
        max_seconds=args.max_seconds,
        out_dir=Path(args.out),
        memory_path=Path(args.memory),
        trace_path=Path(args.trace),
        dry_run=args.dry_run,
    )
    cfg.ensure_dirs()
    playbook = get_playbook(args.playbook)
    run_id = new_id("play-")
    with MemoryStore(cfg.memory_path, run_id=run_id) as memory:
        runner = PlaybookRunner(
            scope=scope,
            target=target,
            memory=memory,
            dry_run=cfg.dry_run,
            max_seconds=cfg.max_seconds,
            max_steps=args.max_steps,
            parallel=args.parallel or None,
            run_id=run_id,
        )
        print(
            f"starting playbook {playbook.name} against {target} "
            f"(engagement={scope.engagement}, steps={len(playbook.steps)})",
            file=sys.stderr,
        )
        result = runner.run(playbook, progress=None if args.quiet else _progress)
    trace_path = save_trace(result.trace, cfg.trace_path)
    paths = write_reports(result.trace, cfg.out_dir)
    if args.json:
        print(result.trace.model_dump_json(indent=2))
    else:
        _print_summary(result.trace, trace_path=trace_path, report_path=paths["report"])
        print(f"executed:    {len(result.executed)} step(s): {', '.join(result.executed)}")
        if result.skipped:
            print(f"skipped:     {len(result.skipped)}")
            for line in result.skipped[:12]:
                print(f"  - {line}")
    return _run_exit_code(result.trace)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _apply_environment(parser, args)
    try:
        if args.list_tools:
            return _list_tools()
        if args.list_skills:
            return _list_skills()
        if args.list_playbooks:
            return _list_playbooks()
        if args.agents:
            return _list_agents()
        if args.toolchain:
            return _print_toolchain(args)
        if (
            args.search_exploits is not None
            or args.templates is not None
            or args.nse is not None
            or args.wordlists is not None
        ):
            return _knowledge(args)
        if args.doctor:
            return _doctor(args)
        if args.playbook:
            if not args.target:
                parser.error("--playbook requires --target")
            return _run_playbook(args)
        if args.replay:
            return _replay(args)
        if args.check:
            return _check(args)
        if args.render_prompt:
            return _render_prompt(args)
        if not args.target:
            parser.error("--target is required (or use --replay, --check, --list-tools)")
        return _run(args)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("interrupted", file=sys.stderr)
        return 130
    except CyberpowerfullError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, sqlite3.Error) as exc:
        print(f"error: local storage operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
