"""Command line interface.

One job: run (or replay) an authorized penetration-testing engagement. There is
no chat mode, no prompt box, and no interactive assistant.
"""

from __future__ import annotations

import argparse
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
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.models import new_id
from cyberpowerfull.reporting import severity_breakdown, write_reports
from cyberpowerfull.scope import load_scope
from cyberpowerfull.skills import skill_index
from cyberpowerfull.tools.registry import catalog
from cyberpowerfull.trace import StepRecord, load_trace, save_trace, summarize_trace

DESCRIPTION = (
    "cyberpowerfull - local-only autonomous penetration-testing agent.\n"
    "Runs recon -> scanning -> validation -> reporting against an authorized target "
    "using a local open-weight model (Ollama / llama.cpp). No chat mode. No cloud inference."
)

EPILOG = """\
examples:
  cyberpowerfull --scope scope.json --target 127.0.0.1
  cyberpowerfull --scope scope.json --target lab.internal --llm ollama:qwen3:4b --max-iterations 20
  cyberpowerfull --replay traces/latest.json
  cyberpowerfull --check --scope scope.json
  cyberpowerfull --list-tools

exit codes:
  0  run completed without a failed or blocked action
  2  usage error
  3  scope.json missing, invalid, unauthorized, or expired
  4  target outside the authorized scope
  5  local inference unavailable
  6  tool argument or execution error surfaced to the operator
  7  policy violation or blocked delegation by the reasoning model
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _apply_environment(parser, args)
    try:
        if args.list_tools:
            return _list_tools()
        if args.list_skills:
            return _list_skills()
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
