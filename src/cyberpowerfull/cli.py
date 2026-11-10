"""Command line interface.

One job: run (or replay) an authorized penetration-testing engagement. There is
no chat mode, no prompt box, and no interactive assistant.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cyberpowerfull import DEFAULT_MODEL, __version__
from cyberpowerfull.brain.attack_tree import AttackTree
from cyberpowerfull.brain.orchestrator import Orchestrator
from cyberpowerfull.brain.prompt import PromptContext, build_system_prompt
from cyberpowerfull.brain.tda import TaskDifficultyAssessor, TDAInput
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
  0  run completed (any stop condition)
  2  usage error
  3  scope.json missing, invalid, unauthorized, or expired
  4  target outside the authorized scope
  5  local inference unavailable
  6  tool argument or execution error surfaced to the operator
  7  policy violation by the reasoning model
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberpowerfull",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scope",
        default="scope.json",
        metavar="PATH",
        help="engagement scope file (required; the agent refuses to run without it)",
    )
    parser.add_argument("--target", metavar="HOST", help="authorized target host or URL")
    parser.add_argument(
        "--llm",
        default=None,
        metavar="SPEC",
        help=f"local inference backend: ollama[:MODEL], llamacpp[:MODEL], replay:PATH "
        f"(default: ollama:{DEFAULT_MODEL})",
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
    parser.add_argument("--max-iterations", type=int, default=12, metavar="N")
    parser.add_argument("--max-tokens", type=int, default=24_000, metavar="N")
    parser.add_argument("--max-seconds", type=int, default=900, metavar="N")
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


def _progress(record: StepRecord) -> None:
    status = (record.result or {}).get("status", "-")
    level = record.tda.get("level", "-")
    print(
        f"[{record.index:02d}] {record.action:<16} {record.tool or '-':<12} "
        f"status={status:<8} findings={len(record.finding_ids)} "
        f"difficulty={level:<8} node={record.node or '-'}"
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
    from cyberpowerfull.config import RunConfig

    scope = load_scope(args.scope)
    # scope.require raises ScopeViolation (exit 4) for anything outside the engagement.
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

    missing: list[str] = []
    for tool in catalog():
        if tool["installed"]:
            print(f"tool: {tool['name']:<12} ready ({tool['binary']})")
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
    target = scope.require(args.target or "")
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


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
