"""Root Agent orchestration loop.

Strict role separation is enforced in code, not in the prompt alone:

* :class:`RootAgent` can only emit ``delegate`` or ``terminate``. It has no
  executor, no subprocess handle, and no write access to memory.
* :class:`WorkerAgent` owns the typed tools, re-checks scope, and executes.
* :class:`Orchestrator` is the only component that mutates the attack tree,
  memory, and the trace, and it does so deterministically from tool results.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cyberpowerfull.brain.attack_tree import AttackTree, ExpansionProposal
from cyberpowerfull.brain.llm import LLMClient
from cyberpowerfull.brain.prompt import (
    PromptContext,
    build_step_prompt,
    build_system_prompt,
)
from cyberpowerfull.brain.tda import DifficultyLevel, TaskDifficultyAssessor, TDAInput, TDAReport
from cyberpowerfull.config import RunConfig, ToolPolicy
from cyberpowerfull.errors import (
    InvalidToolArguments,
    LLMError,
    PolicyViolation,
    ScopeError,
    ScopeViolation,
)
from cyberpowerfull.inventory import NUCLEI_TEMPLATE_ROOTS, WORDLIST_ROOTS, build_toolchain
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.models import (
    BudgetState,
    Decision,
    Finding,
    Phase,
    Severity,
    estimate_tokens,
    utcnow,
)
from cyberpowerfull.scope import Scope, network_contains, normalize_host
from cyberpowerfull.skills import select_skills, skill_names
from cyberpowerfull.tools.base import BaseTool, ToolResult, ToolStatus
from cyberpowerfull.tools.registry import catalog, get_tool
from cyberpowerfull.trace import StepRecord, Trace, TraceRecorder

#: Phase each worker owns. The allowlist is derived from the registry, so adding
#: a tool wrapper automatically makes it delegable to the right worker.
WORKER_PHASES: dict[str, tuple[Phase, ...]] = {
    "recon": (Phase.RECON,),
    "scan": (Phase.SCANNING,),
    "validate": (Phase.VALIDATION,),
    "external": (),
}

#: Cross-phase tools a worker may additionally run (surface mapping needs a port
#: sweep, validation needs an HTTP probe, and so on).
WORKER_EXTRA_TOOLS: dict[str, tuple[str, ...]] = {
    "recon": ("nmap", "nikto", "tcp_probe"),
    "scan": ("httpx", "tcp_probe"),
    "validate": ("ffuf", "httpx"),
    "external": (),
}


def _worker_allowlist() -> dict[str, frozenset[str]]:
    from cyberpowerfull.tools.registry import all_tools

    tools = all_tools()
    mapping: dict[str, frozenset[str]] = {}
    for worker, phases in WORKER_PHASES.items():
        if worker == "external":
            mapping[worker] = frozenset(name for name, tool in tools.items() if tool.external)
            continue
        allowed = {
            name for name, tool in tools.items() if tool.phase in phases and not tool.external
        }
        allowed.update(name for name in WORKER_EXTRA_TOOLS[worker] if name in tools)
        mapping[worker] = frozenset(allowed)
    return mapping


#: Deterministic delegation allowlist: which worker may run which tool.
WORKER_TOOL_ALLOWLIST: dict[str, frozenset[str]] = _worker_allowlist()


class DelegationRequest(BaseModel):
    """Validated payload of a ``delegate`` decision."""

    model_config = ConfigDict(extra="forbid")

    agent: Literal["recon", "scan", "validate", "external"] = "recon"
    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    node: str | None = None
    expand: list[ExpansionProposal] = Field(default_factory=list)
    reason: str | None = Field(default=None, max_length=400)


class RootAgent:
    """Orchestration-only role. Holds an LLM client and nothing else."""

    ALLOWED_ACTIONS: frozenset[str] = frozenset({"delegate", "terminate"})

    def __init__(self, client: LLMClient) -> None:
        self._client = client

    def act(self, system_prompt: str, step_prompt: str, *, step: int) -> Decision:
        decision = self._client.decide(system_prompt, step_prompt, step=step)
        action = decision.tool.strip().lower()
        if action not in self.ALLOWED_ACTIONS:
            raise PolicyViolation(
                f"root agent attempted action {action!r}; permitted actions are "
                f"{sorted(self.ALLOWED_ACTIONS)}"
            )
        return decision.model_copy(update={"tool": action})


_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _top_severity(findings: list[Finding] | None) -> str | None:
    """Highest severity in a step's findings (for traces and live display)."""
    best: str | None = None
    for finding in findings or []:
        level = finding.severity.value if isinstance(finding.severity, Severity) else None
        if level is None:
            continue
        if best is None or _SEVERITY_ORDER.index(level) > _SEVERITY_ORDER.index(best):
            best = level
    return best


def _network_entry(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _library_file(value: str) -> bool:
    """True for a real file inside the host's wordlist / nuclei-template trees.

    ``allowed_wordlists`` and ``allowed_nuclei_templates`` exist so the model cannot
    point a fuzzer at arbitrary host files (``/etc/shadow``, an SSH key). Files from
    the operator's own installed libraries - the Kali wordlist and nuclei template
    directories reported by the live inventory - are that same category of trusted
    data, so they are accepted without listing every path after every update.
    """
    try:
        candidate = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    if not candidate.is_file():
        return False
    for root in (*WORDLIST_ROOTS, *NUCLEI_TEMPLATE_ROOTS):
        try:
            base = Path(root).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            continue
        if candidate == base or base in candidate.parents:
            return True
    return False


def _allowed_file(value: str, allowed: list[str]) -> bool:
    """Allow only an exact existing file explicitly named by the operator."""
    try:
        candidate = Path(value).expanduser().resolve(strict=True)
        if not candidate.is_file():
            return False
        for path in allowed:
            try:
                if candidate == Path(path).expanduser().resolve(strict=True):
                    return True
            except (OSError, RuntimeError, ValueError):
                continue
    except (OSError, RuntimeError, ValueError):
        pass
    return False


def _dns_exclusion_error(target: str, excluded_networks: tuple[str, ...]) -> str | None:
    """Best-effort preflight; external scanners can resolve again after this check."""
    host = normalize_host(target)
    if not excluded_networks and host != "localhost":
        return None
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        return f"target DNS lookup failed: {exc}"
    if not addresses:
        return "target DNS returned no addresses"
    networks = [ipaddress.ip_network(entry, strict=False) for entry in excluded_networks]
    for item in addresses:
        address = ipaddress.ip_address(item[4][0].split("%", 1)[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if host == "localhost" and not address.is_loopback:
            return "localhost resolved outside loopback"
        if any(network_contains(network, address) for network in networks):
            return "target DNS resolved to an excluded network"
    return None


class WorkerAgent:
    """Executes exactly one delegated tool call, after re-checking scope."""

    def __init__(
        self,
        name: str,
        *,
        scope: Scope,
        policy: ToolPolicy | None = None,
        tools: dict[str, BaseTool] | None = None,
    ) -> None:
        self.name = name
        self.scope = scope
        base_policy = policy or ToolPolicy()
        self.policy = replace(
            base_policy,
            max_rps=min(scope.max_rps, base_policy.max_rps or scope.max_rps),
            excluded_networks=tuple(item for item in scope.exclude if _network_entry(item)),
        )
        self._tools = tools if tools is not None else {}
        self.allowlist = WORKER_TOOL_ALLOWLIST[name]

    def _resolve(self, tool_name: str) -> BaseTool:
        if tool_name not in self.allowlist:
            raise PolicyViolation(
                f"worker {self.name!r} may not run {tool_name!r}; allowed: "
                f"{sorted(self.allowlist)}"
            )
        if tool_name in self._tools:
            return self._tools[tool_name]
        return get_tool(tool_name)

    def execute(
        self,
        request: DelegationRequest,
        *,
        dry_run: bool = False,
        timeout_s: float | None = None,
    ) -> ToolResult:
        try:
            self.scope.assert_runnable()
            tool = self._resolve(request.tool)
        except (PolicyViolation, ScopeError) as exc:
            return ToolResult(tool=request.tool, status=ToolStatus.BLOCKED, error=str(exc))

        if tool.phase not in self.scope.allowed_phases:
            return ToolResult(
                tool=tool.name,
                status=ToolStatus.BLOCKED,
                error=f"phase {tool.phase.value!r} is not permitted by scope.json",
            )

        capability = tool.required_capability
        if capability is not None and not self.scope.allows(capability):
            return ToolResult(
                tool=tool.name,
                status=ToolStatus.BLOCKED,
                error=(
                    f"tool {tool.name!r} requires the {capability.value!r} capability; add it "
                    "to scope.json only when the engagement authorises it"
                ),
            )

        target = request.args.get("target")
        if not isinstance(target, str) or not target.strip():
            return ToolResult(
                tool=tool.name,
                status=ToolStatus.ERROR,
                error="delegation args must include a string 'target'",
            )
        try:
            self.scope.require(target)
            validated = tool.validate(request.args)
            # Validate the actual canonical target the wrapper will receive too.
            self.scope.require(validated.target)
        except ScopeViolation as exc:
            return ToolResult(tool=tool.name, status=ToolStatus.BLOCKED, error=str(exc))
        except InvalidToolArguments as exc:
            return ToolResult(tool=tool.name, status=ToolStatus.ERROR, error=str(exc))

        if tool.name == "subfinder" and not self.scope.allow_passive_sources:
            return ToolResult(
                tool=tool.name,
                status=ToolStatus.BLOCKED,
                error=(
                    "subfinder sends domains to external sources; "
                    "set allow_passive_sources in scope"
                ),
            )
        if tool.name == "ffuf" and not (
            _allowed_file(str(request.args.get("wordlist", "")), self.scope.allowed_wordlists)
            or _library_file(str(request.args.get("wordlist", "")))
        ):
            return ToolResult(
                tool=tool.name,
                status=ToolStatus.BLOCKED,
                error="ffuf wordlist must be an existing file listed in scope.allowed_wordlists",
            )
        if tool.name == "nuclei":
            templates = request.args.get("templates") or []
            if not templates or any(
                not (
                    _allowed_file(str(path), self.scope.allowed_nuclei_templates)
                    or _library_file(str(path))
                )
                for path in templates
            ):
                return ToolResult(
                    tool=tool.name,
                    status=ToolStatus.BLOCKED,
                    error=(
                        "nuclei requires explicit template files listed in "
                        "scope.allowed_nuclei_templates or from the local template library"
                    ),
                )
        policy = self.policy
        if timeout_s is not None:
            policy = replace(policy, timeout_s=min(policy.timeout_s, max(timeout_s, 0.001)))
        # The native TCP probe performs its own pinned DNS check; third-party
        # scanners get a best-effort preflight, not a substitute for egress rules.
        if not dry_run and tool.name not in {"tcp_probe", "subfinder"}:
            dns_error = _dns_exclusion_error(validated.target, policy.excluded_networks)
            if dns_error:
                return ToolResult(tool=tool.name, status=ToolStatus.BLOCKED, error=dns_error)
        result = tool.run(request.args, dry_run=dry_run, policy=policy)
        allowed = [
            finding
            for finding in result.findings
            if self.scope.authorizes(finding.target)
            and (finding.endpoint is None or self.scope.authorizes(finding.endpoint))
        ]
        suppressed = len(result.findings) - len(allowed)
        if suppressed:
            result = result.model_copy(
                update={
                    "findings": allowed,
                    "observations": [
                        *result.observations,
                        f"suppressed {suppressed} out-of-scope finding(s)",
                    ],
                }
            )
        return result


@dataclass
class RunResult:
    """Outcome of one agent run."""

    trace: Trace
    stop_reason: str
    findings: list[Finding]


class Orchestrator:
    """Deterministic control plane around the reasoning model."""

    def __init__(
        self,
        *,
        scope: Scope,
        config: RunConfig,
        client: LLMClient,
        memory: MemoryStore,
        target: str,
        tree: AttackTree | None = None,
        policy: ToolPolicy | None = None,
        assessor: TaskDifficultyAssessor | None = None,
        tools: dict[str, BaseTool] | None = None,
        skills: list[str] | None = None,
        context_window: int = 32768,
        run_id: str | None = None,
        toolchain: Any | None = None,
        skill_limit: int = 8,
    ) -> None:
        self.scope = scope
        self.config = config
        self.client = client
        self.memory = memory
        self.target = target
        self.policy = policy or ToolPolicy()
        self.assessor = assessor or TaskDifficultyAssessor()
        self.context_window = context_window
        if run_id is not None and run_id != memory.run_id:
            raise ValueError("orchestrator run_id must match the memory run_id")
        self.run_id = run_id or memory.run_id
        self.skills = skills or skill_names()
        self.skill_limit = skill_limit
        self.tools = tools or {}
        self.tree = tree or AttackTree(target=target)
        self.root = RootAgent(client)
        self._workers = {
            name: WorkerAgent(name, scope=scope, policy=self.policy, tools=self.tools)
            for name in WORKER_TOOL_ALLOWLIST
        }
        self._seen_findings: set[tuple[str, str | None]] = {
            (finding.title, finding.endpoint) for finding in memory.findings()
        }
        self._failed_attempts = 0
        self._tool_catalog = (
            [tool.describe() for tool in self.tools.values()] if self.tools else catalog()
        )
        self.toolchain = toolchain or build_toolchain(versions=False, include_wordlists=True)
        attach = getattr(client, "attach_context", None)
        if callable(attach):
            # Context-aware backends (the built-in auto agent) plan from the
            # live scope, memory and inventory instead of the prompt alone.
            attach(memory=memory, scope=scope, target=target, toolchain=self.toolchain)

    # -- planning ----------------------------------------------------------
    def _assess(self, budget: BudgetState) -> TDAReport:
        return self.assessor.assess(
            TDAInput(
                iteration=max(budget.iterations - 1, 0),
                max_iterations=budget.max_iterations,
                evidence_confidence=self.memory.evidence_confidence(),
                evidence_count=len(self.memory.findings()),
                tokens_used=budget.tokens_used,
                context_window=self.context_window,
                historical_success=self.memory.success_rate(),
                open_nodes=len(self.tree.open_nodes()),
                failed_attempts=self._failed_attempts,
            )
        )

    def _prompt_context(
        self, node_phase: Phase, budget: BudgetState, tda: TDAReport
    ) -> PromptContext:
        return PromptContext(
            target=self.target,
            engagement=self.scope.engagement,
            phase=node_phase,
            step=budget.iterations,
            max_iterations=budget.max_iterations,
            tokens_left=budget.tokens_left,
            model=self.client.model,
            scope_block=self.scope.prompt_block(),
            memory_digest=self.memory.digest(),
            difficulty=tda,
            tree_digest=self.tree.digest(),
            skill_names=(
                self.skills
                if self.skills is not None
                else select_skills(
                    node_phase,
                    [node.skill for node in self.tree.selectable_nodes() if node.skill],
                    limit=self.skill_limit,
                )
            ),
            tools=self._tool_catalog,
            toolchain_summary=self.toolchain.summary_lines(),
            capabilities=[capability.value for capability in self.scope.capabilities],
            external_agents=[
                f"{name}: {'available' if info.get('available') else 'unavailable'} "
                f"(requires {', '.join(info.get('requires', [])) or 'nothing'})"
                for name, info in sorted(self.toolchain.external_agents.items())
            ],
        )

    # -- execution ---------------------------------------------------------
    def run(
        self,
        progress: Callable[[StepRecord], None] | None = None,
        *,
        step_start: Callable[[dict[str, Any]], None] | None = None,
    ) -> RunResult:
        """Run the reason-act loop until a stop condition is reached."""
        started = time.monotonic()
        # Deterministic backends (auto, replay) burn no tokens; only model
        # backends are token-budgeted.
        uses_tokens = bool(getattr(self.client, "uses_tokens", True))
        budget = BudgetState(
            max_iterations=self.config.max_iterations,
            max_tokens=self.config.max_tokens,
            max_seconds=self.config.max_seconds,
        )
        recorder = TraceRecorder(
            target=self.target,
            engagement=self.scope.engagement,
            model=self.client.model,
            backend=self.client.backend,
            scope_fingerprint=self.scope.fingerprint(),
            run_id=self.run_id,
        )
        stop_reason = "budget_exhausted:iterations"
        error: str | None = None
        set_deadline = getattr(self.client, "set_deadline", None)
        if callable(set_deadline):
            set_deadline(started + budget.max_seconds)
        last_result_payload: dict[str, Any] | None = None
        known_failures: list[str] = []

        for _ in range(budget.max_iterations):
            budget.seconds_used = round(time.monotonic() - started, 3)
            exhausted = budget.exhausted()
            if exhausted:
                stop_reason = f"budget_exhausted:{exhausted}"
                break
            budget.iterations += 1

            tda = self._assess(budget)
            self.tree.enforce_depth(tda.max_depth)
            if tda.level in {DifficultyLevel.HIGH, DifficultyLevel.CRITICAL}:
                self.tree.prune_low_value(tda)

            node = self.tree.select(tda)
            if node is None:
                budget.iterations -= 1
                stop_reason = "attack_tree_exhausted"
                break

            ctx = self._prompt_context(node.phase, budget, tda)
            try:
                system_prompt = build_system_prompt(ctx)
                step_prompt = build_step_prompt(
                    ctx,
                    node_id=node.id,
                    last_result=last_result_payload,
                    known_failures=known_failures[-5:],
                )
            except Exception as exc:
                stop_reason = "prompt_render_failed"
                error = f"prompt rendering failed: {exc}"
                break

            if uses_tokens:
                prompt_tokens = estimate_tokens(system_prompt) + estimate_tokens(step_prompt)
                if prompt_tokens > budget.tokens_left:
                    budget.iterations -= 1
                    stop_reason = "budget_exhausted:tokens"
                    break
                budget.tokens_used += prompt_tokens
            step_started = utcnow()
            t0 = time.monotonic()
            try:
                decision = self.root.act(system_prompt, step_prompt, step=budget.iterations)
            except PolicyViolation as exc:
                record = self._record_step(
                    recorder,
                    index=budget.iterations,
                    action="policy_violation",
                    phase=node.phase,
                    node=node.id,
                    tda=tda,
                    started_at=step_started,
                    started_monotonic=t0,
                    error=str(exc),
                )
                self.memory.append_step(
                    step=record.index,
                    phase=record.phase,
                    tool=record.action,
                    ok=False,
                    reason=record.error,
                )
                self._emit(progress, record)
                stop_reason = "policy_violation"
                error = str(exc)
                break
            except LLMError as exc:
                timed_out = time.monotonic() - started >= budget.max_seconds
                record = self._record_step(
                    recorder,
                    index=budget.iterations,
                    action="budget_exhausted" if timed_out else "inference_failed",
                    phase=node.phase,
                    node=node.id,
                    tda=tda,
                    started_at=step_started,
                    started_monotonic=t0,
                    error=str(exc),
                )
                self._emit(progress, record)
                stop_reason = "budget_exhausted:seconds" if timed_out else "inference_failed"
                error = None if timed_out else str(exc)
                self.memory.append_step(
                    step=record.index,
                    phase=record.phase,
                    tool=record.action,
                    ok=False,
                    reason=record.error,
                )
                break

            if uses_tokens:
                budget.tokens_used += estimate_tokens(decision.model_dump_json())
            budget.seconds_used = round(time.monotonic() - started, 3)
            exhausted = (
                "seconds"
                if budget.seconds_used >= budget.max_seconds
                else "tokens"
                if uses_tokens and budget.tokens_used >= budget.max_tokens
                else None
            )
            if exhausted is not None:
                record = self._record_step(
                    recorder,
                    index=budget.iterations,
                    action="budget_exhausted",
                    phase=node.phase,
                    node=node.id,
                    tda=tda,
                    started_at=step_started,
                    started_monotonic=t0,
                    reason=f"{exhausted} budget exhausted before tool execution",
                )
                self._persist_step(record, decision, ok=False, error=record.reason)
                self._emit(progress, record)
                stop_reason = f"budget_exhausted:{exhausted}"
                break

            if decision.tool == "terminate" or decision.done:
                record = self._record_step(
                    recorder,
                    index=budget.iterations,
                    action="terminate",
                    phase=node.phase,
                    node=node.id,
                    tda=tda,
                    started_at=step_started,
                    started_monotonic=t0,
                    reason=decision.reason,
                    thought=decision.thought,
                )
                self._persist_step(record, decision, ok=True, error=None)
                self._emit(progress, record)
                stop_reason = "agent_terminated"
                break

            try:
                request = DelegationRequest.model_validate(decision.args)
            except ValidationError as exc:
                self._failed_attempts += 1
                self.tree.apply_result(node.id, ok=False, findings=[], reason="invalid delegation")
                record = self._record_step(
                    recorder,
                    index=budget.iterations,
                    action="delegate",
                    phase=node.phase,
                    tool=decision.tool,
                    args=decision.args,
                    node=node.id,
                    tda=tda,
                    started_at=step_started,
                    started_monotonic=t0,
                    reason=decision.reason,
                    thought=decision.thought,
                    error=f"invalid delegation payload: {exc}",
                )
                self._persist_step(record, decision, ok=False, error=str(exc))
                self._emit(progress, record)
                known_failures.append(f"invalid delegation: {exc}")
                continue

            node_id = request.node if request.node and self.tree.has(request.node) else node.id
            if request.expand:
                self.tree.expand(node_id, request.expand, tda.max_depth)

            cached_failure = self.memory.negative_cache_hit(request.tool, request.args)
            if cached_failure and not self.config.dry_run:
                self._failed_attempts += 1
                record = self._record_step(
                    recorder,
                    index=budget.iterations,
                    action="delegate",
                    phase=node.phase,
                    tool=request.tool,
                    args=request.args,
                    node=node_id,
                    tda=tda,
                    started_at=step_started,
                    started_monotonic=t0,
                    reason=decision.reason,
                    thought=decision.thought,
                    error=f"negative cache: {cached_failure}",
                )
                self._persist_step(record, decision, ok=False, error=cached_failure)
                self._emit(progress, record)
                known_failures.append(f"{request.tool}: {cached_failure}")
                last_result_payload = {
                    "tool": request.tool,
                    "status": "skipped",
                    "observations": ["identical invocation already failed; not retried"],
                    "error": cached_failure,
                }
                continue

            worker = self._workers[request.agent]
            remaining = max(0.0, budget.max_seconds - (time.monotonic() - started))
            if remaining <= 0:
                stop_reason = "budget_exhausted:seconds"
                break
            if step_start is not None:
                step_start(
                    {
                        "tool": request.tool,
                        "purpose": request.reason or decision.reason,
                        "index": budget.iterations,
                        "total": budget.max_iterations,
                        "phase": node.phase.value,
                    }
                )
            if self.memory.consecutive_failures(request.tool, request.args) >= 2:
                result = ToolResult(
                    tool=request.tool,
                    status=ToolStatus.BLOCKED,
                    error="retry limit reached after two consecutive failures for these arguments",
                )
            else:
                result = worker.execute(request, dry_run=self.config.dry_run, timeout_s=remaining)
            ok = result.status in {ToolStatus.OK, ToolStatus.SKIPPED}

            self.memory.record_attempt(
                tool=result.tool,
                args=request.args,
                target=str(request.args.get("target", self.target)),
                ok=ok,
                error=result.error,
            )
            new_findings = [finding for finding in result.findings if self._accept(finding)]
            for finding in new_findings:
                self.memory.append_finding(finding)
            recorder.add_findings(new_findings)
            self.tree.apply_result(
                node_id, ok=ok, findings=new_findings, reason=result.error or None
            )
            if not ok:
                self._failed_attempts += 1
                known_failures.append(f"{result.tool}: {result.error}")

            record = self._record_step(
                recorder,
                index=budget.iterations,
                action="delegate",
                phase=node.phase,
                tool=result.tool,
                args=request.args,
                node=node_id,
                tda=tda,
                started_at=step_started,
                started_monotonic=t0,
                reason=decision.reason,
                thought=decision.thought,
                result=result,
                findings=new_findings,
                error=None if ok else result.error,
            )
            self._persist_step(record, decision, ok=ok, error=result.error)
            self._emit(progress, record)

            last_result_payload = {
                "tool": result.tool,
                "status": result.status.value,
                "exit_code": result.exit_code,
                "observations": result.observations[:5],
                "finding_titles": [finding.title for finding in new_findings[:5]],
                "error": result.error,
            }

            critical = [
                finding
                for finding in new_findings
                if finding.severity is Severity.CRITICAL and finding.verified
            ]
            if critical:
                stop_reason = "critical_finding_confirmed"
                break

        budget.seconds_used = round(time.monotonic() - started, 3)
        recorder.set_budget(budget)
        trace = recorder.finish(
            stop_reason=stop_reason,
            error=error,
            tree=self.tree.stats(),
            memory_stats=self.memory.stats(),
        )
        return RunResult(trace=trace, stop_reason=stop_reason, findings=recorder.findings)

    # -- helpers -----------------------------------------------------------
    def _accept(self, finding: Finding) -> bool:
        key = (finding.title, finding.endpoint)
        if key in self._seen_findings:
            return False
        self._seen_findings.add(key)
        return True

    def _record_step(
        self,
        recorder: TraceRecorder,
        *,
        index: int,
        action: str,
        phase: Phase,
        node: str | None,
        tda: TDAReport,
        started_at: Any,
        started_monotonic: float,
        tool: str | None = None,
        args: dict[str, Any] | None = None,
        reason: str | None = None,
        thought: str | None = None,
        result: ToolResult | None = None,
        findings: list[Finding] | None = None,
        error: str | None = None,
    ) -> StepRecord:
        record = StepRecord(
            index=index,
            action=action,
            phase=phase,
            tool=tool,
            args=args or {},
            reason=reason or "",
            thought=thought,
            node=node,
            tda=tda.as_context(),
            result=(
                {
                    "status": result.status.value,
                    "exit_code": result.exit_code,
                    "duration_ms": result.duration_ms,
                    "argv": result.argv,
                    "stdout_excerpt": result.stdout[:500],
                    "observations": result.observations[:10],
                    "error": result.error,
                    "finding_titles": [finding.title for finding in (findings or [])[:5]],
                    "top_severity": _top_severity(findings),
                }
                if result is not None
                else None
            ),
            finding_ids=[finding.id for finding in findings or []],
            started_at=started_at.isoformat(),
            duration_ms=int((time.monotonic() - started_monotonic) * 1000),
            error=error,
        )
        return recorder.add_step(record)

    def _persist_step(
        self,
        record: StepRecord,
        decision: Decision,
        *,
        ok: bool,
        error: str | None,
    ) -> None:
        self.memory.append_step(
            step=record.index,
            phase=record.phase,
            tool=record.tool or record.action,
            args=record.args,
            ok=ok,
            reason=record.reason,
            payload={
                "node": record.node,
                "tool": record.tool,
                "action": record.action,
                "finding_ids": record.finding_ids,
                "error": error,
                "decision_reason": decision.reason,
            },
        )

    @staticmethod
    def _emit(progress: Callable[[StepRecord], None] | None, record: StepRecord) -> None:
        if progress is not None:
            progress(record)


__all__ = [
    "WORKER_TOOL_ALLOWLIST",
    "DelegationRequest",
    "Orchestrator",
    "RootAgent",
    "RunResult",
    "WorkerAgent",
]
