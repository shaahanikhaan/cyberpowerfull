"""Root Agent orchestration loop.

Strict role separation is enforced in code, not in the prompt alone:

* :class:`RootAgent` can only emit ``delegate`` or ``terminate``. It has no
  executor, no subprocess handle, and no write access to memory.
* :class:`WorkerAgent` owns the typed tools, re-checks scope, and executes.
* :class:`Orchestrator` is the only component that mutates the attack tree,
  memory, and the trace, and it does so deterministically from tool results.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
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
from cyberpowerfull.errors import LLMError, PolicyViolation, ScopeViolation
from cyberpowerfull.memory.store import MemoryStore
from cyberpowerfull.models import (
    BudgetState,
    Decision,
    Finding,
    Phase,
    Severity,
    estimate_tokens,
    new_id,
    utcnow,
)
from cyberpowerfull.scope import Scope
from cyberpowerfull.skills import skill_names
from cyberpowerfull.tools.base import BaseTool, ToolResult, ToolStatus
from cyberpowerfull.tools.registry import catalog, get_tool
from cyberpowerfull.trace import StepRecord, Trace, TraceRecorder

#: Deterministic delegation allowlist: which worker may run which tool.
WORKER_TOOL_ALLOWLIST: dict[str, frozenset[str]] = {
    "recon": frozenset({"nmap", "httpx", "subfinder", "tcp_probe", "nikto"}),
    "scan": frozenset({"nmap", "nikto", "ffuf", "nuclei", "tcp_probe", "httpx"}),
    "validate": frozenset({"nuclei", "sqlmap", "dalfox", "ffuf", "httpx"}),
}


class DelegationRequest(BaseModel):
    """Validated payload of a ``delegate`` decision."""

    model_config = ConfigDict(extra="forbid")

    agent: Literal["recon", "scan", "validate"] = "recon"
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
        self.policy = policy or ToolPolicy()
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

    def execute(self, request: DelegationRequest, *, dry_run: bool = False) -> ToolResult:
        try:
            tool = self._resolve(request.tool)
        except PolicyViolation as exc:
            return ToolResult(tool=request.tool, status=ToolStatus.BLOCKED, error=str(exc))

        if tool.phase not in self.scope.allowed_phases:
            return ToolResult(
                tool=tool.name,
                status=ToolStatus.BLOCKED,
                error=f"phase {tool.phase.value!r} is not permitted by scope.json",
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
        except ScopeViolation as exc:
            return ToolResult(tool=tool.name, status=ToolStatus.BLOCKED, error=str(exc))

        return tool.run(request.args, dry_run=dry_run, policy=self.policy)


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
    ) -> None:
        self.scope = scope
        self.config = config
        self.client = client
        self.memory = memory
        self.target = target
        self.policy = policy or ToolPolicy()
        self.assessor = assessor or TaskDifficultyAssessor()
        self.context_window = context_window
        self.run_id = run_id or new_id("run-")
        self.skills = skills or skill_names()
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
            skill_names=self.skills,
            tools=self._tool_catalog,
        )

    # -- execution ---------------------------------------------------------
    def run(self, progress: Callable[[StepRecord], None] | None = None) -> RunResult:
        """Run the reason-act loop until a stop condition is reached."""
        started = time.monotonic()
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
        last_result_payload: dict[str, Any] | None = None
        known_failures: list[str] = []

        for _ in range(budget.max_iterations):
            budget.iterations += 1
            budget.seconds_used = round(time.monotonic() - started, 3)
            exhausted = budget.exhausted()
            if exhausted and exhausted != "iterations":
                stop_reason = f"budget_exhausted:{exhausted}"
                break

            tda = self._assess(budget)
            self.tree.enforce_depth(tda.max_depth)
            if tda.level in {DifficultyLevel.HIGH, DifficultyLevel.CRITICAL}:
                self.tree.prune_low_value(tda)

            node = self.tree.select(tda)
            if node is None:
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

            budget.tokens_used += estimate_tokens(system_prompt) + estimate_tokens(step_prompt)
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
                self._emit(progress, record)
                stop_reason = "policy_violation"
                error = str(exc)
                break
            except LLMError as exc:
                record = self._record_step(
                    recorder,
                    index=budget.iterations,
                    action="inference_failed",
                    phase=node.phase,
                    node=node.id,
                    tda=tda,
                    started_at=step_started,
                    started_monotonic=t0,
                    error=str(exc),
                )
                self._emit(progress, record)
                stop_reason = "inference_failed"
                error = str(exc)
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

            worker = self._workers[request.agent]
            result = worker.execute(request, dry_run=self.config.dry_run)
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
