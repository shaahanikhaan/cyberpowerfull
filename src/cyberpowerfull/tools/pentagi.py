"""PentAGI integration: create and follow a real flow through the PentAGI API.

Verified against vxcontrol/pentagi v2.2.0 (``backend/pkg/graph/schema.graphqls``,
``backend/pkg/server/router.go``, ``backend/pkg/server/services/flows.go``,
``backend/pkg/server/models/flows.go``, ``backend/pkg/config/config.go``):

* GraphQL lives at ``POST /api/v1/graphql`` and takes
  ``createFlow(modelProvider, input)``; flow state is ``flow(flowId:)`` (the
  argument is ``flowId``, not ``id``) and a flow has **no** ``report`` field —
  results come from ``tasks(flowId:)`` (each task has ``title``/``status``/``result``).
* Flow statuses are exactly ``created | running | waiting | finished | failed``.
  ``waiting`` means the flow needs input in the PentAGI UI — polling it forever
  is wrong, so it stops with an actionable message.
* REST fallback routes (token tier, ``Authorization: Bearer <API token>``):
  ``POST /api/v1/flows/`` with ``{"input", "provider"}`` (the key is
  ``provider``, not ``modelProvider``), ``GET /api/v1/flows/{id}``,
  ``GET /api/v1/flows/{id}/tasks/``. Success envelopes look like
  ``{"status": "success", "data": ...}``. There is no ``/report`` route.
* The server listens on ``SERVER_PORT`` (default **8080**) with TLS **off** by
  default, and API-token auth needs a non-default server auth salt.

This native tool (no binary, no shell) creates a flow whose input is restricted
to the engagement scope, polls it until it finishes/fails/waits, and returns
the task results it can retrieve. GraphQL is tried first, REST second, and the
exact server error is surfaced instead of being masked.

Environment:
    PENTAGI_URL          base URL, e.g. ``http://127.0.0.1:8080``
    PENTAGI_API_TOKEN    Bearer API token (created in the PentAGI UI)
    PENTAGI_TLS_VERIFY   ``false`` to accept a self-signed certificate
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from pydantic import Field, field_validator

from cyberpowerfull.models import Capability, Finding, Phase
from cyberpowerfull.tools.base import BaseTool, ToolStatus, UrlInput, _Exec, truncate
from cyberpowerfull.tools.extract import extract_report_findings, findings_from_json_records

_SUCCESS_STATUSES = {"finished"}
_FAILED_STATUSES = {"failed"}
_WAITING_STATUSES = {"waiting"}

_CREATE_FLOW = """
mutation CreateFlow($provider: String!, $input: String!) {
  createFlow(modelProvider: $provider, input: $input) { id title status }
}
""".strip()
_FLOW_STATUS = """
query FlowStatus($id: ID!) {
  flow(flowId: $id) { id title status }
}
""".strip()
_FLOW_TASKS = """
query FlowTasks($id: ID!) {
  tasks(flowId: $id) { id title status result }
}
""".strip()

_REST_CREATE = "/api/v1/flows/"
_REST_FLOW = "/api/v1/flows/{flow_id}"
_REST_TASKS = "/api/v1/flows/{flow_id}/tasks/"


class PentagiArgs(UrlInput):
    """Validated PentAGI invocation arguments."""

    provider: str = Field(default="openai", min_length=1, max_length=64)
    max_wait_s: int = Field(default=900, ge=5, le=7200)
    poll_s: int = Field(default=5, ge=1, le=60)
    instruction: str | None = Field(default=None, max_length=600)
    report_timeout_s: int = Field(default=60, ge=5, le=300)

    @field_validator("provider")
    @classmethod
    def _check_provider(cls, value: str) -> str:
        if not value.replace("_", "").replace("-", "").isalnum():
            raise ValueError("provider must be a PentAGI model provider name")
        return value

    @field_validator("instruction")
    @classmethod
    def _single_line(cls, value: str | None) -> str | None:
        return " ".join(value.split())[:600] if value else None


class PentagiTool(BaseTool):
    name = "pentagi"
    phase = Phase.VALIDATION
    skill = "external_validation"
    binary = None
    external = True
    required_capability = Capability.EXTERNAL_AGENTS
    description = (
        "Delegates a scoped objective to a running PentAGI instance through its "
        "REST/GraphQL API, waits for the flow to finish, and parses the task results. "
        "Requires the 'external_agents' capability plus PENTAGI_URL / PENTAGI_API_TOKEN."
    )
    input_model = PentagiArgs

    def build_argv(self, args: PentagiArgs, out_file: str | None = None) -> list[str]:
        return ["pentagi", "--target", args.target, "--provider", args.provider]

    # -- transport ---------------------------------------------------------
    def _base_url(self) -> str | None:
        raw = os.environ.get("PENTAGI_URL") or os.environ.get("PENTAGI_BASE_URL")
        if not raw:
            return None
        raw = raw.strip().rstrip("/")
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return raw

    def _ssl_context(self) -> ssl.SSLContext | None:
        parsed = urlparse(self._base_url() or "")
        if parsed.scheme != "https":
            return None
        verify = os.environ.get("PENTAGI_TLS_VERIFY", "true").strip().lower()
        if verify in {"0", "false", "no", "off"}:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        return ssl.create_default_context()

    def _http(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        timeout: int,
    ) -> tuple[int, str]:
        """Issue one authenticated JSON request. Returns ``(status, body)``."""
        base = self._base_url()
        if base is None:  # pragma: no cover - guarded by _execute
            raise RuntimeError("PENTAGI_URL is not configured")
        url = f"{base}{path}"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Accept", "application/json")
        request.add_header("Content-Type", "application/json")
        token = os.environ.get("PENTAGI_API_TOKEN")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(
                request, timeout=timeout, context=self._ssl_context()
            ) as response:
                return int(response.status), response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
            return int(exc.code), detail
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return 0, f"transport error: {exc}"

    def _gql(self, query: str, variables: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        status, body = self._http(
            "POST", "/api/v1/graphql", {"query": query, "variables": variables}, timeout=timeout
        )
        if status != 200:
            raise _http_error("graphql", status, body)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise PentagiError(f"graphql returned non-JSON: {truncate(body, 300)}") from exc
        errors = payload.get("errors")
        if errors:
            raise PentagiError(f"graphql error: {truncate(json.dumps(errors), 400)}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise PentagiError("graphql response has no data object")
        return data

    # -- flow lifecycle ----------------------------------------------------
    def _create_flow(self, args: PentagiArgs) -> dict[str, Any]:
        objective = (
            f"Perform an authorized penetration test of {args.target}. Work strictly "
            "inside the engagement scope. No persistence, lateral movement, or data "
            "extraction."
        )
        if args.instruction:
            objective += f" {args.instruction}"
        errors: list[str] = []
        try:
            data = self._gql(
                _CREATE_FLOW,
                {"provider": args.provider, "input": objective},
                timeout=args.report_timeout_s,
            )
            flow = data.get("createFlow")
            if isinstance(flow, dict) and flow.get("id"):
                return flow
            errors.append("graphql createFlow returned no id")
        except PentagiError as exc:
            errors.append(str(exc))
        # REST fallback: POST /api/v1/flows/ with {"input", "provider"}.
        status, body = self._http(
            "POST",
            _REST_CREATE,
            {"input": objective, "provider": args.provider},
            timeout=args.report_timeout_s,
        )
        if status in {200, 201}:
            data = _envelope_data(body)
            if isinstance(data, dict) and data.get("id"):
                return data
            errors.append("REST create returned no flow id")
        else:
            errors.append(str(_http_error("REST create", status, body)))
        raise PentagiError("could not create a PentAGI flow; " + " | ".join(errors))

    def _flow_state(self, args: PentagiArgs, flow_id: str) -> dict[str, Any]:
        try:
            data = self._gql(_FLOW_STATUS, {"id": flow_id}, timeout=args.report_timeout_s)
            flow = data.get("flow")
            if isinstance(flow, dict):
                return flow
        except PentagiError:
            pass
        status, body = self._http(
            "GET", _REST_FLOW.format(flow_id=flow_id), None, timeout=args.report_timeout_s
        )
        if status != 200:
            raise _http_error("flow status", status, body)
        data = _envelope_data(body)
        if isinstance(data, dict):
            return data
        raise PentagiError(f"flow status payload was not an object: {truncate(body, 200)}")

    def _await(self, args: PentagiArgs, flow_id: str) -> tuple[dict[str, Any], str]:
        """Poll until the flow finishes, fails, waits, or the budget runs out."""
        deadline = time.monotonic() + args.max_wait_s
        state: dict[str, Any] = {}
        while True:
            state = self._flow_state(args, flow_id)
            status = str(state.get("status") or "").lower()
            if status in _SUCCESS_STATUSES:
                return state, "finished"
            if status in _FAILED_STATUSES:
                return state, "failed"
            if status in _WAITING_STATUSES:
                return state, "waiting"
            if time.monotonic() >= deadline:
                return state, "timeout"
            time.sleep(min(args.poll_s, max(deadline - time.monotonic(), 0.1)))

    def _results(self, args: PentagiArgs, flow_id: str) -> str:
        """Task results via GraphQL, falling back to REST. Never raises."""
        try:
            data = self._gql(_FLOW_TASKS, {"id": flow_id}, timeout=args.report_timeout_s)
            sections = _task_sections(data.get("tasks"))
            if sections:
                return "\n\n".join(sections)
        except PentagiError:
            pass
        status, body = self._http(
            "GET", _REST_TASKS.format(flow_id=flow_id), None, timeout=args.report_timeout_s
        )
        if status == 200:
            sections = _task_sections(_envelope_data(body))
            if sections:
                return "\n\n".join(sections)
        return ""

    def _execute(self, args: PentagiArgs, argv: list[str], policy: Any) -> _Exec:
        if self._base_url() is None:
            return _Exec(
                status=ToolStatus.MISSING,
                error="PENTAGI_URL is not set (e.g. http://127.0.0.1:8080)",
            )
        try:
            flow = self._create_flow(args)
            flow_id = str(flow.get("id"))
            state, outcome = self._await(args, flow_id)
            report = self._results(args, flow_id) or json.dumps(state, indent=1, default=str)
        except PentagiError as exc:
            return _Exec(status=ToolStatus.ERROR, error=str(exc))
        except Exception as exc:  # pragma: no cover - defensive boundary
            return _Exec(status=ToolStatus.ERROR, error=f"pentagi integration failed: {exc}")
        header = f"pentagi flow {flow_id}: {outcome}"
        output = truncate(f"{header}\n\n{report}", policy.max_output_bytes)
        if outcome == "finished":
            return _Exec(stdout=output, stderr="", exit_code=0, status=ToolStatus.OK)
        if outcome == "waiting":
            return _Exec(
                stdout=output,
                stderr="",
                exit_code=None,
                status=ToolStatus.ERROR,
                error=(
                    f"flow {flow_id} is waiting for user input: answer it in the PentAGI "
                    "UI, then re-run (tasks completed so far are parsed above)"
                ),
            )
        if outcome == "failed":
            return _Exec(
                stdout=output,
                stderr="",
                exit_code=None,
                status=ToolStatus.ERROR,
                error=f"flow {flow_id} failed in PentAGI (partial results parsed above)",
            )
        return _Exec(
            stdout=output,
            stderr="",
            exit_code=None,
            status=ToolStatus.TIMEOUT,
            error=f"flow {flow_id} did not finish within {args.max_wait_s}s",
        )

    # -- parsing -----------------------------------------------------------
    def parse(self, args: PentagiArgs, output: str, out_file: str | None = None) -> list[Finding]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, list):
            # A structured report wins: prose extraction over JSON would turn
            # field names into titles.
            return findings_from_json_records(
                payload,
                tool=self.name,
                target=args.target,
                skill=self.skill,
                phase=self.phase,
            )
        return extract_report_findings(
            output, tool=self.name, target=args.target, skill=self.skill, phase=self.phase
        )

    def observations(self, args: PentagiArgs, output: str) -> list[str]:
        first_line = output.splitlines()[0] if output.strip() else "no output"
        return [
            f"pentagi provider={args.provider} {truncate(first_line, 120)} "
            f"(flow results are produced by the PentAGI instance)"
        ]


def _envelope_data(body: str) -> Any:
    """Unwrap a PentAGI REST envelope (``{"status", "data"}``)."""
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        return payload.get("data")
    return None


def _task_sections(tasks: Any) -> list[str]:
    sections: list[str] = []
    if not isinstance(tasks, list):
        return sections
    for task in tasks:
        if not isinstance(task, dict):
            continue
        title = str(task.get("title") or "task").strip()
        status = str(task.get("status") or "unknown").strip()
        result = str(task.get("result") or "").strip()
        sections.append(f"### {title} [{status}]\n{result}".rstrip())
    return sections


def _http_error(where: str, status: int, body: str) -> PentagiError:
    if status == 401:
        return PentagiError(
            f"{where}: PentAGI rejected the API token (HTTP 401). Create a token in "
            "the PentAGI UI and set PENTAGI_API_TOKEN (token auth also needs a "
            "non-default server auth salt)."
        )
    if status == 0:
        return PentagiError(f"{where}: {truncate(body, 300)}")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    detail = body
    if isinstance(payload, dict):
        detail = str(payload.get("message") or payload.get("error") or body)
    return PentagiError(f"{where}: HTTP {status}: {truncate(detail, 300)}")


class PentagiError(RuntimeError):
    """Raised when the PentAGI API cannot complete a requested operation."""


__all__ = ["PentagiArgs", "PentagiError", "PentagiTool"]
