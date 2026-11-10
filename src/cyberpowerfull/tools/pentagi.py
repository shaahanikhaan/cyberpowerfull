"""PentAGI integration: create and follow a real flow through the PentAGI API.

PentAGI (https://github.com/vxcontrol/pentagi) exposes a REST + GraphQL API on
``https://localhost:8443``. This native tool (no binary, no shell) authenticates
with ``PENTAGI_API_TOKEN``, creates a flow whose input is restricted to the
engagement scope, polls the flow until it reaches a terminal status, and returns
the report body it can retrieve. Both the GraphQL mutation and the REST
fallback are attempted, and the exact error from the server is surfaced instead
of being masked.

Environment:
    PENTAGI_URL          base URL, e.g. ``https://127.0.0.1:8443``
    PENTAGI_API_TOKEN    Bearer token
    PENTAGI_TLS_VERIFY   ``false`` to accept the self-signed default certificate
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

_TERMINAL = {
    "finished",
    "completed",
    "complete",
    "done",
    "success",
    "succeeded",
    "failed",
    "failure",
    "error",
    "cancelled",
    "canceled",
    "stopped",
}
_CREATE_FLOW = """
mutation CreateFlow($provider: String!, $input: String!) {
  createFlow(modelProvider: $provider, input: $input) { id title status }
}
""".strip()
_FLOW_STATUS = """
query FlowStatus($id: ID!) {
  flow(id: $id) { id title status }
}
""".strip()
_FLOW_REPORT = """
query FlowReport($id: ID!) {
  flow(id: $id) { id title status report }
}
""".strip()


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
        "REST/GraphQL API, waits for the flow to finish, and parses the report. "
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
            raise PentagiError(f"graphql HTTP {status}: {truncate(body, 300)}")
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
            flow = data.get("createFlow") or data.get("createFlowSimple")
            if isinstance(flow, dict) and flow.get("id"):
                return flow
            errors.append("graphql createFlow returned no id")
        except PentagiError as exc:
            errors.append(str(exc))
        # REST fallback (documented as /api/v1/flows)
        status, body = self._http(
            "POST",
            "/api/v1/flows",
            {"input": objective, "modelProvider": args.provider},
            timeout=args.report_timeout_s,
        )
        if status in {200, 201}:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}
            flow = payload.get("flow") if isinstance(payload, dict) else None
            if isinstance(flow, dict) and flow.get("id"):
                return flow
            if isinstance(payload, dict) and payload.get("id"):
                return payload
            errors.append("REST create returned no flow id")
        else:
            errors.append(f"REST create HTTP {status}: {truncate(body, 200)}")
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
            "GET", f"/api/v1/flows/{flow_id}", None, timeout=args.report_timeout_s
        )
        if status != 200:
            raise PentagiError(f"flow status HTTP {status}: {truncate(body, 200)}")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise PentagiError(f"flow status was not JSON: {truncate(body, 200)}") from exc
        if isinstance(payload, dict):
            return payload.get("flow") if isinstance(payload.get("flow"), dict) else payload
        raise PentagiError("flow status payload was not an object")

    def _await(self, args: PentagiArgs, flow_id: str) -> tuple[dict[str, Any], bool]:
        deadline = time.monotonic() + args.max_wait_s
        state: dict[str, Any] = {}
        while True:
            state = self._flow_state(args, flow_id)
            status = str(state.get("status") or "").lower()
            if status in _TERMINAL:
                return state, status in {
                    "finished",
                    "completed",
                    "complete",
                    "done",
                    "success",
                    "succeeded",
                }
            if time.monotonic() >= deadline:
                return state, False
            time.sleep(min(args.poll_s, max(deadline - time.monotonic(), 0.1)))

    def _report(self, args: PentagiArgs, flow_id: str, state: dict[str, Any]) -> str:
        for key in ("report", "result", "resultText", "output"):
            value = state.get(key)
            if isinstance(value, str) and value.strip():
                return value
        try:
            data = self._gql(_FLOW_REPORT, {"id": flow_id}, timeout=args.report_timeout_s)
            flow = data.get("flow") or {}
            if isinstance(flow, dict):
                for key in ("report", "result"):
                    value = flow.get(key)
                    if isinstance(value, str) and value.strip():
                        return value
        except PentagiError:
            pass
        status, body = self._http(
            "GET", f"/api/v1/flows/{flow_id}/report", None, timeout=args.report_timeout_s
        )
        if status == 200 and body.strip():
            return body
        return json.dumps(state, indent=1, default=str)

    def _execute(self, args: PentagiArgs, argv: list[str], policy: Any) -> _Exec:
        if self._base_url() is None:
            return _Exec(
                status=ToolStatus.MISSING,
                error="PENTAGI_URL is not set (e.g. https://127.0.0.1:8443)",
            )
        try:
            flow = self._create_flow(args)
            flow_id = str(flow.get("id"))
            state, succeeded = self._await(args, flow_id)
            report = self._report(args, flow_id, state)
        except PentagiError as exc:
            return _Exec(status=ToolStatus.ERROR, error=str(exc))
        except Exception as exc:  # pragma: no cover - defensive boundary
            return _Exec(status=ToolStatus.ERROR, error=f"pentagi integration failed: {exc}")
        status = ToolStatus.OK if succeeded else ToolStatus.TIMEOUT
        error = None if succeeded else f"flow {flow_id} did not finish within {args.max_wait_s}s"
        return _Exec(
            stdout=truncate(report, policy.max_output_bytes),
            stderr="",
            exit_code=0 if succeeded else None,
            status=status,
            error=error,
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
        return [
            f"pentagi provider={args.provider} report_bytes={len(output)} "
            f"(flow results are produced by the PentAGI instance)"
        ]


class PentagiError(RuntimeError):
    """Raised when the PentAGI API cannot complete a requested operation."""


__all__ = ["PentagiArgs", "PentagiError", "PentagiTool"]
