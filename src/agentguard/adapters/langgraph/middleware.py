"""LangGraph adapter (section 11.4): a middleware that sends every tool call through the Guard.

It contains no policy. Deleting it and wrapping the same tools by hand (docs/sdk.md) must give
the same decisions; tests/adapters/test_langgraph.py checks exactly that (scenario S36).

Approvals use LangGraph's `interrupt()`: the run pauses, your application shows the request,
and resumes with `Command(resume=...)`. A checkpointer and a `thread_id` are required for
`interrupt()` to work; the thread id is also the AgentGuard run id, so the data-flow session
survives the pause.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain.agents.middleware.types import ToolCallRequest
from langchain_core.messages import ToolMessage
from langgraph.errors import GraphBubbleUp
from langgraph.types import Command, interrupt

from agentguard.core.lock import LockFile, ToolLabels, approve, update_lock
from agentguard.core.models import Reason
from agentguard.core.policy import LOCAL_SERVER
from agentguard.sdk import ApprovalRequest, Approved, CallBlocked, Denied, Guard, Modified

APPROVE_WORDS = {"approve", "approved", "yes", "true"}
DENY_WORDS = {"deny", "denied", "no", "false", "reject"}


def tool_definition_of(tool: Any) -> dict[str, Any]:
    """The definition of a LangChain tool, from its name, description and argument schema."""
    schema = tool.get_input_schema().model_json_schema()
    return {"name": tool.name, "description": tool.description or "", "inputSchema": schema}


def definitions_of(tools: list[Any]) -> list[dict[str, Any]]:
    """Definitions for `agentguard lock --from-python your_module:TOOL_DEFINITIONS`."""
    return [tool_definition_of(tool) for tool in tools]


def build_lock(tools: list[Any], declarations: dict[str, dict[str, Any]] | None = None) -> LockFile:
    """An approved lockfile for LangChain tools, for tests and quick starts. In real use run
    `agentguard lock --from-python` and review the result instead."""
    from agentguard.core.lock import Egress

    lock = update_lock(LockFile(), {LOCAL_SERVER: definitions_of(tools)}, {})
    for name, declared in (declarations or {}).items():
        locked = lock.servers[LOCAL_SERVER].tools[name]
        locked.labels = ToolLabels(produces=list(declared.get("produces", [])))
        egress = declared.get("egress")
        locked.egress = Egress.model_validate(egress) if egress else None
    approve(lock)
    return lock


def interrupt_for_approval(request: ApprovalRequest) -> Approved | Denied | Modified:
    """Approval handler that pauses the graph with `interrupt()`.

    Resume with `Command(resume=...)` where the value is one of: `"approve"`, `"deny"`,
    `True` / `False`, or `{"decision": "approve" | "deny" | "modify", "args": {...},
    "decided_by": "alice"}`. Anything else is a denial."""
    answer = interrupt(
        {
            "agentguard": "approval_required",
            "tool": request.tool_id,
            "arguments": request.summary,  # redacted: length, digest, destination host
            "rules": request.rule_ids,
            "reason_code": request.reason_code,
            "evidence": request.evidence,
        }
    )
    return decision_from_resume(answer)


def decision_from_resume(answer: Any) -> Approved | Denied | Modified:
    decided_by = "interrupt"
    if isinstance(answer, dict):
        decided_by = str(answer.get("decided_by", decided_by))
        decision = str(answer.get("decision", "")).lower()
        if decision == "modify" and isinstance(answer.get("args"), dict):
            return Modified(answer["args"], decided_by=decided_by)
        answer = decision
    if answer is True or str(answer).lower() in APPROVE_WORDS:
        return Approved(decided_by=decided_by)
    return Denied(decided_by=decided_by)


class AgentGuardMiddleware(AgentMiddleware):  # type: ignore[misc]
    """Pass this to `create_agent(..., middleware=[guard_middleware(guard)])`."""

    def __init__(
        self,
        guard: Guard,
        principal: str | Callable[[ToolCallRequest], str] | None = None,
        on_approval: Callable[[ApprovalRequest], Any] | None = interrupt_for_approval,
        grants: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        super().__init__()
        self._guard = guard
        self._principal = principal
        self._on_approval = on_approval
        self._grants = grants
        guard.add_passthrough(GraphBubbleUp)  # interrupts must pass through the approval step

    # --- helpers ----------------------------------------------------------------------------

    def _principal_for(self, request: ToolCallRequest) -> str | None:
        return self._principal(request) if callable(self._principal) else self._principal

    @staticmethod
    def _run_id(request: ToolCallRequest) -> str | None:
        configurable = (getattr(request.runtime, "config", None) or {}).get("configurable", {})
        thread_id = configurable.get("thread_id")
        return str(thread_id) if thread_id is not None else None

    def _prepare(self, request: ToolCallRequest) -> tuple[str, dict[str, Any]] | ToolMessage:
        """Register the tool (checked against the lockfile) and return (name, arguments).

        A call for a tool that is not registered with the agent is refused here, not passed on:
        a middleware further in could otherwise serve it unchecked."""
        if request.tool is None:
            self._guard.record_event("call.rejected", tool=request.tool_call["name"], detail="unknown tool")
            return self._blocked_message(
                request, CallBlocked(request.tool_call["name"], Reason.TOOL_UNAPPROVED)
            )
        self._guard.register_local_tool(tool_definition_of(request.tool))
        return request.tool_call["name"], dict(request.tool_call["args"])

    @staticmethod
    def _blocked_message(request: ToolCallRequest, blocked: CallBlocked) -> ToolMessage:
        return ToolMessage(
            content=blocked.message,
            name=request.tool_call["name"],
            tool_call_id=request.tool_call["id"],
            status="error",
        )

    @staticmethod
    def _with_arguments(request: ToolCallRequest, arguments: dict[str, Any]) -> ToolCallRequest:
        return request.override(tool_call={**request.tool_call, "args": arguments})

    # --- the hooks --------------------------------------------------------------------------

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        prepared = self._prepare(request)
        if isinstance(prepared, ToolMessage):
            return prepared
        name, arguments = prepared
        try:
            with self._guard.task(
                principal=self._principal_for(request),
                run_id=self._run_id(request),
                grants=self._grants,
                on_approval=self._on_approval,
            ):
                return self._guard.guarded_call(
                    name, arguments, lambda final: handler(self._with_arguments(request, final))
                )
        except CallBlocked as blocked:
            return self._blocked_message(request, blocked)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        prepared = self._prepare(request)
        if isinstance(prepared, ToolMessage):
            return prepared
        name, arguments = prepared
        try:
            async with self._guard.task(
                principal=self._principal_for(request),
                run_id=self._run_id(request),
                grants=self._grants,
                on_approval=self._on_approval,
            ):
                return await self._guard.aguarded_call(
                    name, arguments, lambda final: handler(self._with_arguments(request, final))
                )
        except CallBlocked as blocked:
            return self._blocked_message(request, blocked)


def guard_middleware(
    guard: Guard,
    principal: str | Callable[[ToolCallRequest], str] | None = None,
    on_approval: Callable[[ApprovalRequest], Any] | None = interrupt_for_approval,
    grants: dict[str, dict[str, Any]] | None = None,
) -> AgentGuardMiddleware:
    """Build the middleware. Pass `on_approval=None` for the default flow (the tool answers
    "approval required" and a person runs `agentguard approve`)."""
    return AgentGuardMiddleware(guard, principal, on_approval, grants)
