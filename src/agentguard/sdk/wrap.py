"""Running a Python call through the Guard (section 11.1).

Two ways in, one decision path:
  * `make_wrapper` wraps a function so every call is checked. It keeps the function's name,
    signature and docstring (functools.wraps), because agent frameworks build tool schemas from them.
  * `Guard.guarded_call` checks a call that a framework already describes as (tool name, arguments),
    for runtimes that dispatch tools by name (the AgentDojo adapter uses this).

Per call: decide, optionally ask a human, run, record the result. A blocked call raises
CallBlocked and nothing runs.
"""

from __future__ import annotations

import functools
import inspect
import secrets
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from agentguard.core.audit import redact_args
from agentguard.core.guard import describe_evidence
from agentguard.core.models import Decision, Reason, ToolCall, Verdict
from agentguard.sdk.approval import ApprovalHandler, ApprovalRequest, Approved, Denied, Modified
from agentguard.sdk.errors import ApprovalRequired, CallBlocked
from agentguard.sdk.local_tools import (
    bind_arguments,
    local_tool_id,
    policy_arguments,
    to_jsonable,
    tool_definition,
)
from agentguard.sdk.results import result_to_texts
from agentguard.sdk.task import TaskContext, current_task

if TYPE_CHECKING:
    from agentguard.sdk.runtime import Guard

MAX_MODIFICATIONS = 1


def make_wrapper(
    runtime: Guard, fn: Callable[..., Any], name: str, exclude: tuple[str, ...]
) -> Callable[..., Any]:
    definition = tool_definition(fn, name, exclude)
    tool_id = local_tool_id(name)
    runtime.register_local_tool(definition)

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            call = _FunctionCall(runtime, tool_id, fn, exclude, args, kwargs)
            await call.authorize_async()
            return await call.run_async()

        wrapper: Callable[..., Any] = async_wrapper
    else:

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            call = _FunctionCall(runtime, tool_id, fn, exclude, args, kwargs)
            call.authorize()
            return call.run()

        wrapper = sync_wrapper
    wrapper.__agentguard_definition__ = definition  # type: ignore[attr-defined]
    wrapper.__agentguard_tool_id__ = tool_id  # type: ignore[attr-defined]
    return wrapper


class _Call:
    """One call: decide, maybe ask, record. Subclasses say how arguments are changed and run."""

    def __init__(self, runtime: Guard, tool_id: str, call_args: dict[str, Any]) -> None:
        self.runtime = runtime
        self.tool_id = tool_id
        self.call_args = call_args
        self.task = self._require_task()
        self.call: ToolCall | None = None
        self.approval_id = ""

    def _require_task(self) -> TaskContext:
        task = current_task()
        if task is None:  # no principal means no basis for authorization
            self.runtime.record_event("call.rejected", tool=self.tool_id, detail="outside guard.task()")
            raise CallBlocked(self.tool_id, Reason.NO_TASK, "Call outside guard.task(): no principal.")
        return task

    def _modified_arguments(self, outcome: Modified) -> dict[str, Any] | None:
        """Apply new argument values and return the new policy arguments; None if not possible."""
        raise NotImplementedError

    # --- deciding ---------------------------------------------------------------------------

    def authorize(self) -> None:
        for attempt in range(MAX_MODIFICATIONS + 1):
            verdict, self.call = self.runtime.decide(self.task, self.tool_id, self.call_args)
            handler = self._handler_needed(verdict)
            if handler is None:
                return
            request = self._request_for(verdict, attempt)
            outcome = self._ask_sync(handler, request)
            if not self._apply(outcome):
                return

    async def authorize_async(self) -> None:
        for attempt in range(MAX_MODIFICATIONS + 1):
            verdict, self.call = self.runtime.decide(self.task, self.tool_id, self.call_args)
            handler = self._handler_needed(verdict)
            if handler is None:
                return
            request = self._request_for(verdict, attempt)
            outcome = await self._ask_async(handler, request)
            if not self._apply(outcome):
                return

    def _handler_needed(self, verdict: Verdict) -> ApprovalHandler | None:
        """None if the call may run now; the handler if a human must decide; otherwise raise."""
        if verdict.decision in (Decision.ALLOW, Decision.WARN):
            return None
        if verdict.decision is Decision.DENY:
            raise CallBlocked(self.tool_id, verdict.reason_code)
        handler = self.task.on_approval
        if handler is None:  # default flow: register, tell the agent, retry later
            raise ApprovalRequired(self.tool_id, verdict.reason_code, verdict.approval_id)
        return handler

    def _request_for(self, verdict: Verdict, attempt: int) -> ApprovalRequest:
        if attempt >= MAX_MODIFICATIONS:  # a modified call needed approval again
            raise CallBlocked(self.tool_id, Reason.APPROVAL_DENIED)
        locked = self.runtime.lock.find("local", self.tool_id.partition("__")[2])
        self.approval_id = "ap_" + secrets.token_hex(4)
        self.runtime.record_event(
            "approval.requested",
            self.task.session,
            approval_id=self.approval_id,
            tool=self.tool_id,
            rule_ids=verdict.rule_ids,
        )
        return ApprovalRequest(
            tool_id=self.tool_id,
            principal=self.task.session.principal,
            run_id=self.task.run_id,
            summary=redact_args(self.call_args, locked.egress if locked else None),
            rule_ids=verdict.rule_ids,
            reason_code=verdict.reason_code,
            evidence=[describe_evidence(item) for item in verdict.evidence],
        )

    def _ask_sync(self, handler: ApprovalHandler, request: ApprovalRequest) -> Any:
        try:
            outcome = handler(request)
        except self.runtime.passthrough:
            raise
        except Exception:
            return None
        if inspect.isawaitable(outcome):  # an async handler on a sync tool cannot be awaited here
            getattr(outcome, "close", lambda: None)()
            return None
        return outcome

    async def _ask_async(self, handler: ApprovalHandler, request: ApprovalRequest) -> Any:
        try:
            outcome = handler(request)
            if inspect.isawaitable(outcome):
                outcome = await outcome
        except self.runtime.passthrough:
            raise
        except Exception:
            return None
        return outcome

    def _apply(self, outcome: Any) -> bool:
        """Act on the handler's answer. Returns True if the call must be decided again."""
        if isinstance(outcome, Approved):
            self._audit_outcome("approved", outcome.decided_by)
            return False
        if isinstance(outcome, Modified):
            changed = self._modified_arguments(outcome)
            if changed is not None:
                self._audit_outcome("modified", outcome.decided_by)
                self.call_args = changed
                return True
        decided_by = outcome.decided_by if isinstance(outcome, Denied | Modified) else "handler-error"
        self._audit_outcome("denied", decided_by)
        raise CallBlocked(self.tool_id, Reason.APPROVAL_DENIED)

    def _audit_outcome(self, outcome: str, decided_by: str) -> None:
        self.runtime.record_event(
            "approval.decided",
            self.task.session,
            approval_id=self.approval_id,
            decided_by=decided_by,
            outcome=outcome,
            tool=self.tool_id,
        )

    # --- recording --------------------------------------------------------------------------

    def record(self, result: Any, is_error: bool = False) -> None:
        assert self.call is not None
        texts, lossy = ([], False) if is_error else result_to_texts(result)
        self.runtime.record_result(self.task, self.call, texts, is_error)
        if lossy:
            self.runtime.record_event("result.unserializable", self.task.session, tool=self.tool_id)


class _FunctionCall(_Call):
    """A call of a wrapped function."""

    def __init__(
        self,
        runtime: Guard,
        tool_id: str,
        fn: Callable[..., Any],
        exclude: tuple[str, ...],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> None:
        self.fn = fn
        self.exclude = exclude
        self.bound = bind_arguments(fn, args, kwargs)
        super().__init__(runtime, tool_id, policy_arguments(self.bound, exclude))

    def _modified_arguments(self, outcome: Modified) -> dict[str, Any] | None:
        parameters = self.bound.signature.parameters
        plain = {
            name
            for name, parameter in parameters.items()
            if parameter.kind not in (parameter.VAR_KEYWORD, parameter.VAR_POSITIONAL)
            and name not in self.exclude
        }
        if not set(outcome.args) <= plain:
            return None
        self.bound.arguments.update(outcome.args)
        return policy_arguments(self.bound, self.exclude)

    def run(self) -> Any:
        try:
            result = self.fn(*self.bound.args, **self.bound.kwargs)
        except Exception:
            self.record(None, is_error=True)
            raise
        self.record(result)
        return result

    async def run_async(self) -> Any:
        try:
            result = await self.fn(*self.bound.args, **self.bound.kwargs)
        except Exception:
            self.record(None, is_error=True)
            raise
        self.record(result)
        return result


class ExplicitCall(_Call):
    """A call described as (tool name, arguments) that the caller executes with `run(args)`."""

    def __init__(
        self,
        runtime: Guard,
        tool_id: str,
        args: dict[str, Any],
        run: Callable[[dict[str, Any]], Any],
        arun: Callable[[dict[str, Any]], Awaitable[Any]] | None = None,
    ) -> None:
        self._raw_args = dict(args)
        self._run = run
        self._arun = arun
        super().__init__(runtime, tool_id, {key: to_jsonable(value)[0] for key, value in args.items()})

    def _modified_arguments(self, outcome: Modified) -> dict[str, Any] | None:
        if not set(outcome.args) <= set(self._raw_args):
            return None
        self._raw_args.update(outcome.args)
        return {key: to_jsonable(value)[0] for key, value in self._raw_args.items()}

    def execute(self) -> Any:
        try:
            result = self._run(self._raw_args)
        except Exception:
            self.record(None, is_error=True)
            raise
        self.record(result)
        return result

    async def execute_async(self) -> Any:
        assert self._arun is not None
        try:
            result = await self._arun(self._raw_args)
        except Exception:
            self.record(None, is_error=True)
            raise
        self.record(result)
        return result
