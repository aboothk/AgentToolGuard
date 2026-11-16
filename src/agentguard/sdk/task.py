"""Tasks: who is calling and in which run (section 11.1, section 4.3).

`with guard.task(principal=..., run_id=...)` sets the current task for the code inside it, using a
ContextVar. The session (labels, value index) belongs to the run: entering a task again with the
same run_id, for example after a LangGraph interrupt, continues the same session.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING

from agentguard.core.session import Session
from agentguard.sdk.approval import ApprovalHandler

if TYPE_CHECKING:
    from agentguard.sdk.runtime import Guard


@dataclass(frozen=True)
class TaskContext:
    """What one call needs to know about its task. The grants live here, not on the shared
    session: several tool calls of one run can be in flight at once (LangGraph runs the calls of
    one model message in parallel), each with its own task."""

    session: Session
    run_id: str
    on_approval: ApprovalHandler | None
    destination_overrides: dict[str, list[str]]


_current: ContextVar[TaskContext | None] = ContextVar("agentguard_task", default=None)


def current_task() -> TaskContext | None:
    return _current.get()


class TaskScope:
    """Context manager for sync (`with`) and async (`async with`) code."""

    def __init__(
        self,
        runtime: Guard,
        principal: str | None,
        run_id: str,
        overrides: dict[str, list[str]],
        on_approval: ApprovalHandler | None,
    ) -> None:
        self._runtime = runtime
        self._principal = principal
        self._run_id = run_id
        self._overrides = overrides
        self._on_approval = on_approval
        self._token: Token[TaskContext | None] | None = None

    def __enter__(self) -> TaskContext:
        session = self._runtime.session_for(self._principal, self._run_id)
        context = TaskContext(session, self._run_id, self._on_approval, dict(self._overrides))
        self._token = _current.set(context)
        return context

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._token is not None:
            _current.reset(self._token)

    async def __aenter__(self) -> TaskContext:
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.__exit__(exc_type, exc, traceback)
