"""The SDK entry point: a Guard that can wrap Python functions (section 11.1).

    guard = Guard.from_files("agentguard.yaml")

    @guard.tool("send_report")
    def send_report(to: str, body: str) -> str: ...

    with guard.task(principal="user_123", run_id=run_id):
        send_report(to="alice@corp.example", body=text)

Only this module and wrap.py know about wrapping. All decisions are made by the core.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from agentguard.core.guard import Guard as CoreGuard
from agentguard.core.guard import LabeledResult
from agentguard.core.models import ToolCall, Verdict
from agentguard.core.session import Session
from agentguard.sdk.approval import ApprovalHandler
from agentguard.sdk.errors import ApprovalPending
from agentguard.sdk.local_tools import local_tool_id
from agentguard.sdk.task import TaskContext, TaskScope
from agentguard.sdk.wrap import ExplicitCall, make_wrapper


class Guard(CoreGuard):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # The core is not thread-safe. Frameworks run sync tools in thread pools, so serialize.
        self._lock = threading.RLock()
        self._sessions: dict[tuple[str, str], Session] = {}
        self._definitions: dict[str, dict[str, Any]] = {}
        self.passthrough: tuple[type[BaseException], ...] = (ApprovalPending,)

    # --- tasks ------------------------------------------------------------------------------

    def task(
        self,
        principal: str | None = None,
        run_id: str | None = None,
        grants: dict[str, dict[str, Any]] | None = None,
        on_approval: ApprovalHandler | None = None,
    ) -> TaskScope:
        """Scope for one agent run. `grants` maps a tool pattern to {"destinations": [set names]},
        which replace the flow rules' allowlists for that tool during the task."""
        overrides = self._destination_overrides(grants or {})
        return TaskScope(self, principal, run_id or "run_" + uuid.uuid4().hex[:8], overrides, on_approval)

    def _destination_overrides(self, grants: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
        overrides: dict[str, list[str]] = {}
        for tool_pattern, grant in grants.items():
            unknown_keys = set(grant) - {"destinations"}
            if unknown_keys:
                raise ValueError(f"unknown task grant keys for {tool_pattern}: {sorted(unknown_keys)}")
            names = list(grant.get("destinations", []))
            for name in names:
                if name not in self.config.flow.destinations:
                    raise ValueError(f"task grant for {tool_pattern}: unknown destination set {name!r}")
            overrides[tool_pattern] = names
        return overrides

    def session_for(self, principal: str | None, run_id: str) -> Session:
        """The session of a run; created on first use and reused when the run continues."""
        who = principal or self.config.principal
        with self._lock:
            if (who, run_id) not in self._sessions:
                self._sessions[(who, run_id)] = self.open_session(who)
            return self._sessions[(who, run_id)]

    def add_passthrough(self, *exceptions: type[BaseException]) -> None:
        """Exceptions an approval handler may raise to suspend the call (e.g. an interrupt)."""
        self.passthrough = (*self.passthrough, *exceptions)

    # --- wrapping ---------------------------------------------------------------------------

    def tool(
        self, name: str | None = None, *, exclude: tuple[str, ...] = ()
    ) -> Callable[[Callable[..., Any]], Any]:
        """Decorator: `@guard.tool("send_report")`. `exclude` names injected parameters (a
        database handle, an environment) that are not data and stay out of policy."""

        def decorator(fn: Callable[..., Any]) -> Any:
            return self.wrap(fn, name, exclude=exclude)

        return decorator

    def wrap(self, fn: Callable[..., Any], name: str | None = None, *, exclude: tuple[str, ...] = ()) -> Any:
        return make_wrapper(self, fn, name or fn.__name__, tuple(exclude))

    def guarded_call(
        self,
        name: str,
        args: dict[str, Any],
        run: Callable[[dict[str, Any]], Any],
    ) -> Any:
        """Check and run a call a framework describes as (tool name, arguments).

        The tool must be registered (`register_local_tool`). `run` receives the final arguments,
        which differ from `args` only if an approval handler returned `Modified`."""
        call = ExplicitCall(self, local_tool_id(name), args, run)
        call.authorize()
        return call.execute()

    async def aguarded_call(
        self,
        name: str,
        args: dict[str, Any],
        arun: Callable[[dict[str, Any]], Awaitable[Any]],
    ) -> Any:
        """Async twin of `guarded_call`: the approval handler and the tool may both be async."""
        call = ExplicitCall(self, local_tool_id(name), args, lambda final: None, arun)
        await call.authorize_async()
        return await call.execute_async()

    def register_local_tool(self, definition: dict[str, Any]) -> None:
        """Check the tool against the lockfile and add it to the exposed set (additively)."""
        name = definition["name"]
        with self._lock:
            known = self._definitions.get(name)
            if known is not None and known != definition:
                raise ValueError(f"a different local tool named {name!r} is already registered")
            self._definitions[name] = definition
            self.filter_tools("local", [definition], additive=True)

    # --- calls (serialized) -----------------------------------------------------------------

    def decide(self, task: TaskContext, tool_id: str, args: dict[str, Any]) -> tuple[Verdict, ToolCall]:
        with self._lock:
            # Applied here, under the lock and just before the decision, so another task of the same
            # run cannot swap them in between.
            task.session.destination_overrides = task.destination_overrides
            call = ToolCall(tool_id=tool_id, args=args, call_id=task.session.next_call_id())
            external = task.on_approval is not None
            return self.before_call(task.session, call, approvals="external" if external else "file"), call

    def record_result(
        self, task: TaskContext, call: ToolCall, texts: list[str], is_error: bool
    ) -> LabeledResult:
        with self._lock:
            return self.after_call_texts(task.session, call, texts, is_error)
