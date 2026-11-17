"""AgentDojo adapter (section 14.1): AgentDojo's tools run through the SDK's Guard.

AgentDojo executes tools with `FunctionsRuntime.run_function(env, name, kwargs)`, and
`TaskSuite.run_task_with_pipeline(..., runtime_class=...)` lets us choose the runtime class. This
adapter supplies a subclass whose `run_function` asks the Guard first. It contains no policy:
labels, egress and rules come from the lockfile and the policy file.

Each runtime instance is one run (AgentDojo makes a new one per task), so the data-flow session
covers exactly one task.
"""

from __future__ import annotations

import uuid
import weakref
from collections.abc import Mapping
from typing import Any, Literal

from agentdojo.agent_pipeline import AgentPipeline, ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import (
    EmptyEnv,
    Function,
    FunctionCallArgTypes,
    FunctionReturnType,
    FunctionsRuntime,
    TaskEnvironment,
)

from agentguard.core.lock import LockFile, ToolLabels, approve, update_lock
from agentguard.core.policy import LOCAL_SERVER
from agentguard.sdk import ApprovalRequest, Approved, CallBlocked, Denied, Guard

ApprovalMode = Literal["default", "deny", "approve"]
"""`default`: the tool answers with "approval required". `deny` / `approve`: every approval request
is answered automatically; the two give the lower and upper bound of what a human could allow."""

DEFAULT_PRINCIPAL = "agentdojo-user"


def tool_definition_of(function: Function) -> dict[str, Any]:
    """The MCP-style definition of an AgentDojo tool, from its Pydantic schema and docstring."""
    return {
        "name": function.name,
        "description": function.full_docstring,
        "inputSchema": function.parameters.model_json_schema(),
    }


def build_suite_lock(functions: list[Function], declarations: Mapping[str, Mapping[str, Any]]) -> LockFile:
    """A lockfile with every tool of a suite approved, labels and egress from `declarations`.

    `declarations[tool]` may hold `produces` (labels) and `egress` (an Egress-shaped mapping)."""
    from agentguard.core.lock import Egress

    definitions = [tool_definition_of(function) for function in functions]
    lock = update_lock(LockFile(), {LOCAL_SERVER: definitions}, {})
    for name, declared in declarations.items():
        locked = lock.servers[LOCAL_SERVER].tools[name]  # a typo in a declaration file fails loudly
        locked.labels = ToolLabels(produces=list(declared.get("produces", [])))
        egress = declared.get("egress")
        locked.egress = Egress.model_validate(egress) if egress else None
    approve(lock)
    for locked in lock.servers[LOCAL_SERVER].tools.values():
        locked.approved_at = None  # generated lockfiles must be reproducible byte for byte
    return lock


def _approval_handler(mode: ApprovalMode, log: list[ApprovalRequest]) -> Any:
    if mode == "default":
        return None

    def handler(request: ApprovalRequest) -> Approved | Denied:
        log.append(request)
        return Approved(decided_by="benchmark") if mode == "approve" else Denied(decided_by="benchmark")

    return handler


def guarded_runtime_class(
    guard: Guard,
    approvals: ApprovalMode = "default",
    principal: str = DEFAULT_PRINCIPAL,
    approval_log: list[ApprovalRequest] | None = None,
) -> type[FunctionsRuntime]:
    """A FunctionsRuntime subclass for `run_task_with_pipeline(runtime_class=...)`.

    Every tool in `functions` must be in the Guard's lockfile (use `build_suite_lock`). A call
    the Guard blocks comes back to the agent as an error string, like any failing tool."""
    log = approval_log if approval_log is not None else []
    handler = _approval_handler(approvals, log)

    class GuardedRuntime(FunctionsRuntime):
        def __init__(self, functions: Any = ()) -> None:
            super().__init__(functions)
            self._run_id = "run_" + uuid.uuid4().hex[:12]
            for function in self.functions.values():
                guard.register_local_tool(tool_definition_of(function))

        def run_function(
            self,
            env: TaskEnvironment | None,
            function: str,
            kwargs: Mapping[str, FunctionCallArgTypes],
            raise_on_error: bool = False,
        ) -> tuple[FunctionReturnType, str | None]:
            if function not in self.functions:
                return super().run_function(env, function, kwargs, raise_on_error)
            tool = self.functions[function]
            try:
                resolved = self._execute_nested_calls(env, kwargs)
                arguments = tool.parameters.model_validate(resolved).model_dump()
            except Exception as exc:
                if raise_on_error:
                    raise
                return "", f"{type(exc).__name__}: {exc}"
            if env is None and tool.dependencies:
                raise ValueError(f"Function {function} has dependencies but no environment was provided.")
            injected = {name: dep.extract_dep_from_env(env) for name, dep in tool.dependencies.items()}  # type: ignore[arg-type]

            try:
                with guard.task(principal=principal, run_id=self._run_id, on_approval=handler):
                    result = guard.guarded_call(function, arguments, lambda final: tool(**(final | injected)))
            except CallBlocked as blocked:
                if raise_on_error:
                    raise
                return "", f"CallBlocked: {blocked.message}"
            except Exception as exc:
                if raise_on_error:
                    raise
                return "", f"{type(exc).__name__}: {exc}"
            return result, None

    return GuardedRuntime


# --- for real LLM runs: replace the pipeline's tool executor --------------------------------------


def guard_pipeline(
    pipeline: AgentPipeline,
    guard: Guard,
    approvals: ApprovalMode = "default",
    principal: str = DEFAULT_PRINCIPAL,
    approval_log: list[ApprovalRequest] | None = None,
) -> AgentPipeline:
    """Swap every ToolsExecutor in a pipeline for one that asks the Guard first.

    `benchmark_suite_with_injections` does not take a runtime class, so for model runs the
    guard goes into the pipeline instead. AgentDojo builds one FunctionsRuntime per task, so one
    guarded runtime (= one session) is kept per original runtime object. It must not be kept in
    `extra_args`: AgentDojo's `query` uses a mutable default dict for it, shared by every task."""
    runtime_class = guarded_runtime_class(guard, approvals, principal, approval_log)
    guarded: weakref.WeakKeyDictionary[Any, Any] = weakref.WeakKeyDictionary()

    class GuardedToolsExecutor(ToolsExecutor):
        def query(  # type: ignore[no-untyped-def,override]
            self, query, runtime, env=None, messages=(), extra_args=None
        ):
            env = EmptyEnv() if env is None else env
            extra_args = {} if extra_args is None else extra_args
            if runtime not in guarded:
                guarded[runtime] = runtime_class(list(runtime.functions.values()))
            result = super().query(query, guarded[runtime], env, messages, extra_args)
            return result[0], runtime, *result[2:]

    for element in pipeline.elements:
        if isinstance(element, ToolsExecutionLoop):
            element.elements = [
                GuardedToolsExecutor(item.output_formatter) if isinstance(item, ToolsExecutor) else item
                for item in element.elements
            ]
    return pipeline
