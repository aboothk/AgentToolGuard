# Using AgentGuard inside your Python agent (SDK)

English · [简体中文](sdk.zh-CN.md)

The MCP gateway needs no code changes: point your client at `agentguard serve`. Use the SDK when you want AgentGuard around **plain Python tools**, when you need the run id and per-task grants, or when approvals should happen inside your application.

The SDK is independent of any agent framework. LangGraph and AgentDojo have thin adapters on top of it (`agentguard.adapters.*`); for any other framework you wrap your tool functions yourself, as shown here.

```python
from agentguard import Guard

guard = Guard.from_files("agentguard.yaml")        # the lockfile path comes from the config

@guard.tool("send_report")                         # becomes the tool `local__send_report`
def send_report(to: str, body: str) -> str:
    """Send the weekly report."""
    ...

with guard.task(principal="user_123", run_id=run_id):
    send_report(to="alice@corp.example", body=text)
```

## Steps

1. **Wrap** your tool functions with `@guard.tool(name)` or `guard.wrap(fn, name)`. Sync and async functions both work; the wrapper keeps the name, signature and docstring, so frameworks that build a tool schema from them still see the original.
2. **Lock** them: `agentguard lock --from-python my_module:TOOLS` (a function, or a list/tuple/dict of functions), review with `lock diff --from-python ...`, then `lock approve --from-python ...`. Tools live under the reserved server name `local`. A plain `agentguard lock` leaves the `local` entries alone; `lock --check --from-python ...` checks them.
3. **Declare labels and egress** for each local tool in `agentguard.lock`, as for MCP tools (`labels.produces`, `egress`).
4. **Run** your agent inside `guard.task(...)`.

## What is locked

A local tool's definition is its name, docstring, and parameter names and JSON types. Changing any of them after approval hides the tool (`tool_drift`). **The function body is not part of the digest**: the lockfile does not detect a changed implementation. That is covered by code review and dependency pinning, the same as for any code you run.

## Tasks, sessions and grants

- `guard.task(principal=..., run_id=...)` sets who is calling. A call outside a task is refused (`AG_NO_TASK`): without a principal there is nothing to authorize against.
- The data-flow session (labels, the index of protected values) belongs to the **run id**. Entering a task again with the same `run_id` continues the session, for example after a LangGraph interrupt. Different run ids are isolated, also when they run concurrently.
- The task is carried in a `ContextVar`. It follows asyncio tasks and `contextvars.copy_context().run(...)`, **not** a bare `threading.Thread` or `ThreadPoolExecutor.submit` (those calls are refused, not allowed). Frameworks that run sync tools in an executor normally copy the context; if yours does not, wrap the call: `ctx = contextvars.copy_context(); pool.submit(ctx.run, tool, ...)`.
- `grants={"local__send_report": {"destinations": ["corp_mail"]}}` replaces the allowlists of the flow rules for that tool (a glob is allowed) while the task runs: it can widen or narrow them. Set names must exist under `flow.destinations`; anything else is rejected when the task is created.

## Arguments

Policy sees the bound arguments, defaults applied, as JSON. Parameters that are not data (a database handle, a benchmark environment) go in `exclude=("env",)`; they stay out of policy, the audit log and the tool definition. Other non-JSON objects are shown as `<TypeName>`, never `repr()`. Values passed through `**kwargs` appear as ordinary arguments.

## Approvals

By default a call that needs approval raises `ApprovalRequired` with an approval id, the same flow as the gateway: a person runs `agentguard approve <id>`, the same call is retried (inside a task with the same `run_id`) and goes through once.

To decide inside your application, pass a handler:

```python
from agentguard.sdk import Approved, Denied, Modified

def ask(request):            # request.tool_id, .summary (redacted), .rule_ids, .evidence ...
    return Approved(decided_by="alice")     # or Denied(), or Modified({"to": "alice@corp.example"})

with guard.task(run_id=run_id, on_approval=ask): ...
```

- `Modified` runs the new arguments through the whole pipeline again. If that needs approval again, the call is denied.
- A handler that raises, or returns anything else, means denied.
- To suspend instead of deciding (LangGraph's `interrupt()`), raise an exception registered with `guard.add_passthrough(ExceptionType)`; it propagates unchanged.
- In `observe` mode the handler is never called.
- Handlers may be `async` for async tools; a sync tool with an async handler is denied.

## Results

What a tool returns (string, dict, list, dataclass, Pydantic model, bytes) is converted to its string leaves, labelled with the lockfile's `produces`, and remembered. Objects that are not JSON data are turned into text with `str()` and `result.unserializable` is audited. The return value reaches your code unchanged.

## Errors

`CallBlocked` (with `.reason_code`) means the function did not run. `ApprovalRequired` is a subclass. Turn them into your framework's tool-error message. The message names the reason code only; rule details are in the audit log.

## Thread safety

Calls are serialized with a lock, so wrapped tools can be called from several threads. A tool that blocks for a long time does not hold the lock while it runs (the lock covers only the decision and the result recording).
