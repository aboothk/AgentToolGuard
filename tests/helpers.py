"""Test helpers: build a Guard with an in-memory approved lockfile."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agentguard.core.approval import ApprovalStore
from agentguard.core.audit import AuditLog, read_entries
from agentguard.core.guard import Guard
from agentguard.core.lock import (
    Egress,
    LockFile,
    ToolLabels,
    approve,
    launch_digest,
    update_lock,
)
from agentguard.core.models import Verdict
from agentguard.core.policy import parse_config
from agentguard.core.session import Session

SECRET_DOC = (
    "Project Falcon launch budget is 4.2M USD. Board vote scheduled for March 3rd. "
    "Codename ORCHID-7731 must not leak outside the company."
)

FLOW_CONFIG: dict[str, Any] = {
    "destinations": {"corp_mail": ["*@corp.example"], "corp_hosts": ["*.corp.example"]},
    "rules": [
        {
            "id": "FL-001",
            "from": ["confidential", "secret"],
            "to": {"kind": ["network", "message"]},
            "allow_destinations": ["corp_mail", "corp_hosts"],
            "on_value_match": "deny",
            "on_session_exposure": "require_approval",
        },
        {
            "id": "FL-002",
            "from": ["untrusted"],
            "to": {"tools": ["mail__send_email", "files__delete_*"]},
            "on_session_exposure": "require_approval",
        },
    ],
}


def make_tool(name: str, description: str = "does a thing", **properties: str) -> dict[str, Any]:
    schema = {arg: {"type": kind} for arg, kind in properties.items()}
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": schema},
    }


DEFAULT_TOOLS: dict[str, list[dict[str, Any]]] = {
    "files": [
        make_tool("read_document", path="string"),
        make_tool("delete_file", path="string"),
    ],
    "web": [make_tool("search", query="string"), make_tool("fetch", url="string")],
    "mail": [make_tool("send_email", to="string", subject="string", body="string")],
}

DEFAULT_DECLARATIONS: dict[str, dict[str, Any]] = {
    "files/read_document": {"produces": ["confidential"]},
    "web/search": {
        "produces": ["untrusted"],
        "egress": Egress(kind="network", payload_args=["query"]),
    },
    "web/fetch": {
        "produces": ["untrusted"],
        "egress": Egress(kind="network", destination_args=["url"], payload_args=["url"]),
    },
    "mail/send_email": {
        "egress": Egress(kind="message", destination_args=["to"], payload_args=["subject", "body"])
    },
}


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def build_lock(tools: dict[str, list[dict[str, Any]]], declarations: dict[str, dict[str, Any]]) -> LockFile:
    lock = update_lock(LockFile(), tools, {server: launch_digest(["x"], None) for server in tools})
    for key, declared in declarations.items():
        server, tool = key.split("/")
        locked = lock.servers[server].tools[tool]
        locked.labels = ToolLabels(produces=declared.get("produces", []))
        locked.egress = declared.get("egress")
    approve(lock)
    return lock


def build_guard(
    tmp_path: Path,
    config: dict[str, Any] | None = None,
    tools: dict[str, list[dict[str, Any]]] | None = None,
    declarations: dict[str, dict[str, Any]] | None = None,
    clock: FakeClock | None = None,
) -> Guard:
    tools = tools if tools is not None else DEFAULT_TOOLS
    declarations = declarations if declarations is not None else DEFAULT_DECLARATIONS
    settings: dict[str, Any] = {"flow": FLOW_CONFIG, **(config or {})}
    clock = clock or FakeClock()
    parsed = parse_config(yaml.safe_dump(settings), base_dir=tmp_path)
    guard = Guard(
        config=parsed,
        lock=build_lock(tools, declarations),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        approvals=ApprovalStore(tmp_path / "approvals", parsed.approval.timeout_seconds, clock),
        clock=clock,
    )
    for server, server_tools in tools.items():
        guard.filter_tools(server, server_tools)
    return guard


def call(guard: Guard, session: Session, tool_id: str, **args: Any) -> tuple[Verdict, Any]:
    from agentguard.core.models import ToolCall

    tool_call = ToolCall(tool_id=tool_id, args=args, call_id=session.next_call_id())
    return guard.before_call(session, tool_call), tool_call


def read_data(guard: Guard, session: Session, tool_id: str, text: str, **args: Any) -> None:
    """Simulate a tool call that returns `text`."""
    verdict, tool_call = call(guard, session, tool_id, **args)
    assert verdict.decision.value in ("allow", "warn"), verdict
    guard.after_call(session, tool_call, {"content": [{"type": "text", "text": text}]})


def audit_events(tmp_path: Path, event: str | None = None) -> list[dict[str, Any]]:
    entries = read_entries(tmp_path / "audit.jsonl")
    return [entry for entry in entries if event is None or entry["event"] == event]
