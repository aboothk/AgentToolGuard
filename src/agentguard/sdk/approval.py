"""Approval handlers (section 11.3).

The default flow is the same as the gateway's: register a pending approval, tell the agent to
retry, a human runs `agentguard approve`. A handler replaces that with your own channel (a
dialog, a chat message, LangGraph's interrupt()).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ApprovalRequest:
    """What a person needs to see to decide. Arguments are redacted (length, digest, host)."""

    tool_id: str
    principal: str
    run_id: str
    summary: dict[str, Any]
    rule_ids: list[str]
    reason_code: str
    evidence: list[str]


@dataclass(frozen=True)
class Approved:
    decided_by: str = "handler"


@dataclass(frozen=True)
class Denied:
    decided_by: str = "handler"


@dataclass(frozen=True)
class Modified:
    """Approve with different arguments. The new arguments go through the whole pipeline again;
    a second require_approval after a modification is a denial."""

    args: dict[str, Any]
    decided_by: str = "handler"


Outcome = Approved | Denied | Modified
ApprovalHandler = Callable[[ApprovalRequest], Outcome | Awaitable[Outcome]]


@dataclass
class HandlerSettings:
    """Exceptions that must pass through a handler untouched (an interrupt is not a failure)."""

    passthrough: tuple[type[BaseException], ...] = field(default_factory=tuple)
