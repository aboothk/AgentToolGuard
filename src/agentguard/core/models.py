"""Shared data types: calls, decisions, evidence, labels (§6.1, §7.1)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Sensitivity levels, lowest to highest. `untrusted` is a separate marker (§6.1).
PUBLIC = "public"
INTERNAL = "internal"
CONFIDENTIAL = "confidential"
SECRET = "secret"
UNTRUSTED = "untrusted"
SENSITIVITY_ORDER = [PUBLIC, INTERNAL, CONFIDENTIAL, SECRET]

NAMESPACE_SEPARATOR = "__"


class Reason:
    """Machine-readable reason codes returned to the client and written to the audit log."""

    ALLOWED = "AG_ALLOWED"
    APPROVED = "AG_APPROVED"
    TOOL_UNAPPROVED = "AG_TOOL_UNAPPROVED"
    NOT_GRANTED = "AG_NOT_GRANTED"
    RULE_DENY = "AG_RULE_DENY"
    RULE_APPROVAL = "AG_RULE_APPROVAL"
    RULE_WARN = "AG_RULE_WARN"
    DEST_BLOCKED = "AG_DEST_BLOCKED"
    FLOW_VALUE_MATCH = "AG_FLOW_VALUE_MATCH"
    FLOW_SESSION_EXPOSURE = "AG_FLOW_SESSION_EXPOSURE"
    APPROVAL_LIMIT = "AG_APPROVAL_LIMIT"
    APPROVAL_DENIED = "AG_APPROVAL_DENIED"
    NO_TASK = "AG_NO_TASK"
    RATE_LIMITED = "AG_RATE_LIMITED"
    STOPPED = "AG_STOPPED"
    AUDIT_FAILURE = "AG_AUDIT_FAILURE"
    INTERNAL_ERROR = "AG_INTERNAL_ERROR"
    UPSTREAM_TIMEOUT = "AG_UPSTREAM_TIMEOUT"
    UPSTREAM_ERROR = "AG_UPSTREAM_ERROR"
    FRAME_INVALID = "AG_FRAME_INVALID"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    WARN = "warn"


_PRIORITY = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.REQUIRE_APPROVAL: 2, Decision.DENY: 3}


def strictest(first: Decision, second: Decision) -> Decision:
    """Merge rule from §7.1: deny > require_approval > warn > allow."""
    return first if _PRIORITY[first] >= _PRIORITY[second] else second


class Model(BaseModel):
    """Base for every model: unknown fields are errors (§7.4)."""

    model_config = ConfigDict(extra="forbid")


class ToolCall(Model):
    tool_id: str  # "server__tool"
    args: dict[str, Any] = Field(default_factory=dict)
    call_id: str


class Evidence(Model):
    """Why a flow rule fired. `level` is E1, E2 or E3 (§6.3)."""

    level: str
    label: str
    source_call: str | None = None
    overlap: float | None = None
    detail: str | None = None


class Finding(Model):
    """One pipeline stage's opinion about a call. Findings are merged into a Verdict."""

    decision: Decision
    reason_code: str
    rule_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class Verdict(Model):
    """The outcome of Guard.before_call."""

    decision: Decision
    reason_code: str = Reason.ALLOWED
    rule_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    approval_id: str | None = None
    would_decide: Decision | None = None  # set in observe mode only


def make_tool_id(server: str, tool: str) -> str:
    return f"{server}{NAMESPACE_SEPARATOR}{tool}"


def split_tool_id(tool_id: str) -> tuple[str, str] | None:
    """Split at the first separator. Server names cannot contain it, tool names may."""
    server, separator, tool = tool_id.partition(NAMESPACE_SEPARATOR)
    if not separator or not server or not tool:
        return None
    return server, tool
