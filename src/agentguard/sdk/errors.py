"""Exceptions raised by wrapped tools (section 11.1)."""

from __future__ import annotations


class CallBlocked(Exception):
    """AgentGuard refused the call. The wrapped function was not executed.

    Only the reason code is exposed, never the rule that fired (section 10.3); details are in the
    audit log. Frameworks turn this into their own "tool error" message."""

    def __init__(self, tool_id: str, reason_code: str, message: str | None = None) -> None:
        self.tool_id = tool_id
        self.reason_code = reason_code
        self.message = (
            message or f"AgentGuard blocked this call ({reason_code}). Details are in the audit log."
        )
        super().__init__(self.message)


class ApprovalRequired(CallBlocked):
    """The default approval flow: tell the user to approve, then retry the same call."""

    def __init__(self, tool_id: str, reason_code: str, approval_id: str | None) -> None:
        self.approval_id = approval_id
        super().__init__(
            tool_id,
            reason_code,
            f"Human confirmation required (approval {approval_id}). Tell the user to run "
            f"`agentguard approve {approval_id}`, then retry the same call.",
        )


class ApprovalPending(Exception):
    """A handler may raise this (or a framework's interrupt exception, see
    `Guard.add_passthrough`) to suspend the call instead of deciding. It propagates unchanged."""
