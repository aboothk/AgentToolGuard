"""In-process SDK: wrap any Python function with AgentGuard (section 11). Depends only on `core`."""

from agentguard.sdk.approval import (
    ApprovalHandler,
    ApprovalRequest,
    Approved,
    Denied,
    Modified,
)
from agentguard.sdk.errors import ApprovalPending, ApprovalRequired, CallBlocked
from agentguard.sdk.local_tools import load_python_tools, local_tool_id, tool_definition
from agentguard.sdk.runtime import Guard
from agentguard.sdk.task import current_task

__all__ = [
    "ApprovalHandler",
    "ApprovalPending",
    "ApprovalRequest",
    "ApprovalRequired",
    "Approved",
    "CallBlocked",
    "Denied",
    "Guard",
    "Modified",
    "current_task",
    "load_python_tools",
    "local_tool_id",
    "tool_definition",
]
