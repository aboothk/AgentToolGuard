"""AgentDojo adapter: run AgentDojo tools through AgentGuard. Requires `pip install agentguard[agentdojo]`."""

from agentguard.adapters.agentdojo.runtime import (
    ApprovalMode,
    build_suite_lock,
    guard_pipeline,
    guarded_runtime_class,
    tool_definition_of,
)

__all__ = [
    "ApprovalMode",
    "build_suite_lock",
    "guard_pipeline",
    "guarded_runtime_class",
    "tool_definition_of",
]
