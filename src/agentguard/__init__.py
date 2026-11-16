"""AgentGuard: MCP tool lockfile + cross-tool data-flow policy gateway."""

__version__ = "0.1.0"

from agentguard.sdk.runtime import Guard  # noqa: E402  (the Guard that can also wrap Python functions)

__all__ = ["Guard", "__version__"]
