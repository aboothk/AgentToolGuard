"""MCP protocol versions this gateway has been tested with.

Kept here instead of imported from the `mcp` package: that package restructured its modules
between major versions, and the gateway needs only these constants. A newer protocol version is
not claimed until the integration tests have run against it.
"""

SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[-1]
