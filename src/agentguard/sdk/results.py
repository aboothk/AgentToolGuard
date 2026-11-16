"""Turn any Python return value into the strings AgentGuard remembers (section 11.2).

The result goes through core's `after_call_texts`, never through the MCP result path, so a tool
that returns {"isError": True} or {"content": ...} is not misread as an MCP result.
"""

from __future__ import annotations

from typing import Any

from agentguard.core.index import iter_string_leaves
from agentguard.sdk.local_tools import to_jsonable


def result_to_texts(value: Any) -> tuple[list[str], bool]:
    """Return (string leaves of the result, lossy). `lossy` is True if some object had to be
    turned into text with str() because it is not JSON data."""
    converted, lossy = to_jsonable(value, describe_unknown=True)
    return list(iter_string_leaves(converted)), lossy
