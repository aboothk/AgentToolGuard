"""Per-session state: protected-value index, label set, rate limits (§6.7, §7.3)."""

from __future__ import annotations

import itertools
import secrets
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from agentguard.core.index import ValueIndex
from agentguard.core.policy import RateLimit


@dataclass
class Session:
    session_id: str
    principal: str
    index: ValueIndex
    clock: Callable[[], float] = time.monotonic
    labels: set[str] = field(default_factory=set)  # only grows, except via `declassify`
    saturation_reported: bool = False
    _recent_calls: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))
    _call_numbers: itertools.count[int] = field(default_factory=lambda: itertools.count(1))

    def next_call_id(self) -> str:
        return f"c_{next(self._call_numbers)}"

    def is_rate_limited(self, tool_id: str, limit: RateLimit | None) -> bool:
        """Count this call and report whether it exceeds the per-tool limit."""
        if limit is None:
            return False
        now = self.clock()
        calls = self._recent_calls[tool_id]
        while calls and now - calls[0] >= limit.window_seconds:
            calls.popleft()
        if len(calls) >= limit.max_calls:
            return True
        calls.append(now)
        return False


def new_session_id() -> str:
    return "s_" + secrets.token_hex(6)
