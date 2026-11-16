"""Tool-definition poisoning hints (§5.4).

Runs only during `lock diff` / `lock approve`. The output is a list of hints for the human
reviewer. It never blocks anything by itself.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any

from agentguard.core.models import Model

LONG_TEXT_CHARS = 1500
TEXT_FIELDS = {"description", "title", "default", "enum", "examples"}

_INSTRUCTION_PATTERNS = [
    r"\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|above|earlier)\b",
    r"\byou (must|should|need to|have to)\b",
    r"\b(always|first|before) (call|use|invoke|run)\b",
    r"\bbefore (calling|using|running) (this|any|the)\b",
    r"\b(system prompt|instructions? above)\b",
]
_CONCEALMENT_PATTERNS = [
    r"\bdo not (tell|mention|reveal|inform|show)\b",
    r"\bdon'?t (tell|mention|reveal|inform|show)\b",
    r"\b(secretly|silently|without (telling|informing|notifying))\b",
    r"\bnever (tell|mention|reveal)\b",
]
_URL = re.compile(r"https?://[^\s\"')>]+", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")


class Hint(Model):
    kind: str
    path: str
    snippet: str


def scan_tool(tool: dict[str, Any], other_tool_names: Iterable[str] = ()) -> list[Hint]:
    """Return poisoning hints for one tool definition."""
    own_name = str(tool.get("name", ""))
    others = [name for name in other_tool_names if name and name != own_name and len(name) >= 4]
    hints: list[Hint] = []
    for path, text in _model_visible_strings(tool, path="$", field=""):
        hints.extend(_scan_text(path, text, others))
    return hints


def _model_visible_strings(node: Any, path: str, field: str) -> Iterator[tuple[str, str]]:
    """Yield every string the model may read, following allOf/anyOf/$defs and friends."""
    if isinstance(node, str):
        if field in TEXT_FIELDS:
            yield path, node
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from _model_visible_strings(child, f"{path}[{index}]", field)
    elif isinstance(node, dict):
        for key, child in node.items():
            yield from _model_visible_strings(
                child, f"{path}.{key}", str(key) if isinstance(key, str) else ""
            )


def _scan_text(path: str, text: str, other_tool_names: list[str]) -> list[Hint]:
    found: list[Hint] = []

    def add(kind: str, match_text: str) -> None:
        found.append(Hint(kind=kind, path=path, snippet=match_text[:80]))

    lowered = text.lower()
    for pattern in _INSTRUCTION_PATTERNS:
        match = re.search(pattern, lowered)
        if match:
            add("instruction_to_agent", match.group(0))
    for pattern in _CONCEALMENT_PATTERNS:
        match = re.search(pattern, lowered)
        if match:
            add("concealment", match.group(0))
    for name in other_tool_names:
        if re.search(rf"\b{re.escape(name.lower())}\b", lowered):
            add("mentions_other_tool", name)
    for match in _URL.finditer(text):
        add("url", match.group(0))
    for match in _EMAIL.finditer(text):
        add("email", match.group(0))
    if _INVISIBLE.search(text):
        add("invisible_characters", "zero-width or Unicode tag characters")
    if len(text) > LONG_TEXT_CHARS:
        add("unusually_long", f"{len(text)} characters")
    return found
