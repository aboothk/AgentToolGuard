"""Strict parsing and canonical forms (§5.2).

Why this exists: a lenient parser lets the scanner and the model see different content.
So we reject duplicate keys, invalid UTF-8, NaN/Infinity and over-deep nesting, and we keep
number literals exactly as written (`1.0` stays `1.0`) so digests do not drift.
"""

from __future__ import annotations

import json
import math
import unicodedata
from collections.abc import Iterator
from typing import Any

import yaml

MAX_DEPTH = 64
# A duplicate key is not an exception while parsing. The parser leaves this marker in the
# dict, so a caller can reject one tool and still process the rest of the message.
DUPLICATE_KEY_MARKER = "\x00duplicate-key"


class InvalidJson(ValueError):
    """The input is not acceptable JSON (malformed, too deep, bad UTF-8, ...)."""


class RawNumber(str):
    """A JSON number kept as its original text."""


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            result[DUPLICATE_KEY_MARKER] = key
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise InvalidJson(f"non-finite number literal: {name}")


def loads_strict(data: bytes | str) -> Any:
    """Parse JSON, keeping number literals and marking duplicate keys."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidJson("invalid UTF-8") from exc
    try:
        value = json.loads(
            data,
            object_pairs_hook=_object_from_pairs,
            parse_int=RawNumber,
            parse_float=RawNumber,
            parse_constant=_reject_constant,
        )
    except RecursionError as exc:
        raise InvalidJson("nesting too deep") from exc
    except json.JSONDecodeError as exc:
        raise InvalidJson(f"malformed JSON: {exc.msg}") from exc
    if nesting_depth(value) > MAX_DEPTH:
        raise InvalidJson(f"nesting deeper than {MAX_DEPTH}")
    return value


def to_plain(value: Any) -> Any:
    """Replace RawNumber with int/float (recursively) so values can be compared and matched."""
    if isinstance(value, RawNumber):
        is_integer_literal = not any(char in value for char in ".eE")
        return int(value) if is_integer_literal else float(value)
    if isinstance(value, dict):
        return {key: to_plain(child) for key, child in value.items()}
    if isinstance(value, list):
        return [to_plain(child) for child in value]
    return value


def nesting_depth(value: Any) -> int:
    """Depth of nested lists/dicts, computed without recursion."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            deepest = max(deepest, depth)
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            deepest = max(deepest, depth)
            stack.extend((child, depth + 1) for child in node)
    return deepest


def _walk(value: Any) -> Iterator[Any]:
    stack = [value]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def find_violation(value: Any) -> str | None:
    """Return a reason if the parsed tree has a duplicate key or a lone surrogate."""
    for node in _walk(value):
        if isinstance(node, dict):
            if DUPLICATE_KEY_MARKER in node:
                return f"duplicate key {node[DUPLICATE_KEY_MARKER]!r}"
            if any(_has_lone_surrogate(key) for key in node):
                return "invalid unicode in key"
        elif isinstance(node, str) and _has_lone_surrogate(node):
            return "invalid unicode in string"
    return None


def _has_lone_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


def find_case_alias(mapping: dict[str, Any]) -> str | None:
    """Return a key that collides with another key when case is ignored."""
    seen: dict[str, str] = {}
    for key in mapping:
        folded = key.casefold()
        if folded in seen and seen[folded] != key:
            return f"keys {seen[folded]!r} and {key!r} differ only in case"
        seen[folded] = key
    return None


# --- canonical output ---------------------------------------------------------------------


def canonical_dumps(value: Any, *, sort_keys: bool = True, nfc: bool = True) -> str:
    """Serialize to compact JSON with NFC strings, sorted keys and preserved number text.

    Digests use the defaults. Forwarding messages uses `sort_keys=False, nfc=False`, so the
    content reaches the other side unchanged."""
    parts: list[str] = []
    _write(value, parts, sort_keys, nfc)
    return "".join(parts)


def _text(value: str, nfc: bool) -> str:
    return json.dumps(unicodedata.normalize("NFC", value) if nfc else value, ensure_ascii=False)


def _write(value: Any, out: list[str], sort_keys: bool, nfc: bool) -> None:
    if value is None:
        out.append("null")
    elif isinstance(value, bool):
        out.append("true" if value else "false")
    elif isinstance(value, RawNumber):
        out.append(str(value))
    elif isinstance(value, int):
        out.append(str(int(value)))
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("cannot serialize a non-finite float")
        out.append(repr(value))
    elif isinstance(value, str):
        out.append(_text(value, nfc))
    elif isinstance(value, list | tuple):
        out.append("[")
        for position, item in enumerate(value):
            if position:
                out.append(",")
            _write(item, out, sort_keys, nfc)
        out.append("]")
    elif isinstance(value, dict):
        keys = sorted(value) if sort_keys else list(value)
        out.append("{")
        for position, key in enumerate(keys):
            if position:
                out.append(",")
            out.append(_text(key, nfc))
            out.append(":")
            _write(value[key], out, sort_keys, nfc)
        out.append("}")
    else:
        raise TypeError(f"cannot serialize {type(value).__name__}")


# --- strict YAML --------------------------------------------------------------------------


class _StrictYamlLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys and keeps timestamps as plain strings."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.YAMLError(f"duplicate key {key!r} (line {key_node.start_mark.line + 1})")
            seen.add(key)
        return super().construct_mapping(node, deep)


_StrictYamlLoader.yaml_implicit_resolvers = {
    first_char: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for first_char, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def load_yaml_strict(text: str) -> Any:
    return yaml.load(text, Loader=_StrictYamlLoader)  # noqa: S506 - SafeLoader subclass
