"""Local Python tools: definitions, argument binding, JSON-safe conversion (sections 11.1, 11.2).

A local tool lives under the reserved server name `local`, so its id is `local__<name>`. Its
definition is built from the function name, docstring and parameter names/types only. The
function body is deliberately not part of the digest (see open question 4 in the design).
Everything here must be deterministic: no repr() of objects, no addresses, no defaults.
"""

from __future__ import annotations

import dataclasses
import enum
import importlib
import inspect
import math
import typing
from collections.abc import Callable, Iterable
from typing import Any

from agentguard.core.lock import validate_tool_definition
from agentguard.core.models import make_tool_id
from agentguard.core.policy import LOCAL_SERVER

MAX_CONVERSION_DEPTH = 20
_JSON_TYPES: dict[Any, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    tuple: "array",
    set: "array",
    dict: "object",
}
_JSON_TYPES_BY_NAME = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
}


def local_tool_id(name: str) -> str:
    return make_tool_id(LOCAL_SERVER, name)


# --- definitions --------------------------------------------------------------------------


def tool_definition(fn: Callable[..., Any], name: str, exclude: Iterable[str] = ()) -> dict[str, Any]:
    """The MCP-style definition of a Python function, used for the lockfile digest."""
    skipped = set(exclude)
    properties: dict[str, Any] = {}
    required: list[str] = []
    accepts_extra = False
    hints = _resolved_hints(fn)
    for parameter in inspect.signature(fn).parameters.values():
        if parameter.name in skipped:
            continue
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            accepts_extra = True
            continue
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            properties[parameter.name] = {"type": "array"}
            continue
        properties[parameter.name] = {"type": _json_type(hints.get(parameter.name, parameter.annotation))}
        if parameter.default is inspect.Parameter.empty:
            required.append(parameter.name)
    schema: dict[str, Any] = {"type": "object", "properties": properties, "required": required}
    if accepts_extra:
        schema["additionalProperties"] = True
    return {"name": name, "description": inspect.getdoc(fn) or "", "inputSchema": schema}


def _resolved_hints(fn: Callable[..., Any]) -> dict[str, Any]:
    """Annotations with string forms (`from __future__ import annotations`) evaluated, so the
    definition does not depend on how the module was written. Falls back to the raw strings when
    a name cannot be resolved (for example an import under TYPE_CHECKING)."""
    try:
        return typing.get_type_hints(fn)
    except Exception:  # noqa: BLE001 - unresolved names are expected and handled by the fallback
        return {}


def _json_type(annotation: Any) -> str:
    """A JSON type name for an annotation, or "any". Never uses repr(), so it is stable across
    Python versions."""
    if annotation is inspect.Parameter.empty or annotation is Any:
        return "any"
    if isinstance(annotation, str):
        return _JSON_TYPES_BY_NAME.get(annotation.strip(), "any")
    origin = typing.get_origin(annotation)
    if origin is not None:
        members = [arg for arg in typing.get_args(annotation) if arg is not type(None)]
        if origin in (typing.Union, getattr(__import__("types"), "UnionType", None)):
            return _json_type(members[0]) if len(members) == 1 else "any"
        return _JSON_TYPES.get(origin, "any")
    return _JSON_TYPES.get(annotation, "any")


# --- arguments ----------------------------------------------------------------------------


def bind_arguments(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> inspect.BoundArguments:
    bound = inspect.signature(fn).bind(*args, **kwargs)
    bound.apply_defaults()
    return bound


def policy_arguments(bound: inspect.BoundArguments, exclude: Iterable[str] = ()) -> dict[str, Any]:
    """The arguments policy sees: JSON-safe, without injected dependencies (`exclude`).

    Objects that are not JSON data become `<TypeName>` (not repr) so the same call always has the
    same fingerprint."""
    skipped = set(exclude)
    signature = bound.signature
    result: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        if name in skipped:
            continue
        kind = signature.parameters[name].kind
        if kind is inspect.Parameter.VAR_KEYWORD:
            result.update({str(key): to_jsonable(item)[0] for key, item in value.items()})
        else:
            result[name] = to_jsonable(value)[0]
    return result


def to_jsonable(value: Any, describe_unknown: bool = False, _depth: int = 0) -> tuple[Any, bool]:
    """Convert to JSON data. Returns (value, lossy).

    Unknown objects become `<TypeName>`, or `str(value)` if `describe_unknown` (used for tool
    results, where the text is what we want to remember)."""
    if _depth > MAX_CONVERSION_DEPTH:
        return f"<{type(value).__name__}>", True
    if value is None or isinstance(value, bool | int | str):
        return value, False
    if isinstance(value, float):
        return (value, False) if math.isfinite(value) else (str(value), False)
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace"), True
    if isinstance(value, enum.Enum):
        return to_jsonable(value.value, describe_unknown, _depth + 1)
    if isinstance(value, dict):
        converted = {str(key): to_jsonable(item, describe_unknown, _depth + 1) for key, item in value.items()}
        return {k: v for k, (v, _) in converted.items()}, any(lossy for _, lossy in converted.values())
    if isinstance(value, list | tuple | set | frozenset):
        items = [to_jsonable(item, describe_unknown, _depth + 1) for item in value]
        return [v for v, _ in items], any(lossy for _, lossy in items)
    model_dump = getattr(value, "model_dump", None)  # Pydantic models
    if callable(model_dump):
        try:
            return to_jsonable(model_dump(mode="json"), describe_unknown, _depth + 1)
        except Exception:  # noqa: BLE001 - fall through to the generic handling
            pass
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {f.name: getattr(value, f.name) for f in dataclasses.fields(value)}
        return to_jsonable(fields, describe_unknown, _depth + 1)
    return (str(value) if describe_unknown else f"<{type(value).__name__}>"), True


# --- lockfile support (`agentguard lock --from-python module:tools`) ------------------------


def load_python_tools(spec: str) -> list[dict[str, Any]]:
    """Import `module:attribute` and return tool definitions for the functions it holds.

    The attribute may be one function or a list/tuple/dict of functions. Functions wrapped by the
    SDK carry their definition; plain functions get one from their name; ready-made definition
    dicts (for example `definitions_of(langchain_tools)`) are used as they are. Importing runs your own
    module code, as with any Python import."""
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError(f"expected module:attribute, got {spec!r}")
    target = getattr(importlib.import_module(module_name), attribute)
    functions = (
        list(target.values())
        if isinstance(target, dict)
        else (list(target) if isinstance(target, list | tuple) else [target])
    )
    definitions = []
    for function in functions:
        definition = (
            function if isinstance(function, dict) else getattr(function, "__agentguard_definition__", None)
        )
        if definition is None:
            definition = tool_definition(function, function.__name__)
        problem = validate_tool_definition(definition)
        if problem:
            raise ValueError(f"tool {definition.get('name')!r} rejected: {problem}")
        definitions.append(definition)
    return definitions
