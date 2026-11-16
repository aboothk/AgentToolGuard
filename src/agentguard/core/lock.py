"""Tool lockfile: digests, comparison and lifecycle (§5).

The lockfile is a YAML file you commit to Git. Each tool has two digests:
  digest      the whole tool definition
  structural  the same definition without descriptive text
so a "description only" change can be told apart from a "capability" change.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field

from agentguard.core.canonical import (
    canonical_dumps,
    find_case_alias,
    find_violation,
    load_yaml_strict,
)
from agentguard.core.models import Model

LOCK_VERSION = 1
DESCRIPTIVE_KEYS = {"description", "title", "examples", "$comment"}
# Inside these keywords the dict keys are user-chosen names, not schema keywords.
NAME_MAP_KEYS = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}


class LockError(Exception):
    """The lockfile is missing, malformed or contains unknown fields."""


# --- digests ------------------------------------------------------------------------------


def sha256_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def full_digest(tool: dict[str, Any]) -> str:
    return sha256_digest(canonical_dumps(tool))


def structural_digest(tool: dict[str, Any]) -> str:
    return sha256_digest(canonical_dumps(_strip_descriptive(tool, in_name_map=False)))


def _strip_descriptive(node: Any, in_name_map: bool) -> Any:
    if isinstance(node, list):
        return [_strip_descriptive(item, False) for item in node]
    if not isinstance(node, dict):
        return node
    kept: dict[str, Any] = {}
    for key, child in node.items():
        if not in_name_map and key in DESCRIPTIVE_KEYS:
            continue
        kept[key] = _strip_descriptive(child, in_name_map=(not in_name_map and key in NAME_MAP_KEYS))
    return kept


def launch_digest(command: list[str] | None, url: str | None) -> str:
    """Digest of how a server is started (§5.1 `launch_digest`)."""
    return sha256_digest(canonical_dumps({"command": command, "url": url}))


def validate_tool_definition(tool: Any) -> str | None:
    """Return why a tool definition must be rejected, or None if it is acceptable (S22)."""
    if not isinstance(tool, dict):
        return "tool definition is not an object"
    violation = find_violation(tool)
    if violation:
        return violation
    if not isinstance(tool.get("name"), str) or not tool["name"]:
        return "tool has no name"
    for mapping in (tool, tool.get("inputSchema")):
        if isinstance(mapping, dict):
            alias = find_case_alias(mapping)
            if alias:
                return alias
    return None


# --- lockfile model -----------------------------------------------------------------------


class ToolStatus(StrEnum):
    APPROVED = "approved"
    PENDING = "pending"
    REVOKED = "revoked"


class ToolLabels(Model):
    produces: list[str] = Field(default_factory=list)


class Egress(Model):
    """Where a tool can send data (§6.1). Declared by a human, suggested by `agentguard lock`."""

    kind: Literal["network", "message"]
    destination_args: list[str] = Field(default_factory=list)
    payload_args: list[str] = Field(default_factory=list)


class LockedTool(Model):
    digest: str
    structural: str
    status: ToolStatus = ToolStatus.PENDING
    approved_at: str | None = None
    labels: ToolLabels = Field(default_factory=ToolLabels)
    egress: Egress | None = None


class LockedServer(Model):
    launch_digest: str | None = None
    tools: dict[str, LockedTool] = Field(default_factory=dict)


class LockFile(Model):
    lock_version: int = LOCK_VERSION
    servers: dict[str, LockedServer] = Field(default_factory=dict)

    def find(self, server: str, tool: str) -> LockedTool | None:
        locked_server = self.servers.get(server)
        return locked_server.tools.get(tool) if locked_server else None


def load_lock(path: Path) -> LockFile:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LockError(f"cannot read lockfile {path}: {exc}") from exc
    try:
        raw = load_yaml_strict(text)
        lock = LockFile.model_validate(raw if raw is not None else {})
    except (yaml.YAMLError, ValueError) as exc:
        raise LockError(f"invalid lockfile {path}: {exc}") from exc
    if lock.lock_version != LOCK_VERSION:
        raise LockError(f"unsupported lock_version {lock.lock_version}")
    return lock


def render_lock(lock: LockFile) -> str:
    """Deterministic text: keys and tools sorted, so Git diffs stay small."""
    data = lock.model_dump(mode="json")
    return yaml.safe_dump(data, sort_keys=True, allow_unicode=True, default_flow_style=False)


def save_lock(lock: LockFile, path: Path) -> None:
    path.write_text(render_lock(lock), encoding="utf-8")


def lock_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


# --- runtime check ------------------------------------------------------------------------


class Exposure(StrEnum):
    EXPOSED = "exposed"
    UNKNOWN = "unknown"  # not in the lockfile
    DRIFT_DESCRIPTION = "drift_description"  # only descriptive text changed
    DRIFT_STRUCTURE = "drift_structure"  # capability changed
    NOT_APPROVED = "not_approved"  # pending or revoked
    INVALID = "invalid"  # duplicate keys, case aliases, ...


def check_exposure(lock: LockFile, server: str, tool: Any) -> tuple[Exposure, str]:
    """Decide whether a tool as reported by its server may be shown to the client (§5.3)."""
    problem = validate_tool_definition(tool)
    if problem:
        return Exposure.INVALID, problem
    name = tool["name"]
    locked = lock.find(server, name)
    if locked is None:
        return Exposure.UNKNOWN, "tool is not in the lockfile"
    if locked.status is not ToolStatus.APPROVED:
        return Exposure.NOT_APPROVED, f"status is {locked.status.value}"
    if full_digest(tool) == locked.digest:
        return Exposure.EXPOSED, ""
    if structural_digest(tool) == locked.structural:
        return Exposure.DRIFT_DESCRIPTION, "only descriptive text changed"
    return Exposure.DRIFT_STRUCTURE, "tool structure changed"


# --- `agentguard lock` --------------------------------------------------------------------


class ChangeKind(StrEnum):
    NEW = "new"
    CHANGED = "changed"
    REMOVED = "removed"
    PENDING = "pending"  # unchanged but still waiting for approval
    LAUNCH_CHANGED = "launch_changed"


class Change(Model):
    kind: ChangeKind
    server: str
    tool: str | None = None
    detail: str = ""


def compute_changes(
    lock: LockFile,
    live: dict[str, list[dict[str, Any]]],
    launch_digests: dict[str, str],
) -> list[Change]:
    """Differences between the lockfile and what the servers report right now."""
    changes: list[Change] = []
    for server, tools in sorted(live.items()):
        locked_server = lock.servers.get(server)
        if locked_server and locked_server.launch_digest not in (None, launch_digests.get(server)):
            changes.append(Change(kind=ChangeKind.LAUNCH_CHANGED, server=server))
        live_names = set()
        for tool in tools:
            name = tool["name"]
            live_names.add(name)
            locked = lock.find(server, name)
            if locked is None:
                changes.append(Change(kind=ChangeKind.NEW, server=server, tool=name))
            elif full_digest(tool) != locked.digest:
                kind = "structure" if structural_digest(tool) != locked.structural else "description"
                changes.append(Change(kind=ChangeKind.CHANGED, server=server, tool=name, detail=kind))
            elif locked.status is not ToolStatus.APPROVED:
                changes.append(Change(kind=ChangeKind.PENDING, server=server, tool=name))
        if locked_server:
            for name in sorted(set(locked_server.tools) - live_names):
                changes.append(Change(kind=ChangeKind.REMOVED, server=server, tool=name))
    return changes


def update_lock(
    lock: LockFile,
    live: dict[str, list[dict[str, Any]]],
    launch_digests: dict[str, str],
) -> LockFile:
    """Return a new lock: new and changed tools become pending, vanished tools are removed."""
    servers: dict[str, LockedServer] = {}
    for server, tools in live.items():
        old_server = lock.servers.get(server)
        locked_tools: dict[str, LockedTool] = {}
        for tool in tools:
            name = tool["name"]
            old = old_server.tools.get(name) if old_server else None
            locked_tools[name] = _merge_tool(old, tool)
        servers[server] = LockedServer(
            launch_digest=launch_digests.get(server), tools=dict(sorted(locked_tools.items()))
        )
    return LockFile(servers=dict(sorted(servers.items())))


def _merge_tool(old: LockedTool | None, tool: dict[str, Any]) -> LockedTool:
    digest = full_digest(tool)
    if old is not None and old.digest == digest and old.status is not ToolStatus.PENDING:
        return old
    labels, egress = (old.labels, old.egress) if old else suggest_declarations(tool)
    return LockedTool(
        digest=digest,
        structural=structural_digest(tool),
        status=ToolStatus.PENDING,
        labels=labels,
        egress=egress,
    )


def approve(
    lock: LockFile,
    server: str | None = None,
    tool: str | None = None,
    live: dict[str, list[dict[str, Any]]] | None = None,
) -> list[str]:
    """Approve matching pending tools in place; return the approved tool ids.

    If `live` is given, a tool is approved only when the server still reports exactly the
    definition that is recorded in the lock, so nothing unreviewed slips in between."""
    approved: list[str] = []
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for server_name, locked_server in lock.servers.items():
        if server and server != server_name:
            continue
        live_digests = {
            definition["name"]: full_digest(definition) for definition in (live or {}).get(server_name, [])
        }
        for tool_name, locked in locked_server.tools.items():
            if tool and tool != tool_name:
                continue
            if live is not None and live_digests.get(tool_name) != locked.digest:
                continue
            if locked.status is ToolStatus.PENDING:
                locked.status = ToolStatus.APPROVED
                locked.approved_at = now
                approved.append(f"{server_name}/{tool_name}")
    return approved


# --- declaration suggestions --------------------------------------------------------------

_UNTRUSTED_SOURCE_WORDS = ("fetch", "search", "browse", "scrape", "crawl", "http")
_NETWORK_EGRESS_WORDS = ("fetch", "search", "browse", "http", "request", "download", "upload")
_MESSAGE_EGRESS_WORDS = ("send", "email", "mail", "post", "message", "notify", "publish")
_DESTINATION_ARGS = ("to", "cc", "bcc", "url", "uri", "recipient", "recipients", "address")
_PAYLOAD_ARGS = ("body", "subject", "text", "message", "content", "query", "q", "url", "data")


def suggest_declarations(tool: dict[str, Any]) -> tuple[ToolLabels, Egress | None]:
    """Guess `labels` and `egress` from names. A human must review the guess (§5.1)."""
    name = str(tool.get("name", "")).lower()
    properties = (tool.get("inputSchema") or {}).get("properties") or {}
    arg_names = [arg for arg in properties if isinstance(arg, str)]

    produces = ["untrusted"] if any(word in name for word in _UNTRUSTED_SOURCE_WORDS) else []

    if any(word in name for word in _MESSAGE_EGRESS_WORDS):
        kind: Literal["network", "message"] | None = "message"
    elif any(word in name for word in _NETWORK_EGRESS_WORDS):
        kind = "network"
    else:
        kind = None
    if kind is None:
        return ToolLabels(produces=produces), None

    egress = Egress(
        kind=kind,
        destination_args=[arg for arg in arg_names if arg.lower() in _DESTINATION_ARGS],
        payload_args=[arg for arg in arg_names if arg.lower() in _PAYLOAD_ARGS],
    )
    return ToolLabels(produces=produces), egress
