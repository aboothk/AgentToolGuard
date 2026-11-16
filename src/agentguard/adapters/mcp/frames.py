"""Newline-delimited JSON-RPC framing with strict limits (§7.3, §10.3).

Written by hand on top of raw bytes because the checks need to happen before any parsing
convenience: batches (S20), duplicate keys (S22), the 10 MiB line limit and depth limit.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agentguard.core.canonical import (
    InvalidJson,
    RawNumber,
    canonical_dumps,
    find_violation,
    loads_strict,
    to_plain,
)

MAX_FRAME_BYTES = 10 * 1024 * 1024

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class FrameError(Exception):
    """A frame that must be rejected. `code` is the JSON-RPC error code to answer with."""

    def __init__(self, reason: str, code: int = INVALID_REQUEST, request_id: Any = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code
        self.request_id = request_id  # echoed in the error reply when the frame parsed far enough


async def read_line(reader: asyncio.StreamReader) -> bytes | None:
    """Return the next line without its newline, or None at end of stream.

    An over-long line is discarded in full and reported as FrameError, so the stream stays
    usable for the next message.
    """
    try:
        line = await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:  # end of stream; a last line may lack "\n"
        return exc.partial or None
    except asyncio.LimitOverrunError as exc:
        await _discard_rest_of_line(reader, exc.consumed)
        raise FrameError("frame exceeds the size limit", INVALID_REQUEST) from exc
    return line.rstrip(b"\r\n")


async def _discard_rest_of_line(reader: asyncio.StreamReader, already_buffered: int) -> None:
    await reader.readexactly(already_buffered)
    while True:
        try:
            await reader.readuntil(b"\n")
            return
        except asyncio.LimitOverrunError as exc:
            await reader.readexactly(exc.consumed)
        except asyncio.IncompleteReadError:
            return


def new_stream_reader() -> asyncio.StreamReader:
    return asyncio.StreamReader(limit=MAX_FRAME_BYTES)


def parse_message(line: bytes, check_violations: bool = True) -> dict[str, Any] | None:
    """Parse one frame. Returns None for a blank line, raises FrameError for a bad frame.

    With `check_violations=False` duplicate keys are left for the caller to judge. The upstream
    side needs this to reject a single bad tool instead of losing the whole tools/list reply."""
    if not line.strip():
        return None
    if len(line) > MAX_FRAME_BYTES:
        raise FrameError("frame exceeds the size limit")
    try:
        message = loads_strict(line)
    except InvalidJson as exc:
        raise FrameError(str(exc), PARSE_ERROR) from exc
    if isinstance(message, list):
        raise FrameError("batch requests are not accepted")
    if not isinstance(message, dict):
        raise FrameError("a message must be a JSON object")
    request_id = message.get("id") if isinstance(message.get("id"), str | int | RawNumber) else None
    violation = find_violation(message) if check_violations else None
    if violation:
        raise FrameError(violation, request_id=request_id)
    if message.get("jsonrpc") != "2.0":
        raise FrameError("missing jsonrpc: 2.0", request_id=request_id)
    return message


def encode(message: dict[str, Any]) -> bytes:
    """Serialize without changing content (no key sorting, no Unicode normalization)."""
    return (canonical_dumps(message, sort_keys=False, nfc=False) + "\n").encode("utf-8")


# --- message shapes -----------------------------------------------------------------------


def is_request(message: dict[str, Any]) -> bool:
    return "method" in message and "id" in message


def is_notification(message: dict[str, Any]) -> bool:
    return "method" in message and "id" not in message


def is_response(message: dict[str, Any]) -> bool:
    return "method" not in message and "id" in message and ("result" in message or "error" in message)


def message_id(message: dict[str, Any]) -> Any:
    """The `id` as a plain value (JSON numbers are parsed as RawNumber), for matching."""
    return to_plain(message.get("id"))


def make_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def make_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def make_notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    return message
