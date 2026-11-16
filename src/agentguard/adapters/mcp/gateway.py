"""The MCP gateway: one stdio client in front of several downstream servers (§10).

Exposes only tools that the lockfile approves, under `server__tool` names, and runs every
call through `Guard`. Resources, prompts and every other request are refused in v0.1.
"""

from __future__ import annotations

import asyncio
import io
import logging
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
from mcp.types import LATEST_PROTOCOL_VERSION

from agentguard import __version__
from agentguard.adapters.mcp.frames import (
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    FrameError,
    encode,
    is_notification,
    is_request,
    make_error,
    make_notification,
    make_response,
    new_stream_reader,
    parse_message,
    read_line,
)
from agentguard.adapters.mcp.upstream import (
    RpcError,
    Upstream,
    UpstreamError,
    UpstreamTimeout,
    create_upstream,
)
from agentguard.core.canonical import to_plain
from agentguard.core.guard import Guard
from agentguard.core.lock import launch_digest
from agentguard.core.models import (
    Decision,
    Reason,
    ToolCall,
    Verdict,
    make_tool_id,
    split_tool_id,
)

log = logging.getLogger("agentguard.gateway")

CONFIG_POLL_SECONDS = 2.0


def blocked_result(verdict: Verdict) -> dict[str, Any]:
    """Tool error for a denied or pending call. It names the reason code, not the rule."""
    if verdict.decision is Decision.REQUIRE_APPROVAL:
        text = (
            f"Human confirmation required (approval {verdict.approval_id}). Tell the user to run "
            f"`agentguard approve {verdict.approval_id}`, then retry the same call."
        )
    else:
        text = f"AgentGuard blocked this call ({verdict.reason_code}). Details are in the audit log."
    meta = {"reason_code": verdict.reason_code}
    if verdict.approval_id:
        meta["approval_id"] = verdict.approval_id
    return {
        "isError": True,
        "content": [{"type": "text", "text": text}],
        "_meta": {"agentguard": meta},
    }


def error_result(reason_code: str, text: str) -> dict[str, Any]:
    return {
        "isError": True,
        "content": [{"type": "text", "text": f"{text} ({reason_code})"}],
        "_meta": {"agentguard": {"reason_code": reason_code}},
    }


class Gateway:
    def __init__(
        self,
        guard: Guard,
        upstreams: dict[str, Upstream],
        send: Callable[[bytes], None],
        config_path: Path | None = None,
        poll_seconds: float = CONFIG_POLL_SECONDS,
    ) -> None:
        self.guard = guard
        self.upstreams = upstreams
        self._send = send
        self._config_path = config_path
        self._poll_seconds = poll_seconds
        self.session = guard.open_session()
        self._raw_tools: dict[str, list[Any]] = {}
        self._exposed_tools: dict[str, list[dict[str, Any]]] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._background: list[asyncio.Task[None]] = []
        for name, upstream in upstreams.items():
            upstream.on_notification = self._make_notification_handler(name)
            upstream.on_unsolicited = self._make_unsolicited_handler(name)

    # --- startup and shutdown -------------------------------------------------------------

    async def start(self) -> None:
        results = await asyncio.gather(
            *(self._start_upstream(name) for name in self.upstreams), return_exceptions=True
        )
        for name, result in zip(self.upstreams, results, strict=True):
            if isinstance(result, BaseException):
                log.error("server %s is unavailable: %s", name, result)
                self.guard.record_event("upstream.error", self.session, server=name, detail=str(result)[:200])
                self._raw_tools[name] = []
                self._publish_exposed(name)
        self._background = [asyncio.create_task(self._watch())]

    async def _start_upstream(self, name: str) -> None:
        upstream = self.upstreams[name]
        await upstream.start()
        await upstream.initialize()
        await self.refresh_server(name)

    async def close(self) -> None:
        for task in self._background:
            task.cancel()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._background, *self._tasks, return_exceptions=True)
        await asyncio.gather(*(u.close() for u in self.upstreams.values()), return_exceptions=True)

    # --- tool exposure --------------------------------------------------------------------

    async def refresh_server(self, name: str) -> bool:
        """Re-read one server's tools and re-check them against the lockfile.
        Returns True if the set of exposed tools changed."""
        self._raw_tools[name] = await self.upstreams[name].list_tools(self.guard.config.call_timeout_seconds)
        return self._publish_exposed(name)

    def _publish_exposed(self, name: str) -> bool:
        server_config = self.guard.config.servers.get(name)
        launch_ok = True
        if server_config is not None:
            expected = self.guard.lock.servers.get(name)
            actual = launch_digest(server_config.command, server_config.url)
            launch_ok = expected is None or expected.launch_digest in (None, actual)
        exposed = self.guard.filter_tools(name, self._raw_tools.get(name, []), launch_ok)
        changed = exposed != self._exposed_tools.get(name)
        self._exposed_tools[name] = exposed
        return changed

    def _make_notification_handler(self, name: str) -> Callable[[str, dict[str, Any]], Any]:
        async def handle(method: str, params: dict[str, Any]) -> None:
            if method == "notifications/tools/list_changed":
                self._spawn(self._refresh_and_announce(name))

        return handle

    def _make_unsolicited_handler(self, name: str) -> Callable[[dict[str, Any]], None]:
        def handle(message: dict[str, Any]) -> None:
            self.guard.record_event(
                "response.unsolicited",
                self.session,
                server=name,
                response_id=str(message.get("id"))[:40],
            )

        return handle

    async def _refresh_and_announce(self, name: str) -> None:
        try:
            if await self.refresh_server(name):
                self._announce_tools_changed()
        except UpstreamError as exc:
            log.warning("could not refresh tools of %s: %s", name, exc)

    def _announce_tools_changed(self) -> None:
        self._send(encode(make_notification("notifications/tools/list_changed")))

    async def _watch(self) -> None:
        """Poll for config/lock edits and, on a timer, re-check every server's tools."""
        interval = self._poll_seconds
        last_recheck = asyncio.get_running_loop().time()
        stamps = self._file_stamps()
        while True:
            await asyncio.sleep(interval)
            if self._config_path and (current := self._file_stamps()) != stamps:
                stamps = current
                if self.guard.reload(self._config_path):
                    for name in self.upstreams:
                        self._publish_exposed(name)
                    self._announce_tools_changed()
            recheck = self.guard.config.tools_recheck_seconds
            now = asyncio.get_running_loop().time()
            if recheck is not None and now - last_recheck >= recheck:
                last_recheck = now
                await asyncio.gather(*(self._refresh_and_announce(name) for name in self.upstreams))

    def _file_stamps(self) -> tuple[float, ...]:
        if not self._config_path:
            return ()
        paths = [self._config_path, self.guard.config.resolve(self.guard.config.lock)]
        return tuple(path.stat().st_mtime if path.exists() else 0.0 for path in paths)

    # --- client side ----------------------------------------------------------------------

    async def serve(self, reader: asyncio.StreamReader) -> None:
        """Read client frames until end of input; each request is handled in its own task."""
        while True:
            try:
                line = await read_line(reader)
                if line is None:
                    break
                message = parse_message(line)
            except FrameError as exc:
                self._reject_frame(exc)
                continue
            if message is not None:
                self._spawn(self.handle(message))
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    def _reject_frame(self, error: FrameError) -> None:
        self.guard.record_event("request.rejected", self.session, reason=error.reason, code=error.code)
        self._send(encode(make_error(error.request_id, error.code, f"invalid message: {error.reason}")))

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def handle(self, message: dict[str, Any]) -> None:
        if is_notification(message):
            return  # initialized, cancelled, ... nothing to do in v0.1
        if not is_request(message):
            return  # a response to a request we never sent
        request_id, method = message["id"], message["method"]
        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        try:
            reply = await self._route(request_id, method, params)
        except Exception:
            log.exception("request %s failed", method)
            reply = make_error(request_id, -32603, "internal error")
        self._send(encode(reply))

    async def _route(self, request_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return make_response(request_id, self._initialize_result(params))
        if method == "ping":
            return make_response(request_id, {})
        if method == "tools/list":
            return make_response(request_id, {"tools": self._client_tool_list()})
        if method == "tools/call":
            return await self._tools_call(request_id, params)
        self.guard.record_event(
            "request.rejected", self.session, reason="unsupported method", method=method[:80]
        )
        return make_error(request_id, METHOD_NOT_FOUND, "this method is not available through AgentGuard")

    def _initialize_result(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "agentguard", "version": __version__},
        }

    def _client_tool_list(self) -> list[dict[str, Any]]:
        tools = []
        for server in sorted(self._exposed_tools):
            for tool in self._exposed_tools[server]:
                tools.append({**tool, "name": make_tool_id(server, tool["name"])})
        return tools

    async def _tools_call(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        name, arguments = params.get("name"), params.get("arguments")
        if not isinstance(name, str) or not (arguments is None or isinstance(arguments, dict)):
            return make_error(request_id, INVALID_PARAMS, "tools/call needs a name and object arguments")

        call = ToolCall(tool_id=name, args=to_plain(arguments or {}), call_id=self.session.next_call_id())
        verdict = self.guard.before_call(self.session, call)
        if verdict.decision in (Decision.DENY, Decision.REQUIRE_APPROVAL):
            return make_response(request_id, blocked_result(verdict))

        parts = split_tool_id(name)
        if parts is None or parts[0] not in self.upstreams:
            return make_error(request_id, INVALID_PARAMS, f"unknown tool {name}")
        server, tool = parts
        try:
            result = await self.upstreams[server].call_tool(
                tool, arguments, self.guard.config.call_timeout_seconds
            )
        except RpcError as exc:
            return make_error(request_id, exc.code, exc.message)
        except UpstreamTimeout:
            return make_response(
                request_id, error_result(Reason.UPSTREAM_TIMEOUT, "The tool did not answer in time")
            )
        except UpstreamError as exc:
            log.warning("call to %s failed: %s", name, exc)
            return make_response(request_id, error_result(Reason.UPSTREAM_ERROR, "The tool server failed"))

        labeled = self.guard.after_call(self.session, call, result)
        return make_response(request_id, labeled.result)


def _stdout_writer() -> Callable[[bytes], None]:
    def write(data: bytes) -> None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    return write


def _feed_from_stdin(loop: asyncio.AbstractEventLoop, reader: asyncio.StreamReader) -> None:
    """Runs in a thread: blocking stdin reads work the same on every OS, including Windows."""
    stream = cast(io.BufferedReader, sys.stdin.buffer)
    while chunk := stream.read1(65536):
        loop.call_soon_threadsafe(reader.feed_data, chunk)
    loop.call_soon_threadsafe(reader.feed_eof)


async def run_stdio(config_path: Path, poll_seconds: float = CONFIG_POLL_SECONDS) -> None:
    """Serve one MCP client on stdin/stdout until it disconnects."""
    guard = Guard.from_files(config_path)
    upstreams = {name: create_upstream(name, cfg) for name, cfg in guard.config.servers.items()}
    gateway = Gateway(guard, upstreams, _stdout_writer(), config_path, poll_seconds)

    loop = asyncio.get_running_loop()
    reader = new_stream_reader()
    threading.Thread(target=_feed_from_stdin, args=(loop, reader), daemon=True).start()
    await gateway.start()
    try:
        await gateway.serve(reader)
    finally:
        await gateway.close()
