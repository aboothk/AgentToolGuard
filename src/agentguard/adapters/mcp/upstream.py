"""Connections to downstream MCP servers (§10.1).

Two transports behind one small interface: a stdio subprocess and Streamable HTTP.
Request IDs are issued here and every response must match one that is still waiting;
anything else is dropped and reported (S21).
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import os
import shutil
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from agentguard import __version__
from agentguard.adapters.mcp.frames import (
    MAX_FRAME_BYTES,
    FrameError,
    encode,
    is_notification,
    is_request,
    is_response,
    make_error,
    make_notification,
    make_response,
    message_id,
    parse_message,
    read_line,
)
from agentguard.adapters.mcp.protocol import LATEST_PROTOCOL_VERSION
from agentguard.core.canonical import find_violation
from agentguard.core.policy import ServerConfig

log = logging.getLogger("agentguard.upstream")

MAX_LIST_PAGES = 50
# Only these variables are passed to a downstream server (plus its own `env:` entries).
INHERITED_ENV = {
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP",
    "TMPDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "LANG",
    "LC_ALL", "USER", "USERNAME", "LOGNAME", "SHELL", "TERM",
}  # fmt: skip

NotificationHandler = Callable[[str, dict[str, Any]], Awaitable[None]]
UnsolicitedHandler = Callable[[dict[str, Any]], None]


class UpstreamError(Exception):
    """The downstream server failed, closed, or sent something unusable."""


class UpstreamTimeout(UpstreamError):
    pass


class RpcError(Exception):
    """The downstream server answered with a JSON-RPC error."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def safe_environment(extra: dict[str, str]) -> dict[str, str]:
    """A filtered copy of our environment. The gateway's own secrets are not passed on."""
    inherited = {k: v for k, v in os.environ.items() if k.upper() in INHERITED_ENV}
    return {**inherited, **extra}


class Upstream:
    """Common behaviour: tool listing with pagination and the initialize handshake."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.on_notification: NotificationHandler | None = None
        self.on_unsolicited: UnsolicitedHandler | None = None

    async def start(self) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    async def request(
        self,
        method: str,
        params: dict[str, Any] | None,
        timeout: float,
        tolerate_violations: bool = False,
    ) -> dict[str, Any]:
        raise NotImplementedError

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise NotImplementedError

    async def initialize(self, timeout: float = 30) -> None:
        await self.request(
            "initialize",
            {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agentguard", "version": __version__},
            },
            timeout,
        )
        await self.notify("notifications/initialized")

    async def list_tools(self, timeout: float = 30) -> list[Any]:
        """All tools the server reports, following pagination. Entries are unvalidated."""
        tools: list[Any] = []
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            params = {"cursor": cursor} if cursor else None
            result = await self.request("tools/list", params, timeout, tolerate_violations=True)
            page = result.get("tools")
            if isinstance(page, list):
                tools.extend(page)
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor:
                break
        return tools

    async def call_tool(self, name: str, arguments: Any, timeout: float) -> dict[str, Any]:
        params: dict[str, Any] = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        return await self.request("tools/call", params, timeout)

    def _check_response(self, message: dict[str, Any], tolerate_violations: bool) -> dict[str, Any]:
        """Turn a matched response into its result, or raise."""
        if "error" in message:
            error = message["error"] if isinstance(message["error"], dict) else {}
            raise RpcError(int(error.get("code", -32603)), str(error.get("message", "error")))
        if not tolerate_violations and (reason := find_violation(message)):
            raise UpstreamError(f"invalid response from {self.name}: {reason}")
        result = message.get("result")
        return result if isinstance(result, dict) else {}


# --- stdio --------------------------------------------------------------------------------


class StdioUpstream(Upstream):
    def __init__(self, name: str, config: ServerConfig) -> None:
        super().__init__(name)
        assert config.command is not None
        self._command = config.command
        self._env = config.env
        self._process: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._ids = itertools.count(1)
        self._waiting: dict[int, tuple[asyncio.Future[dict[str, Any]], bool]] = {}

    async def start(self) -> None:
        executable = shutil.which(self._command[0]) or self._command[0]
        try:
            self._process = await asyncio.create_subprocess_exec(
                executable,
                *self._command[1:],
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                env=safe_environment(self._env),
                limit=MAX_FRAME_BYTES,
            )
        except OSError as exc:
            raise UpstreamError(f"cannot start {self.name}: {exc}") from exc
        self._reader_task = asyncio.create_task(self._read_loop())

    async def close(self) -> None:
        process = self._process
        if process is None:
            return
        if process.stdin and not process.stdin.is_closing():
            process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except TimeoutError:
            process.kill()
            await process.wait()
        if self._reader_task:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
        self._fail_all("connection closed")

    async def _write(self, message: dict[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None or process.stdin.is_closing():
            raise UpstreamError(f"{self.name} is not running")
        try:
            process.stdin.write(encode(message))
            await process.stdin.drain()
        except (ConnectionError, OSError) as exc:
            raise UpstreamError(f"{self.name} closed its input: {exc}") from exc

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        await self._write(make_notification(method, params))

    async def request(
        self,
        method: str,
        params: dict[str, Any] | None,
        timeout: float,
        tolerate_violations: bool = False,
    ) -> dict[str, Any]:
        request_id = next(self._ids)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._waiting[request_id] = (future, tolerate_violations)
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        try:
            await self._write(message)
            return await asyncio.wait_for(future, timeout)
        except TimeoutError as exc:
            raise UpstreamTimeout(f"{self.name} did not answer {method} in {timeout}s") from exc
        finally:
            self._waiting.pop(request_id, None)  # a late answer is now "unsolicited"

    def _fail_all(self, reason: str) -> None:
        for future, _ in self._waiting.values():
            if not future.done():
                future.set_exception(UpstreamError(f"{self.name}: {reason}"))
        self._waiting.clear()

    async def _read_loop(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        stream = self._process.stdout
        while True:
            try:
                line = await read_line(stream)
                if line is None:
                    break
                message = parse_message(line, check_violations=False)
            except FrameError as exc:
                log.warning("dropping bad frame from %s: %s", self.name, exc.reason)
                continue
            except (ConnectionError, OSError):
                break
            if message is not None:
                await self._dispatch(message)
        self._fail_all("connection closed")

    async def _dispatch(self, message: dict[str, Any]) -> None:
        if not is_response(message) and find_violation(message):
            log.warning("dropping message with duplicate keys from %s", self.name)
            return
        if is_response(message):
            self._deliver_response(message)
        elif is_notification(message):
            if self.on_notification:
                params = message.get("params")
                await self.on_notification(str(message["method"]), params if isinstance(params, dict) else {})
        elif is_request(message):
            await self._answer_server_request(message)

    def _deliver_response(self, message: dict[str, Any]) -> None:
        response_id = message_id(message)
        entry = self._waiting.pop(response_id, None) if isinstance(response_id, int) else None
        if entry is None:
            if self.on_unsolicited:
                self.on_unsolicited(message)
            return
        future, tolerate = entry
        if future.done():
            return
        try:
            future.set_result(self._check_response(message, tolerate))
        except (RpcError, UpstreamError) as exc:
            future.set_exception(exc)

    async def _answer_server_request(self, message: dict[str, Any]) -> None:
        """Downstream servers may ask the client for things; v0.1 answers only `ping`."""
        if message["method"] == "ping":
            reply = make_response(message["id"], {})
        else:
            reply = make_error(message["id"], -32601, "AgentGuard does not support this request")
        with contextlib.suppress(UpstreamError):
            await self._write(reply)


# --- Streamable HTTP ----------------------------------------------------------------------


class HttpUpstream(Upstream):
    def __init__(
        self,
        name: str,
        config: ServerConfig,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(name)
        assert config.url is not None
        self._url = config.url
        self._headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if config.auth_env:
            token = os.environ.get(config.auth_env)
            if not token:
                raise UpstreamError(f"environment variable {config.auth_env} is not set")
            self._headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(transport=transport, follow_redirects=False)
        self._ids = itertools.count(1)

    async def start(self) -> None:
        return None

    async def close(self) -> None:
        await self._client.aclose()

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        response = await self._post(make_notification(method, params), timeout=30)
        await response.aclose()

    async def _post(self, message: dict[str, Any], timeout: float) -> httpx.Response:
        try:
            request = self._client.build_request(
                "POST", self._url, content=encode(message), headers=self._headers, timeout=timeout
            )
            response = await self._client.send(request, stream=True)
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout(f"{self.name} did not answer in {timeout}s") from exc
        except httpx.HTTPError as exc:
            raise UpstreamError(f"{self.name}: {exc}") from exc
        if session_id := response.headers.get("mcp-session-id"):
            self._headers["Mcp-Session-Id"] = session_id
        if response.status_code >= 400:
            await response.aclose()
            raise UpstreamError(f"{self.name} returned HTTP {response.status_code}")
        return response

    async def request(
        self,
        method: str,
        params: dict[str, Any] | None,
        timeout: float,
        tolerate_violations: bool = False,
    ) -> dict[str, Any]:
        request_id = next(self._ids)
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        response = await self._post(message, timeout)
        try:
            async with asyncio.timeout(timeout):
                return await self._read_answer(response, request_id, tolerate_violations)
        except TimeoutError as exc:
            raise UpstreamTimeout(f"{self.name} did not answer {method} in {timeout}s") from exc
        finally:
            await response.aclose()

    async def _read_answer(
        self, response: httpx.Response, request_id: int, tolerate_violations: bool
    ) -> dict[str, Any]:
        content_type = response.headers.get("content-type", "")
        bodies = _sse_events(response) if "text/event-stream" in content_type else _single_body(response)
        async for body in bodies:
            try:
                parsed = parse_message(body, check_violations=False)
            except FrameError as exc:
                log.warning("dropping bad frame from %s: %s", self.name, exc.reason)
                continue
            if parsed is None:
                continue
            if is_response(parsed) and message_id(parsed) == request_id:
                return self._check_response(parsed, tolerate_violations)
            if is_response(parsed):
                if self.on_unsolicited:
                    self.on_unsolicited(parsed)
            elif is_notification(parsed) and self.on_notification and not find_violation(parsed):
                params = parsed.get("params")
                await self.on_notification(str(parsed["method"]), params if isinstance(params, dict) else {})
        raise UpstreamError(f"{self.name} ended the stream without answering")


async def _single_body(response: httpx.Response) -> Any:
    yield await response.aread()


async def _sse_events(response: httpx.Response) -> Any:
    """Yield the `data:` payload of each server-sent event."""
    data_lines: list[str] = []
    async for line in response.aiter_lines():
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
        elif not line and data_lines:
            yield "\n".join(data_lines).encode("utf-8")
            data_lines = []
    if data_lines:
        yield "\n".join(data_lines).encode("utf-8")


def create_upstream(name: str, config: ServerConfig) -> Upstream:
    return StdioUpstream(name, config) if config.command is not None else HttpUpstream(name, config)


async def discover_tools(
    servers: dict[str, ServerConfig], timeout: float = 30
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    """Connect to every server, list its tools, disconnect. Used by `agentguard lock`.

    Returns (valid tool definitions per server, errors per server). Tools that fail
    validation (duplicate keys, case aliases) are left out and reported as errors."""
    from agentguard.core.lock import validate_tool_definition

    live: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, str] = {}
    for name, config in servers.items():
        upstream = create_upstream(name, config)
        try:
            await upstream.start()
            await upstream.initialize(timeout)
            raw_tools = await upstream.list_tools(timeout)
        except (UpstreamError, RpcError) as exc:
            errors[name] = str(exc)
            continue
        finally:
            await upstream.close()
        live[name] = []
        for tool in raw_tools:
            problem = validate_tool_definition(tool)
            if problem:
                label = tool.get("name") if isinstance(tool, dict) else "?"
                errors[f"{name}/{label}"] = f"rejected: {problem}"
            else:
                live[name].append(tool)
    return live, errors
