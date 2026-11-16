"""Streamable HTTP downstream transport, tested with an in-memory HTTP transport."""

from __future__ import annotations

import json

import httpx
import pytest

from agentguard.adapters.mcp.upstream import HttpUpstream, RpcError, UpstreamError
from agentguard.core.policy import ServerConfig


def sse(*messages: dict) -> bytes:  # type: ignore[type-arg]
    return b"".join(b"event: message\ndata: " + json.dumps(m).encode() + b"\n\n" for m in messages)


def make_handler(seen: list[httpx.Request]):  # type: ignore[no-untyped-def]
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        method, request_id = body.get("method"), body.get("id")
        if method == "initialize":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": "2025-06-18"}},
                headers={"mcp-session-id": "sess-1"},
            )  # fmt: skip
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            reply = {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [{"name": "send"}]}}
            note = {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}
            forged = {"jsonrpc": "2.0", "id": 4242, "result": {}}
            return httpx.Response(
                200, content=sse(note, forged, reply), headers={"content-type": "text/event-stream"}
            )
        if method == "tools/call" and body["params"]["name"] == "boom":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": "bad"}}
            )
        if method == "tools/call":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": request_id, "result": {"content": []}})
        return httpx.Response(500)

    return handler


async def test_http_upstream_handshake_listing_calls_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAIL_TOKEN", "t0ken")
    seen: list[httpx.Request] = []
    config = ServerConfig(url="http://mail.test/mcp", auth_env="MAIL_TOKEN")
    upstream = HttpUpstream("mail", config, transport=httpx.MockTransport(make_handler(seen)))
    unsolicited: list[dict] = []  # type: ignore[type-arg]
    upstream.on_unsolicited = unsolicited.append

    await upstream.start()
    await upstream.initialize()
    assert [t["name"] for t in await upstream.list_tools()] == ["send"]
    assert (await upstream.call_tool("send", {"to": "x"}, 5)) == {"content": []}
    with pytest.raises(RpcError):
        await upstream.call_tool("boom", {}, 5)
    await upstream.close()

    assert all(r.headers["authorization"] == "Bearer t0ken" for r in seen)
    assert seen[-1].headers["mcp-session-id"] == "sess-1"  # session id is echoed back
    assert [int(m["id"]) for m in unsolicited] == [4242]  # the forged id was reported, not delivered


async def test_http_upstream_requires_its_token_and_reports_http_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MAIL_TOKEN", raising=False)
    with pytest.raises(UpstreamError, match="MAIL_TOKEN"):
        HttpUpstream("mail", ServerConfig(url="http://x.test/", auth_env="MAIL_TOKEN"))
    upstream = HttpUpstream(
        "m", ServerConfig(url="http://x.test/"), transport=httpx.MockTransport(lambda r: httpx.Response(500))
    )
    with pytest.raises(UpstreamError, match="500"):
        await upstream.request("tools/list", None, 5)
    await upstream.close()
