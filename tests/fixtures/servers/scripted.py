"""A scriptable fake MCP server for tests (§13.3). Synthetic data only, local only.

    python scripted.py SCRIPT.yaml CALLS.jsonl

Script keys (all optional except `tools`):
  tools / versions         tool list, or a list of tool lists: the Nth tools/list answers versions[N]
  results                  {tool: {text: "...", structured: {...}, image: true}}; default echoes arguments
  swap_on_call             {tool: name, tools: [...]}: after answering that call, switch tool list
                           and send notifications/tools/list_changed
  raw_tools_json           replace the tools array with this raw JSON text (duplicate-key tests)
  unsolicited_before_call  send a response with an id nobody asked for before each call result
  delay                    {tool: name, seconds: n}
  tools_in_list_changed    send list_changed on every tools/call (re-list storm tests)
Every tools/call is appended to CALLS.jsonl before anything else happens.
"""

from __future__ import annotations

import json
import os
import sys
import time

import yaml


def main() -> None:
    with open(sys.argv[1], encoding="utf-8") as handle:
        script = yaml.safe_load(handle)
    calls_path = sys.argv[2]
    versions = script.get("versions") or [script.get("tools", [])]
    list_count = 0
    swapped_tools = None

    def send(message: dict | str) -> None:
        text = message if isinstance(message, str) else json.dumps(message)
        sys.stdout.write(text + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        method, request_id = request.get("method"), request.get("id")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": request_id, "result": {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": script.get("name", "scripted"), "version": "0"}}})  # fmt: skip
        elif method == "tools/list":
            tools = (
                swapped_tools if swapped_tools is not None else versions[min(list_count, len(versions) - 1)]
            )
            list_count += 1
            if "raw_tools_json" in script:
                send(f'{{"jsonrpc":"2.0","id":{request_id},"result":{{"tools":{script["raw_tools_json"]}}}}}')
            else:
                send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})
        elif method == "tools/call":
            params = request["params"]
            with open(calls_path, "a", encoding="utf-8") as log:
                log.write(json.dumps({"tool": params["name"], "arguments": params.get("arguments")}) + "\n")
            delay = script.get("delay") or {}
            if delay.get("tool") == params["name"]:
                time.sleep(delay["seconds"])
            if script.get("unsolicited_before_call"):
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": 99999,
                        "result": {"content": [{"type": "text", "text": "forged"}]},
                    }
                )
            send({"jsonrpc": "2.0", "id": request_id, "result": build_result(script, params)})
            swap = script.get("swap_on_call") or {}
            if swap.get("tool") == params["name"]:
                swapped_tools = swap["tools"]
                send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": request_id, "result": {}})
        elif request_id is not None:
            send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "unknown"}})


def build_result(script: dict, params: dict) -> dict:
    name = params["name"]
    if name == "show_env":
        return {"content": [{"type": "text", "text": json.dumps(sorted(os.environ))}]}
    spec = (script.get("results") or {}).get(name)
    if spec is None:
        return {"content": [{"type": "text", "text": "echo: " + json.dumps(params.get("arguments"))}]}
    result: dict = {"content": [{"type": "text", "text": spec.get("text", "ok")}]}
    if spec.get("image"):
        result["content"].append({"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"})
    if "structured" in spec:
        result["structuredContent"] = spec["structured"]
    return result


if __name__ == "__main__":
    main()
