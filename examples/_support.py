"""Shared helpers for the examples: a throw-away workspace with fake MCP servers.

The fake servers are `tests/fixtures/servers/scripted.py` (synthetic data, local only).
Each example talks to a real `agentguard serve` process, like an MCP client would.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from agentguard.adapters.mcp.upstream import discover_tools
from agentguard.core.lock import LockFile, ToolLabels, approve, launch_digest, save_lock, update_lock
from agentguard.core.policy import parse_config

FAKE_SERVER = Path(__file__).parents[1] / "tests" / "fixtures" / "servers" / "scripted.py"

SECRET = (
    "Project Falcon launch budget is 4.2M USD. Board vote scheduled for March 3rd. "
    "Codename ORCHID-7731 must not leak outside the company."
)

FLOW = {
    "destinations": {"corp_mail": ["*@corp.example"], "corp_hosts": ["*.corp.example"]},
    "rules": [
        {
            "id": "FL-001",
            "from": ["confidential", "secret"],
            "to": {"kind": ["network", "message"]},
            "allow_destinations": ["corp_mail", "corp_hosts"],
            "on_value_match": "deny",
            "on_session_exposure": "require_approval",
        },
        {
            "id": "FL-002",
            "from": ["untrusted"],
            "to": {"tools": ["files__delete_*"]},
            "on_session_exposure": "require_approval",
        },
    ],
}


def tool(name: str, description: str = "a tool", **properties: str) -> dict[str, Any]:
    schema = {arg: {"type": kind} for arg, kind in properties.items()}
    return {"name": name, "description": description, "inputSchema": {"type": "object", "properties": schema}}


class Demo:
    """A workspace with fake servers, an approved lockfile and (after `start`) a running gateway."""

    def __init__(self, scripts: dict[str, dict[str, Any]], declarations: dict[str, dict[str, Any]]) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agentguard-demo-")
        self.root = Path(self._tmp.name)
        self.scripts = scripts
        self.config_path = self.root / "agentguard.yaml"
        self._process: subprocess.Popen[str] | None = None
        self._next_id = 0
        self._write_scripts()
        self._write_config()
        self._write_lock(declarations)

    def _write_scripts(self) -> None:
        for name, script in self.scripts.items():
            (self.root / f"{name}.yaml").write_text(yaml.safe_dump(script), encoding="utf-8")

    def _write_config(self) -> None:
        servers = {
            name: {
                "command": [
                    sys.executable,
                    str(FAKE_SERVER),
                    str(self.root / f"{name}.yaml"),
                    str(self.root / f"{name}.calls"),
                ]
            }
            for name in self.scripts
        }
        self.config_path.write_text(yaml.safe_dump({"servers": servers, "flow": FLOW}), encoding="utf-8")

    def _write_lock(self, declarations: dict[str, dict[str, Any]]) -> None:
        config = parse_config(self.config_path.read_text(encoding="utf-8"), base_dir=self.root)
        live, errors = asyncio.run(discover_tools(config.servers))
        assert not errors, errors
        digests = {name: launch_digest(cfg.command, cfg.url) for name, cfg in config.servers.items()}
        lock = update_lock(LockFile(), live, digests)
        for key, declared in declarations.items():
            server, tool_name = key.split("/")
            lock.servers[server].tools[tool_name].labels = ToolLabels(produces=declared.get("produces", []))
            lock.servers[server].tools[tool_name].egress = declared.get("egress")
        approve(lock)  # in real life: `agentguard lock`, review, `agentguard lock approve`
        save_lock(lock, self.root / "agentguard.lock")

    # --- gateway ---------------------------------------------------------------------------

    def rewrite_server(self, name: str, **changes: Any) -> None:
        """Change what a fake server reports from now on (simulates a rug-pull)."""
        self.scripts[name] = {**self.scripts[name], **changes}
        self._write_scripts()

    def start(self) -> None:
        self._process = subprocess.Popen(
            [sys.executable, "-m", "agentguard", "serve", "--config", str(self.config_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=self.root,
        )
        hello = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "demo", "version": "0"},
        }
        self.request("initialize", hello)

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self._process and self._process.stdin and self._process.stdout
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params or {}}
        self._process.stdin.write(json.dumps(message) + "\n")
        self._process.stdin.flush()
        while True:
            reply = json.loads(self._process.stdout.readline())
            if reply.get("id") == self._next_id:
                return reply

    def tools(self) -> list[str]:
        return sorted(t["name"] for t in self.request("tools/list")["result"]["tools"])

    def call(self, tool_name: str, **arguments: Any) -> dict[str, Any]:
        return self.request("tools/call", {"name": tool_name, "arguments": arguments})["result"]

    def receiver_saw(self, server: str) -> list[str]:
        """Tool calls that actually reached a fake server."""
        path = self.root / f"{server}.calls"
        if not path.exists():
            return []
        return [json.loads(line)["tool"] for line in path.read_text(encoding="utf-8").splitlines()]

    def audit(self, event: str) -> list[dict[str, Any]]:
        path = self.root / ".agentguard" / "audit.jsonl"
        entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        return [entry for entry in entries if entry["event"] == event]

    def stop(self) -> None:
        if self._process and self._process.stdin and not self._process.stdin.closed:
            self._process.stdin.close()
            self._process.wait(timeout=10)
        self._tmp.cleanup()


def outcome(result: dict[str, Any]) -> str:
    """One phrase for a tool result: ALLOWED, BLOCKED (with reason code) or NEEDS APPROVAL."""
    meta = result.get("_meta", {}).get("agentguard", {})
    if "approval_id" in meta:
        return f"NEEDS APPROVAL  ({meta['approval_id']})"
    if result.get("isError"):
        return f"BLOCKED         ({meta.get('reason_code', 'tool error')})"
    return "ALLOWED"


def say(label: str, text: str) -> None:
    print(f"  {label:<34} {text}")
