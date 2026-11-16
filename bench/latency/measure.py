"""Latency of a tool call: direct to the server vs through AgentGuard (§14.2).

    python bench/latency/measure.py [--calls 300]

Direct and gateway calls are interleaved against identical fake servers, so machine noise hits
both equally. Reports p50/p95/p99 of the added time. Two index states: empty, and loaded with
a large protected document (the scan has to slide windows over every argument).
The target is p95 < 20 ms over stdio. It is a target; this script is how you check it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT))

from agentguard.adapters.mcp.upstream import StdioUpstream, discover_tools  # noqa: E402
from agentguard.core.lock import (  # noqa: E402
    Egress,
    LockFile,
    ToolLabels,
    approve,
    launch_digest,
    save_lock,
    update_lock,
)
from agentguard.core.policy import parse_config  # noqa: E402

FAKE_SERVER = ROOT / "tests" / "fixtures" / "servers" / "scripted.py"
BIG_DOCUMENT = " ".join(f"record {n:07d}: confidential line of the protected report." for n in range(26000))


def tool(name: str, **props: str) -> dict[str, Any]:
    schema = {key: {"type": kind} for key, kind in props.items()}
    return {"name": name, "description": "t", "inputSchema": {"type": "object", "properties": schema}}


async def build_workspace(root: Path) -> Path:
    script = {
        "tools": [tool("read_document", path="string"), tool("notify", to="string", body="string")],
        "results": {"read_document": {"text": BIG_DOCUMENT}},
    }
    (root / "srv.yaml").write_text(yaml.safe_dump(script), encoding="utf-8")
    command = [sys.executable, str(FAKE_SERVER), str(root / "srv.yaml"), str(root / "calls.jsonl")]
    flow = {
        "destinations": {"corp": ["*@corp.example"]},
        "rules": [
            {
                "id": "FL-001", "from": ["confidential"], "to": {"kind": ["message"]},
                "allow_destinations": ["corp"], "on_session_exposure": "warn",
            }
        ],
    }  # fmt: skip
    config_path = root / "agentguard.yaml"
    config_path.write_text(
        yaml.safe_dump({"servers": {"srv": {"command": command}}, "flow": flow}), encoding="utf-8"
    )
    config = parse_config(config_path.read_text(encoding="utf-8"), base_dir=root)
    live, _ = await discover_tools(config.servers)
    lock = update_lock(LockFile(), live, {"srv": launch_digest(command, None)})
    lock.servers["srv"].tools["read_document"].labels = ToolLabels(produces=["confidential"])
    lock.servers["srv"].tools["notify"].egress = Egress(
        kind="message", destination_args=["to"], payload_args=["body"]
    )
    approve(lock)
    save_lock(lock, root / "agentguard.lock")
    return config_path


class GatewayClient:
    def __init__(self, config_path: Path) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-m", "agentguard", "serve", "--config", str(config_path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )  # fmt: skip
        self.next_id = 0
        self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "b", "version": "0"},
            },
        )

    def request(self, method: str, params: dict[str, Any]) -> None:
        assert self.process.stdin and self.process.stdout
        self.next_id += 1
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}) + "\n"
        )
        self.process.stdin.flush()
        while json.loads(self.process.stdout.readline()).get("id") != self.next_id:
            pass

    def close(self) -> None:
        assert self.process.stdin
        self.process.stdin.close()
        self.process.wait(timeout=10)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


async def measure(calls: int, loaded: bool) -> list[float]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config_path = await build_workspace(root)
        config = parse_config(config_path.read_text(encoding="utf-8"), base_dir=root)
        direct = StdioUpstream("srv", config.servers["srv"])
        await direct.start()
        await direct.initialize()
        gateway = GatewayClient(config_path)
        arguments = {"to": "someone@elsewhere.example", "body": "weekly status: all green, nothing to report"}
        if loaded:
            gateway.request("tools/call", {"name": "srv__read_document", "arguments": {"path": "x"}})
        for _ in range(20):  # warm-up
            gateway.request("tools/call", {"name": "srv__notify", "arguments": arguments})
            await direct.call_tool("notify", arguments, 30)

        added: list[float] = []
        for _ in range(calls):
            start = time.perf_counter()
            await direct.call_tool("notify", arguments, 30)
            direct_time = time.perf_counter() - start
            start = time.perf_counter()
            gateway.request("tools/call", {"name": "srv__notify", "arguments": arguments})
            added.append((time.perf_counter() - start - direct_time) * 1000)
        gateway.close()
        await direct.close()
        return added


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls", type=int, default=300)
    calls = parser.parse_args().calls
    print(f"stdio, {calls} paired calls, added latency in ms (gateway minus direct)")
    for label, loaded in (("index empty", False), ("index loaded (~1.5 MB protected doc)", True)):
        added = asyncio.run(measure(calls, loaded))
        print(
            f"  {label:<40} p50={statistics.median(added):6.2f}  p95={percentile(added, 0.95):6.2f}"
            f"  p99={percentile(added, 0.99):6.2f}"
        )


if __name__ == "__main__":
    main()
