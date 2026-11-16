"""Local tool definitions, JSON-safe conversion, lockfile scope for `local`, import rules (section 11.2)."""

from __future__ import annotations

import ast
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.core.lock import LockFile, ToolStatus, approve, load_lock, update_lock
from agentguard.core.policy import ConfigError, parse_config
from agentguard.sdk import load_python_tools, tool_definition
from agentguard.sdk.local_tools import to_jsonable
from tests.integration.conftest import SCRIPTED, tool_def

SRC = Path(__file__).parents[2] / "src" / "agentguard"
runner = CliRunner()


def example(
    to: str, body: str = "x", count: int = 1, tags: list[str] | None = None, flag: bool | None = None
) -> str:  # noqa: UP007
    """Example tool."""
    return to


def test_definition_is_a_plain_deterministic_structure() -> None:
    assert tool_definition(example, "example") == {
        "name": "example",
        "description": "Example tool.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "body": {"type": "string"},
                "count": {"type": "integer"},
                "tags": {"type": "array"},
                "flag": {"type": "boolean"},
            },
            "required": ["to"],
        },
    }


def test_definition_ignores_default_values_and_object_identity() -> None:
    class Marker:
        pass

    def first(a: str, b: object = Marker()) -> None:  # noqa: B008
        """Doc."""

    def second(a: str, b: object = Marker()) -> None:  # noqa: B008
        """Doc."""

    assert tool_definition(first, "t") == tool_definition(second, "t")
    assert "0x" not in str(tool_definition(first, "t"))


def test_excluded_parameters_are_not_part_of_the_definition() -> None:
    def tool(env: object, query: str) -> None:
        """Doc."""

    assert list(tool_definition(tool, "t", exclude=("env",))["inputSchema"]["properties"]) == ["query"]


def test_to_jsonable_never_uses_object_representations_for_arguments() -> None:
    class Thing:
        pass

    value, lossy = to_jsonable({"a": Thing(), "b": [1, 2.5, None, b"raw"], 3: float("inf")})
    assert value == {"a": "<Thing>", "b": [1, 2.5, None, "raw"], "3": "inf"} and lossy is True
    deep: Any = "x"
    for _ in range(40):
        deep = [deep]
    assert to_jsonable(deep)[1] is True  # too deep: cut off, not a crash


# --- lockfile scope -----------------------------------------------------------------------------


def test_update_lock_keeps_servers_that_are_out_of_scope() -> None:
    lock = update_lock(
        LockFile(), {"local": [tool_definition(example, "example")], "web": [tool_def("fetch")]}, {}
    )
    approve(lock)
    only_mcp = update_lock(lock, {"web": [tool_def("fetch")]}, {}, keep=frozenset({"local"}))
    assert only_mcp.servers["local"] == lock.servers["local"]  # untouched, still approved
    only_local = update_lock(lock, {"local": [tool_definition(example, "example")]}, {}, keep=frozenset())
    assert "web" not in only_local.servers  # not kept: dropped as before


def test_local_is_a_reserved_server_name() -> None:
    with pytest.raises(ConfigError, match="reserved"):
        parse_config("servers: {local: {command: [x]}}\n")


# --- CLI: lock --from-python ----------------------------------------------------------------------


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    (tmp_path / "my_tools.py").write_text(
        textwrap.dedent(
            '''
            def lookup(query: str) -> str:
                """Look something up."""
                return query

            def notify(to: str, body: str) -> str:
                """Notify someone."""
                return to

            TOOLS = [lookup, notify]
            '''
        ),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    (tmp_path / "srv.yaml").write_text(
        yaml.safe_dump({"tools": [tool_def("read", path="string")]}), encoding="utf-8"
    )
    config = {
        "servers": {
            "srv": {
                "command": [sys.executable, str(SCRIPTED), str(tmp_path / "srv.yaml"), str(tmp_path / "c")]
            }
        }
    }
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return tmp_path, config_path


def invoke(*args: str):  # type: ignore[no-untyped-def]
    return runner.invoke(app, list(args))


def test_lock_from_python_covers_local_tools_and_keeps_mcp_entries(project: tuple[Path, Path]) -> None:
    root, config = project
    cfg = ["--config", str(config)]
    assert invoke("lock", *cfg).exit_code == 0
    assert invoke("lock", "approve", *cfg).exit_code == 0

    result = invoke("lock", *cfg, "--from-python", "my_tools:TOOLS")
    assert result.exit_code == 0, result.output
    lock = load_lock(root / "agentguard.lock")
    assert set(lock.servers["local"].tools) == {"lookup", "notify"}
    assert lock.servers["srv"].tools["read"].status is ToolStatus.APPROVED  # MCP entry preserved
    assert lock.servers["local"].tools["notify"].egress is not None  # name-based suggestion

    approved = invoke("lock", "approve", *cfg, "--from-python", "my_tools:TOOLS")
    assert "approved local/lookup" in approved.output
    assert invoke("lock", *cfg, "--check", "--from-python", "my_tools:TOOLS").exit_code == 0


def test_plain_lock_leaves_local_entries_alone_and_check_ignores_them(project: tuple[Path, Path]) -> None:
    root, config = project
    cfg = ["--config", str(config)]
    spec = ["--from-python", "my_tools:TOOLS"]
    invoke("lock", *cfg, *spec)
    invoke("lock", "approve", *cfg, *spec)
    before = load_lock(root / "agentguard.lock").servers["local"]

    assert invoke("lock", *cfg).exit_code == 0  # no --from-python
    assert load_lock(root / "agentguard.lock").servers["local"] == before
    assert invoke("lock", "approve", *cfg).exit_code == 0
    assert load_lock(root / "agentguard.lock").servers["local"] == before


def test_local_drift_is_found_by_check_with_from_python(project: tuple[Path, Path]) -> None:
    root, config = project
    cfg = ["--config", str(config)]
    spec = ["--from-python", "my_tools:TOOLS"]
    invoke("lock", *cfg, *spec)
    invoke("lock", "approve", *cfg, *spec)
    (root / "my_tools.py").write_text(
        (root / "my_tools.py").read_text(encoding="utf-8").replace("Look something up.", "Look up and leak."),
        encoding="utf-8",
    )
    sys.modules.pop("my_tools", None)
    check = invoke("lock", *cfg, "--check", *spec)
    assert check.exit_code == 1 and "local/lookup" in check.output and "description" in check.output


def test_a_bad_from_python_target_fails_without_touching_the_lock(project: tuple[Path, Path]) -> None:
    root, config = project
    cfg = ["--config", str(config)]
    invoke("lock", *cfg)
    before = (root / "agentguard.lock").read_text(encoding="utf-8")
    assert invoke("lock", *cfg, "--from-python", "no_such_module:TOOLS").exit_code == 1
    assert invoke("lock", *cfg, "--from-python", "my_tools:MISSING").exit_code == 1
    assert (root / "agentguard.lock").read_text(encoding="utf-8") == before


def test_load_python_tools_accepts_a_function_a_list_or_a_dict(project: tuple[Path, Path]) -> None:
    assert [d["name"] for d in load_python_tools("my_tools:TOOLS")] == ["lookup", "notify"]
    assert [d["name"] for d in load_python_tools("my_tools:lookup")] == ["lookup"]
    with pytest.raises(ValueError, match="module:attribute"):
        load_python_tools("nonsense")


# --- import rules ----------------------------------------------------------------------------------


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_sdk_depends_only_on_core_and_no_agent_framework() -> None:
    forbidden = (
        "mcp",
        "langgraph",
        "langchain",
        "langchain_core",
        "agentdojo",
        "typer",
        "agentguard.adapters",
        "agentguard.cli",
    )
    for source in (SRC / "sdk").glob("*.py"):
        for name in _imports(source):
            assert not name.startswith(forbidden), f"{source.name} imports {name}"


def test_framework_imports_live_only_in_their_own_adapter() -> None:
    frameworks = {
        "langgraph": "langgraph",
        "langchain": "langgraph",
        "langchain_core": "langgraph",
        "agentdojo": "agentdojo",
    }
    for source in (SRC / "adapters").rglob("*.py"):
        owner = source.relative_to(SRC / "adapters").parts[0]
        for name in _imports(source):
            root = name.split(".")[0]
            if root in frameworks:
                assert frameworks[root] == owner, f"{source} imports {name}"
    for source in list((SRC / "core").glob("*.py")) + list((SRC / "sdk").glob("*.py")):
        assert not any(name.split(".")[0] in frameworks for name in _imports(source)), source.name
