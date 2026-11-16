"""Shared helpers for the AgentDojo scripts: load a suite, build its Guard from the shipped files."""

from __future__ import annotations

import importlib.metadata
import shutil
from pathlib import Path
from typing import Any

import yaml
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.task_suite.task_suite import TaskSuite

from agentguard import Guard
from agentguard.adapters.agentdojo import build_suite_lock
from agentguard.core.lock import save_lock

BENCHMARK_VERSION = "v1.2.2"
SUITES = ("workspace", "travel", "banking", "slack")
SUITE_DIR = Path(__file__).parent / "suites"

# The configurations of design document section 14.1 (the "no protection" baseline needs no guard).
VARIANT_LOCK_AND_RULES = "lock_and_rules"  # lockfile exposure + argument rules; no data-flow rules
VARIANT_FULL = "full"  # everything on


def agentdojo_version() -> str:
    return importlib.metadata.version("agentdojo")


def load_suite(name: str) -> TaskSuite[Any]:
    return get_suites(BENCHMARK_VERSION)[name]


def suite_declarations(name: str) -> dict[str, Any]:
    return yaml.safe_load((SUITE_DIR / name / "declarations.yaml").read_text(encoding="utf-8"))["tools"]


def shipped_lock_text(suite: TaskSuite[Any], name: str, workdir: Path) -> str:
    """The lockfile text generated from the installed suite and the shipped declarations."""
    path = workdir / f"{name}.lock"
    save_lock(build_suite_lock(list(suite.tools), suite_declarations(name)), path)
    return path.read_text(encoding="utf-8")


def make_guard(name: str, suite: TaskSuite[Any], variant: str, workdir: Path) -> Guard:
    """A fresh Guard for one suite and configuration, with its files under `workdir`."""
    workdir.mkdir(parents=True, exist_ok=True)
    policy = yaml.safe_load((SUITE_DIR / name / "policy.yaml").read_text(encoding="utf-8"))
    if variant == VARIANT_LOCK_AND_RULES:
        policy["flow"]["rules"] = []
    config_path = workdir / "agentguard.yaml"
    config_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    shutil.rmtree(workdir / "approvals", ignore_errors=True)
    (workdir / "audit.jsonl").unlink(missing_ok=True)
    save_lock(build_suite_lock(list(suite.tools), suite_declarations(name)), workdir / "agentguard.lock")
    return Guard.from_files(config_path)
