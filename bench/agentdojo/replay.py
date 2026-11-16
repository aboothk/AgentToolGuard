"""Ground-truth replay on AgentDojo: no model, no API key, no cost.

    python bench/agentdojo/replay.py [--suites banking slack] [--pairs 6] [--out results/replay.json]

THIS IS NOT THE LLM BENCHMARK of design document section 14.1. A scripted agent calls the tools
exactly as AgentDojo's own ground truth says:

  * utility replay: the ground-truth tool calls of each user task. It shows how many normal tasks
    still complete when the Guard sits in front of the tools (and how many approvals they ask for).
  * attack replay: the ground-truth calls of a user task, then the ground-truth calls of an
    injection task: an "ideal" hijacked agent that finishes its job and then does the attacker's.
    It shows how many of those attacker calls the policy stops. A real model can behave differently
    (refuse, improvise, stop early); only an LLM run (run_benchmark.py) measures that.

Configurations: no protection; lockfile + argument rules (no flow rules); full policy with every
approval answered "deny" and with every approval answered "approve" (lower and upper bound of what
a human could allow). Scoring is AgentDojo's own. Note that some injection tasks score the *attempted*
tool calls (security_from_traces), so a blocked attempt still counts there; they are listed.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, text_content_block_from_string
from common import (
    BENCHMARK_VERSION,
    SUITES,
    VARIANT_FULL,
    VARIANT_LOCK_AND_RULES,
    agentdojo_version,
    load_suite,
    make_guard,
)

from agentguard.adapters.agentdojo import guarded_runtime_class
from agentguard.sdk import ApprovalRequest

CONFIGS: dict[str, tuple[str | None, str]] = {
    # name: (variant or None for no guard, approval mode)
    "no_protection": (None, "approve"),
    "lock_and_rules": (VARIANT_LOCK_AND_RULES, "approve"),
    "full_approvals_denied": (VARIANT_FULL, "deny"),
    "full_approvals_granted": (VARIANT_FULL, "approve"),
}


class Replay(BasePipelineElement):
    """Plays the ground-truth tool calls of one or more tasks, in order."""

    def __init__(self, tasks: Sequence[Any], notes: dict[str, Any]) -> None:
        self._tasks = tasks
        self._notes = notes

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Any = None,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, FunctionsRuntime, Any, Sequence[Any], dict[str, Any]]:
        env = EmptyEnv() if env is None else env
        new_messages: list[Any] = []
        blocked: list[str] = []
        for task in self._tasks:
            for call in task.ground_truth(env):
                new_messages.append(
                    ChatAssistantMessage(
                        role="assistant", tool_calls=[call], content=[text_content_block_from_string("")]
                    )
                )
                result, error = runtime.run_function(env, call.function, call.args, raise_on_error=False)
                if error and error.startswith("CallBlocked"):
                    blocked.append(f"{call.function}: {error}")
                new_messages.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(str(result))],
                        tool_call=call,
                        tool_call_id=None,
                        error=error,
                    )
                )
        new_messages.append(
            ChatAssistantMessage(
                role="assistant",
                tool_calls=None,
                content=[text_content_block_from_string(self._tasks[0].GROUND_TRUTH_OUTPUT)],
            )
        )
        self._notes["blocked"] = blocked
        return query, runtime, env, [*messages, *new_messages], extra_args or {}


def run_once(
    suite: Any, name: str, config: str, user_task: Any, injection_task: Any | None, workdir: Path
) -> dict[str, Any]:
    variant, approvals = CONFIGS[config]
    notes: dict[str, Any] = {}
    approval_log: list[ApprovalRequest] = []
    runtime_class: type[FunctionsRuntime] = FunctionsRuntime
    if variant is not None:
        guard = make_guard(name, suite, variant, workdir)
        runtime_class = guarded_runtime_class(guard, approvals, approval_log=approval_log)  # type: ignore[arg-type]
    tasks = [user_task] if injection_task is None else [user_task, injection_task]
    utility, security = suite.run_task_with_pipeline(
        Replay(tasks, notes), user_task, injection_task, {}, runtime_class=runtime_class
    )
    return {
        "utility": bool(utility),
        # run_task_with_pipeline returns True for "security" when there is no injection; ignore that case
        "attack_succeeded": bool(security) if injection_task is not None else None,
        "approvals": len(approval_log),
        "blocked": notes.get("blocked", []),
    }


def spread(items: list[Any], count: int) -> list[Any]:
    """`count` items spread evenly over the list (all of them if count is 0 or large)."""
    if count <= 0 or count >= len(items):
        return items
    step = len(items) / count
    return [items[int(i * step)] for i in range(count)]


def evaluate_suite(name: str, pairs: int, workdir: Path) -> dict[str, Any]:
    suite = load_suite(name)
    user_tasks = list(suite.user_tasks.values())
    injection_tasks = list(suite.injection_tasks.values())
    report: dict[str, Any] = {
        "user_tasks": len(user_tasks),
        "injection_tasks": len(injection_tasks),
        "configs": {},
    }
    trace_scored = [
        task.ID
        for task in injection_tasks
        if type(task).security_from_traces is not type(task).__mro__[1].security_from_traces
    ]
    report["injection_tasks_scored_from_attempted_calls"] = trace_scored

    for config in CONFIGS:
        utility_runs = {t.ID: run_once(suite, name, config, t, None, workdir / config) for t in user_tasks}
        attack_runs: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for injection in injection_tasks:
            for user in spread(user_tasks, pairs):
                attack_runs[injection.ID].append(
                    {"user_task": user.ID, **run_once(suite, name, config, user, injection, workdir / config)}
                )
        attacks = [run for runs in attack_runs.values() for run in runs]
        report["configs"][config] = {
            "utility_rate": sum(r["utility"] for r in utility_runs.values()) / len(utility_runs),
            "approvals_per_task": sum(r["approvals"] for r in utility_runs.values()) / len(utility_runs),
            "utility_failures": {
                task_id: (run["blocked"][0] if run["blocked"] else "no block recorded")
                for task_id, run in utility_runs.items()
                if not run["utility"]
            },
            "attack_runs": len(attacks),
            "attack_success_rate": sum(r["attack_succeeded"] for r in attacks) / len(attacks),
            "attack_utility_rate": sum(r["utility"] for r in attacks) / len(attacks),
            "attacks_not_stopped": sorted(
                {f"{inj}" for inj, runs in attack_runs.items() if any(r["attack_succeeded"] for r in runs)}
            ),
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suites", nargs="+", default=list(SUITES), choices=SUITES)
    parser.add_argument("--pairs", type=int, default=6, help="user tasks per injection task (0 = all)")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "results" / "replay.json")
    args = parser.parse_args()

    results: dict[str, Any] = {
        "kind": "ground-truth replay (no LLM)",
        "agentdojo_version": agentdojo_version(),
        "benchmark_version": BENCHMARK_VERSION,
        "pairs_per_injection_task": args.pairs,
        "suites": {},
    }
    with tempfile.TemporaryDirectory() as tmp:
        for name in args.suites:
            start = time.perf_counter()
            results["suites"][name] = evaluate_suite(name, args.pairs, Path(tmp) / name)
            print(f"{name}: done in {time.perf_counter() - start:.0f}s", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print_summary(results)
    print(f"\nwritten to {args.out}")


def print_summary(results: dict[str, Any]) -> None:
    print(f"\nAgentDojo {results['agentdojo_version']} / {results['benchmark_version']}: {results['kind']}")
    header = (
        f"{'suite':<10} {'configuration':<24} {'utility':>8} {'approvals/task':>15} {'attack success':>15}"
    )
    print(header + "\n" + "-" * len(header))
    for name, suite in results["suites"].items():
        for config, data in suite["configs"].items():
            print(
                f"{name:<10} {config:<24} {data['utility_rate']:>8.0%} {data['approvals_per_task']:>15.2f} "
                f"{data['attack_success_rate']:>15.0%}"
            )


if __name__ == "__main__":
    main()
