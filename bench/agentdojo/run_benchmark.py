"""The LLM benchmark of design document section 14.1. It calls a model API and COSTS MONEY.

    python bench/agentdojo/run_benchmark.py --model gpt-4o-2024-05-13 --suites banking \\
        --config full_approvals_denied --repeats 3

Status: the loop is exercised in tests/adapters/test_agentdojo.py with a scripted stand-in for the
model (no API, no cost), which covers the guarded executor inside AgentDojo's real benchmark loop.
It has never been run against a real model, and no LLM result is shipped.

Run it once per configuration:

    no_protection           AgentDojo pipeline as is
    lock_and_rules          lockfile exposure and argument rules only
    full_approvals_denied   everything on, every approval answered "deny"  (lower bound)
    full_approvals_granted  everything on, every approval answered "approve" (upper bound)

Fix the model version and temperature, run each configuration at least 3 times, and report mean
and range together with the failures. The results file holds, per repeat, the utility without
attacks, the utility under attack and the attack success rate. The average number of approvals
per task is `approvals_asked` in the same file.

The suites' policies and lockfiles (bench/agentdojo/suites/*) are written from what the tools
are; they never mention a specific injection task.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

from agentdojo.agent_pipeline import AgentPipeline, BasePipelineElement, PipelineConfig
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.logging import OutputLogger
from common import (
    BENCHMARK_VERSION,
    SUITES,
    VARIANT_FULL,
    VARIANT_LOCK_AND_RULES,
    agentdojo_version,
    load_suite,
    make_guard,
)

from agentguard.adapters.agentdojo import guard_pipeline
from agentguard.sdk import ApprovalRequest

CONFIGS: dict[str, tuple[str | None, str]] = {
    "no_protection": (None, "approve"),
    "lock_and_rules": (VARIANT_LOCK_AND_RULES, "approve"),
    "full_approvals_denied": (VARIANT_FULL, "deny"),
    "full_approvals_granted": (VARIANT_FULL, "approve"),
}

PipelineFactory = Callable[[int], BasePipelineElement]

DEEPSEEK_URL = "https://api.deepseek.com"
TOKENS = {"prompt": 0, "completion": 0, "calls": 0}  # what the run spent, written to the results


def pipeline_for_model(model: str) -> PipelineFactory:
    """The standard AgentDojo pipeline for one of its models (API key from the environment)."""

    def make(repeat: int) -> BasePipelineElement:
        config = PipelineConfig(
            llm=model, model_id=None, defense=None, system_message_name=None, system_message=None
        )
        pipeline = AgentPipeline.from_config(config)
        pipeline.name = f"{model}-run{repeat}"  # AgentDojo's attacks read the model name from this
        return pipeline

    return make


def pipeline_for_deepseek(model: str, temperature: float = 0.0) -> PipelineFactory:
    """The standard AgentDojo pipeline with DeepSeek (OpenAI-compatible API) as the model.

    The key is read from DEEPSEEK_API_KEY and is never written anywhere."""
    import json
    import os

    import openai
    from agentdojo.agent_pipeline import OpenAILLM
    from agentdojo.agent_pipeline.llms import openai_llm
    from agentdojo.functions_runtime import FunctionCall

    def tolerant_tool_call(tool_call: Any) -> FunctionCall:
        """DeepSeek sometimes returns tool arguments that are not valid JSON. AgentDojo would crash
        the whole benchmark process on that; an empty argument set makes the tool call fail with a
        validation error that the model sees, like any other bad call. Same for every configuration."""
        try:
            args = json.loads(tool_call.function.arguments)
        except json.JSONDecodeError:
            args = {}
        return FunctionCall(function=tool_call.function.name, args=args, id=tool_call.id)

    openai_llm._openai_to_tool_call = tolerant_tool_call

    def make(repeat: int) -> BasePipelineElement:
        client = openai.OpenAI(api_key=os.environ["DEEPSEEK_API_KEY"], base_url=DEEPSEEK_URL)
        create = client.chat.completions.create

        def counting_create(*args: Any, **kwargs: Any) -> Any:
            response = create(*args, **kwargs)
            if response.usage is not None:
                TOKENS["prompt"] += response.usage.prompt_tokens
                TOKENS["completion"] += response.usage.completion_tokens
            TOKENS["calls"] += 1
            return response

        client.chat.completions.create = counting_create  # type: ignore[method-assign]
        llm = OpenAILLM(client, model, temperature=temperature)
        llm.name = model
        config = PipelineConfig(
            llm=llm, model_id=None, defense=None, system_message_name=None, system_message=None
        )
        pipeline = AgentPipeline.from_config(config)
        # AgentDojo's attacks look the model up by name even in the "no model name" variant, which
        # then ignores it; "local" is the one entry meant for custom models.
        pipeline.name = f"local-{model}-run{repeat}"
        return pipeline

    return make


def run_config(
    suite_name: str,
    config: str,
    repeats: int,
    logdir: Path,
    workdir: Path,
    make_pipeline: PipelineFactory,
    attack_name: str = "important_instructions",
    user_tasks: Sequence[str] | None = None,
    injection_tasks: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Run one configuration on one suite; returns one summary per repeat."""
    variant, approvals = CONFIGS[config]
    suite = load_suite(suite_name)
    summaries = []
    for repeat in range(repeats):
        pipeline = make_pipeline(repeat)
        approval_log: list[ApprovalRequest] = []
        if variant is not None:
            guard = make_guard(suite_name, suite, variant, workdir / suite_name / str(repeat))
            pipeline = guard_pipeline(pipeline, guard, approvals, approval_log=approval_log)  # type: ignore[arg-type]
        run_logdir = logdir / config / suite_name / str(repeat)
        run_logdir.mkdir(parents=True, exist_ok=True)
        with OutputLogger(str(run_logdir), live=None):  # AgentDojo's benchmark functions need a logger
            clean = benchmark_suite_without_injections(
                pipeline,
                suite,
                logdir=run_logdir,
                force_rerun=True,
                user_tasks=user_tasks,
                benchmark_version=BENCHMARK_VERSION,
            )
            attacked = benchmark_suite_with_injections(
                pipeline,
                suite,
                load_attack(attack_name, suite, pipeline),
                logdir=run_logdir,
                force_rerun=True,
                user_tasks=user_tasks,
                injection_tasks=injection_tasks,
                verbose=False,
                benchmark_version=BENCHMARK_VERSION,
            )
        task_count = len(clean["utility_results"]) + len(attacked["utility_results"])
        summaries.append(
            {
                "utility_no_attack": _rate(clean["utility_results"]),
                "utility_under_attack": _rate(attacked["utility_results"]),
                "attack_success_rate": _rate(attacked["security_results"]),
                "approvals_asked": len(approval_log),
                "approvals_per_task": len(approval_log) / task_count if task_count else 0.0,
            }
        )
    return summaries


def _rate(results: dict[Any, bool]) -> float:
    return sum(results.values()) / len(results) if results else 0.0


def pick_injection_tasks(suite_name: str, count: int) -> list[str] | None:
    """`count` injection task ids spread evenly over the suite; None means all of them."""
    ids = sorted(load_suite(suite_name).injection_tasks, key=lambda task_id: int(task_id.rsplit("_", 1)[1]))
    if count <= 0 or count >= len(ids):
        return None
    return [ids[int(i * len(ids) / count)] for i in range(count)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=["agentdojo", "deepseek"], default="agentdojo")
    parser.add_argument(
        "--model",
        required=True,
        help="an AgentDojo ModelsEnum value, or a DeepSeek model such as deepseek-chat",
    )
    parser.add_argument("--suites", nargs="+", default=list(SUITES), choices=SUITES)
    parser.add_argument("--config", required=True, choices=list(CONFIGS))
    parser.add_argument(
        "--attack",
        default=None,
        help="default: important_instructions (deepseek: the variant without a model name)",
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--user-tasks", nargs="+", default=None, help="a subset of user task ids (default: all)"
    )
    parser.add_argument(
        "--injection-tasks", nargs="+", default=None, help="a subset of injection task ids (default: all)"
    )
    parser.add_argument(
        "--injection-count",
        type=int,
        default=0,
        help="use this many injection tasks per suite, spread evenly (default: all)",
    )
    parser.add_argument("--tag", default="", help="added to the results file name")
    parser.add_argument("--logdir", type=Path, default=Path(__file__).parent / "results" / "llm-runs")
    args = parser.parse_args()

    deepseek = args.provider == "deepseek"
    attack = args.attack or ("important_instructions_no_model_name" if deepseek else "important_instructions")
    factory = pipeline_for_deepseek(args.model) if deepseek else pipeline_for_model(args.model)
    summary: dict[str, list[dict[str, Any]]] = {}
    used_injection_tasks: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name in args.suites:
            injection_tasks = args.injection_tasks or pick_injection_tasks(name, args.injection_count)
            summary[name] = run_config(
                name, args.config, args.repeats, args.logdir, Path(tmp), factory, attack,
                user_tasks=args.user_tasks, injection_tasks=injection_tasks,
            )  # fmt: skip
            used_injection_tasks[name] = injection_tasks or "all"
    out = args.logdir / f"{args.config}{args.tag}-summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    result = {
        "agentdojo": agentdojo_version(),
        "provider": args.provider,
        "model": args.model,
        "attack": attack,
        "config": args.config,
        "user_tasks": args.user_tasks or "all",
        "injection_tasks": used_injection_tasks,
        "tokens": TOKENS,
        "runs": summary,
    }
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"written to {out}  (tokens: {TOKENS})")


if __name__ == "__main__":
    main()
