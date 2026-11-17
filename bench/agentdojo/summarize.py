"""Combine the per-repeat summaries written by run_benchmark.py into one table (mean and range).

    python bench/agentdojo/summarize.py [results/llm-runs] [--out results/deepseek-summary.json]

Reads <dir>/r*/<config>_r*-summary.json. Prints a Markdown table and writes the combined JSON.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

METRICS = ("utility_no_attack", "utility_under_attack", "attack_success_rate", "approvals_per_task")
CONFIG_ORDER = ["no_protection", "lock_and_rules", "full_approvals_denied", "full_approvals_granted"]
LABELS = {
    "no_protection": "no protection",
    "lock_and_rules": "lockfile + argument rules",
    "full_approvals_denied": "full, approvals denied",
    "full_approvals_granted": "full, approvals granted",
}


def load(directory: Path) -> tuple[dict[tuple[str, str], list[dict[str, float]]], dict[str, Any]]:
    runs: dict[tuple[str, str], list[dict[str, float]]] = defaultdict(list)
    meta: dict[str, Any] = {"tokens": {"prompt": 0, "completion": 0, "calls": 0}, "files": 0}
    for path in sorted(directory.glob("r*/*-summary.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        meta["files"] += 1
        for key in ("agentdojo", "provider", "model", "attack"):
            meta[key] = data[key]
        for key in ("prompt", "completion", "calls"):
            meta["tokens"][key] += data["tokens"][key]
        meta.setdefault("injection_tasks", data["injection_tasks"])
        for suite, repeats in data["runs"].items():
            runs[(data["config"], suite)].extend(repeats)
    return runs, meta


def stat(values: list[float]) -> dict[str, float]:
    return {"mean": sum(values) / len(values), "min": min(values), "max": max(values), "n": len(values)}


def combine(
    runs: dict[tuple[str, str], list[dict[str, float]]],
) -> dict[str, dict[str, dict[str, dict[str, float]]]]:
    combined: dict[str, dict[str, dict[str, dict[str, float]]]] = {}
    for (config, suite), repeats in runs.items():
        combined.setdefault(suite, {})[config] = {m: stat([r[m] for r in repeats]) for m in METRICS}
    return combined


def table(combined: dict[str, Any]) -> str:
    def cell(s: dict[str, float], percent: bool) -> str:
        fmt = (lambda v: f"{v:.0%}") if percent else (lambda v: f"{v:.2f}")
        return f"{fmt(s['mean'])} ({fmt(s['min'])}-{fmt(s['max'])})"

    rows = [
        "| suite | configuration | normal tasks (no attack) | normal tasks (under attack) | attack success | approvals per task |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for suite in sorted(combined):
        for config in CONFIG_ORDER:
            if config in combined[suite]:
                c = combined[suite][config]
                rows.append(
                    f"| {suite} | {LABELS[config]} | {cell(c['utility_no_attack'], True)} | "
                    f"{cell(c['utility_under_attack'], True)} | {cell(c['attack_success_rate'], True)} | "
                    f"{cell(c['approvals_per_task'], False)} |"
                )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "directory", nargs="?", type=Path, default=Path(__file__).parent / "results" / "llm-runs"
    )
    parser.add_argument(
        "--out", type=Path, default=Path(__file__).parent / "results" / "deepseek-summary.json"
    )
    args = parser.parse_args()
    runs, meta = load(args.directory)
    combined = combine(runs)
    args.out.write_text(
        json.dumps({"meta": meta, "results": combined}, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(table(combined))
    print(f"\n{meta['files']} summary files; tokens: {meta['tokens']}")


if __name__ == "__main__":
    main()
