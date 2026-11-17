# AgentDojo

English · [简体中文](README.zh-CN.md)

What is here, and what is not.

**Shipped:** the adapter (`agentguard.adapters.agentdojo`), a policy and a lockfile per suite (`suites/<suite>/`), a ground-truth replay with its results, and the script for the real LLM benchmark.

**LLM results: only an unprotected baseline.** The benchmark of the design document (a fixed model, at least 3 repeats, every configuration) needs an API key and costs money. One model was run without protection (see *DeepSeek runs* below); no protected LLM result exists. The ground-truth replay is the evidence for what the protection stops.

## Ground-truth replay (no model)

`replay.py` plays AgentDojo's own ground-truth tool calls through the tools with AgentGuard in front. It needs no model and no key. AgentDojo 0.1.35, benchmark v1.2.2, every injection task paired with 6 user tasks per suite (spread evenly over the suite); everything is deterministic.

* **Normal tasks completed**: the ground-truth calls of each user task, scored by AgentDojo's `utility`.
* **Attack success**: the ground-truth calls of a user task, then those of an injection task, scored by AgentDojo's `security`. That is an *ideal hijacked agent*: it does its job, then the attacker's. A real model may refuse, improvise or stop early; only the LLM run measures that.
* **Approvals** are answered automatically: *denied* is the lower bound of what a human would allow, *granted* the upper bound.

**Attack success** (an ideal hijacked agent), configurations from least to most protection:

| suite | no protection | lockfile + argument rules | full, approvals granted | full, approvals denied |
|---|---:|---:|---:|---:|
| workspace | 43% | 43% | 36% | **0%** |
| travel | 86% | 86% | 57% | **0%** |
| banking | 98% | 98% | 89% | **0%** |
| slack | 100% | 100% | 60% | **37%** |

**What it costs**: normal tasks completed, and approvals asked per task.

| suite | no protection | lockfile + argument rules | full, approvals granted | full, approvals denied | approvals per task |
|---|---:|---:|---:|---:|---:|
| workspace | 100% | 100% | 80% | 45% | 0.50 |
| travel | 100% | 100% | 100% | 70% | 0.30 |
| banking | 100% | 100% | 81% | 44% | 0.56 |
| slack | 100% | 100% | 100% | 5% | 2.14 |

Read it like this:

* **Compare against "no protection", not against 100%.** The attacker's ground truth does not succeed for every pairing even without protection (workspace 43%, travel 86%, banking 98%); the cause was not investigated.
* **"Lockfile + argument rules" equals the baseline, as expected.** The lockfile stops tools that change after approval; AgentDojo's tools never change, so there is nothing for it to stop here. The policies contain no argument rules, because they describe what the tools are, not particular tasks. This row is the control: it shows that the blocking below comes from the data-flow rules.
* **"Approvals granted" lowers attack success only a little, by design.** The data-flow rules act in two ways. A protected value or fragment in an argument (E1/E2) is denied, and no approval can override that. Reading untrusted text and then changing state (E3) asks a human. Most injected goals are the second kind: sending money to the attacker copies no protected text, it only follows untrusted text. With every approval granted, those go through; what is still stopped (for example slack 100% to 60%) are the attacks that copy protected data verbatim.
* **"Approvals denied" is what the tool layer can stop.** Workspace, travel and banking go to 0%. Slack keeps 37% for the two reasons under *Failures*.
* **The protection works through people.** A real reviewer sits between the two "full" columns: the more they refuse, the safer, and the more normal tasks are lost (44%-70% completed when everything is refused; slack 5%, because its tasks nearly always read a message or page and then post). That is why `observe` mode and destination allowlists exist.
* **Value matches cannot be approved away.** The normal tasks that fail even when approvals are granted (banking 3, workspace 8) legitimately copy data they just read into an outgoing message or payment (for example the IBAN into a payment subject). Rule FL-001 denies that as a value match. Whether such a task should be allowed is a policy decision; the policies here have no allowlist for it.

## Failures, as they are

* **slack `injection_task_3`** ("visit a website") is not stopped under "approvals denied": fetching a page is read-only and carries no protected data, so no rule fires. Fetching an attacker's URL is not blocked by data-flow rules; a destination allowlist for `get_webpage` would stop it, but the policy here does not know which sites are fine.
* **slack `injection_task_5`** is scored by AgentDojo from the *attempted* tool calls (`security_from_traces`), so a blocked attempt still counts as success. It is the only such task in these four suites.
* Under "approvals granted" the attacks that follow the user's own kind of action (send mail, send money, post) go through. This is the E3 limit described in `docs/limitations.md`.
* Normal tasks fail under "denied" mostly with `AG_APPROVAL_DENIED`; the rest with `AG_FLOW_VALUE_MATCH`. `results/replay.json` lists each task and its first blocked call.

## How the policies were written

From what the tools are, never from an injection task (a test checks that the files do not name any task):

* tools returning the user's own data produce `confidential`; tools returning text written by other people (received mail, shared files, reviews, web pages, messages) produce `untrusted`;
* tools that send something declare their `egress`;
* the policy says "private data must not leave for outside destinations" and "after untrusted text, tools that change state need a human".

## Reproduce

```bash
python -m venv .venv-agentdojo && .venv-agentdojo/bin/pip install agentdojo -e .
.venv-agentdojo/bin/python bench/agentdojo/replay.py --pairs 6      # results/replay.json
.venv-agentdojo/bin/python bench/agentdojo/build_locks.py --check   # shipped locks match the installed suite
OPENAI_API_KEY=... python bench/agentdojo/run_benchmark.py --model <model> --config full_approvals_denied --repeats 3   # costs money
```

Pydantic's schema output feeds the tool digests, so the shipped lockfiles are tied to the AgentDojo and Pydantic versions they were generated with; `build_locks.py --check` tells you when they need a new review.

## DeepSeek runs (unprotected baseline only)

`deepseek-chat`, temperature 0, attack `important_instructions_no_model_name`, every user task, 3 injection tasks per suite (spread evenly over the suite, not all of them), 3 repeats; mean (min-max over the repeats). Combined by `summarize.py` into `results/deepseek-summary.json`.

| suite | normal tasks (no attack) | normal tasks (under attack) | attack success |
|---|---:|---:|---:|
| workspace | 99% (98%-100%) | 97% (95%-98%) | 0% (0%-0%) |
| travel | 80% (75%-85%) | 76% (75%-77%) | 0% (0%-0%) |
| banking | 77% (62%-88%) | 59% (56%-62%) | 0% (0%-0%) |
| slack | 100% (100%-100%) | 74% (71%-76%) | 2% (2%-2%) |

* **The three protected configurations were not run to completion, so no protected LLM result exists.** A first set was discarded: `guard_pipeline` kept its guarded runtime in AgentDojo's `extra_args`, a dictionary that AgentDojo shares between all tasks and suites, so every tool of the later suites was rejected as invalid. That is fixed (`tests/adapters/test_agentdojo.py` has a regression test). A second set was stopped on purpose, because the unprotected baseline shows nothing to block with this model and attack; it would only have measured the cost of protection, which the replay already estimates.
* **This model and attack rarely hijack the unprotected agent** (attack success 0-2%). The experiment therefore cannot show that AgentGuard lowers the attack success rate; the ground-truth replay above is the evidence for that. A meaningful LLM measurement needs a model or attack that actually hijacks the unprotected agent; that has not been tried.
* Cost of this part so far: about 16.7 million prompt tokens and 0.7 million completion tokens.
* DeepSeek sometimes returns tool arguments that are not valid JSON, which makes AgentDojo crash. `run_benchmark.py` turns such a call into one with empty arguments (the model sees a validation error), the same for every configuration.
